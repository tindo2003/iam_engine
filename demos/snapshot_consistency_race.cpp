// Standalone, isolated demo -- NOT part of iam-engine's real
// PolicyEngine/DecisionCache, deliberately kept separate (see
// teach/lessons/0004-quantization-and-hotspots.html discussion).
//
// Reproduces, deterministically, the exact class of bug Zanzibar's
// snapshot-timestamp reads exist to prevent: a check that does two
// separate reads can observe a combination of state that was never
// true at any real instant, if a write lands between the two reads.
//
// Invariant modeled here: access to a resource is being handed off from
// "engineers" to "managers" in one atomic reorg. Exactly one of the two
// groups should ever have access -- never both, never neither.

#include <atomic>
#include <condition_variable>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>

namespace {

std::unordered_map<std::string, bool> group_access{
    {"engineers", true},
    {"managers", false},
};
std::mutex data_mutex;

// Manual checkpoints so the bad interleaving is FORCED to happen every
// run, instead of depending on OS scheduling luck.
std::mutex checkpoint_mutex;
std::condition_variable checkpoint_cv;
bool read_one_done = false;
bool writer_done = false;

void reassignAccessAtomically() {
    std::lock_guard<std::mutex> lock(data_mutex);
    group_access["managers"] = true;
    group_access["engineers"] = false;
}

struct CheckResult {
    bool engineers_had_access;
    bool managers_had_access;
};

// BUGGY: two separate reads, not pinned to one snapshot.
CheckResult checkWithoutSnapshot() {
    bool engineers;
    {
        std::lock_guard<std::mutex> lock(data_mutex);
        engineers = group_access["engineers"]; // read #1
    }

    // Force the writer's atomic update to land strictly between the two
    // reads -- a real scheduler might do this by accident; here it's on
    // purpose, so the bug reproduces every run instead of only sometimes.
    {
        std::unique_lock<std::mutex> lock(checkpoint_mutex);
        read_one_done = true;
        checkpoint_cv.notify_all();
        checkpoint_cv.wait(lock, [] { return writer_done; });
    }

    bool managers;
    {
        std::lock_guard<std::mutex> lock(data_mutex);
        managers = group_access["managers"]; // read #2
    }

    return {engineers, managers};
}

// FIXED: both reads happen under one continuous lock, so the writer
// (which needs that same lock for its atomic update) structurally
// cannot land between them -- exactly the role a snapshot timestamp
// plays in Zanzibar: pinning every read in one check to agree.
CheckResult checkWithSnapshot() {
    std::lock_guard<std::mutex> lock(data_mutex);
    return {group_access["engineers"], group_access["managers"]};
}

void resetState() {
    std::lock_guard<std::mutex> lock(data_mutex);
    group_access["engineers"] = true;
    group_access["managers"] = false;
}

void runBuggyDemo() {
    resetState();
    read_one_done = false;
    writer_done = false;

    std::thread writer([] {
        {
            std::unique_lock<std::mutex> lock(checkpoint_mutex);
            checkpoint_cv.wait(lock, [] { return read_one_done; });
        }
        reassignAccessAtomically();
        {
            std::lock_guard<std::mutex> lock(checkpoint_mutex);
            writer_done = true;
        }
        checkpoint_cv.notify_all();
    });

    CheckResult result = checkWithoutSnapshot();
    writer.join();

    std::cout << "[no snapshot]  engineers=" << result.engineers_had_access
            << "  managers=" << result.managers_had_access;
    if (result.engineers_had_access && result.managers_had_access) {
        std::cout << "  <-- BUG: both true at once.\n"
                << "      This state never existed in reality -- engineers was read\n"
                << "      BEFORE the reorg, managers was read AFTER it.\n";
    } else {
        std::cout << "  (invariant held, unexpectedly -- try rerunning)\n";
    }
}

void runFixedDemoStressTest() {
    resetState();
    std::atomic<bool> stop{false};
    std::atomic<int> violations{0};
    std::atomic<int> iterations{0};

    // Flip the reorg back and forth as fast as possible -- real,
    // uncontrolled concurrency this time, no manual checkpoints.
    std::thread writer([&stop] {
        while (!stop.load()) {
            reassignAccessAtomically();
            {
                std::lock_guard<std::mutex> lock(data_mutex);
                group_access["engineers"] = true;
                group_access["managers"] = false;
            }
        }
    });

    for (int i = 0; i < 200000; ++i) {
        CheckResult result = checkWithSnapshot();
        ++iterations;
        if (result.engineers_had_access == result.managers_had_access) {
            ++violations; // both true, or both false -- invariant broken
        }
    }

    stop.store(true);
    writer.join();

    std::cout << "[with snapshot] " << iterations.load() << " checks under real concurrent writes, "
            << violations.load() << " invariant violations.\n";
}

} // namespace

int main() {
    std::cout << "--- Reproducing the bug (forced interleaving) ---\n";
    runBuggyDemo();

    std::cout << "\n--- Proving the fix (real concurrency, no forcing needed) ---\n";
    runFixedDemoStressTest();

    return 0;
}
