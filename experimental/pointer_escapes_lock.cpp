// Illustrates ONE idea: a lock protects a critical section, not a value.
// If a locked function hands back a pointer to the data it was guarding,
// the caller uses that pointer with no lock held, and the guarantee is
// gone.
//
// This is the bug that was live in RoleGraph::find() -- reduced here to
// the smallest program that shows it, with no iam-engine types involved.
//
// Build (from the repo root):
//     c++ -std=c++17 -O2 -pthread experimental/pointer_escapes_lock.cpp \
//         -o /tmp/pointer_escapes_lock && /tmp/pointer_escapes_lock
//
// The BrokenStore half is undefined behaviour. What you see below is one
// observable symptom of it, not a defined outcome -- a different compiler
// or platform is free to do something else entirely, including nothing
// visible at all. That is exactly why "I ran it and it looked fine" is
// not evidence, and why ThreadSanitizer is.

#include <array>
#include <vector>
#include <atomic>
#include <cstdio>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <thread>
#include <unordered_map>

namespace {

// Every element must always be the same number. A reader that ever sees
// two different values caught a write in progress -- this array plays the
// part Role::policies played in the real bug.
// Kept small on purpose, so a write holds the lock only briefly and the
// reader is not starved of it.
constexpr size_t kWidth = 1024;

// The race window is the gap between "reader released the lock" and
// "reader finished reading". Re-reading the same entry many times widens
// that window without making writes slow. With a single quick read the
// race is just as real but almost never observable -- which is precisely
// the trap this demo exists to warn about.
constexpr int kReadPasses = 400;

struct Entry {
    std::vector<int> data;

    explicit Entry(int fill = 0) : data(kWidth, fill) {}

    bool isConsistent() const {
        if (data.size() != kWidth) {
            return false;
        }
        const int first = data[0];
        for (size_t i = 1; i < kWidth; ++i) {
            if (data[i] != first) {
                return false;
            }
        }
        return true;
    }
};

// ---------------------------------------------------------------------
// BROKEN: correctly locked, and still racy.
// ---------------------------------------------------------------------
class BrokenStore {
public:
    void put(const std::string& key, int fill) {
        std::unique_lock<std::shared_mutex> lock(mutex_);
        entries_[key] = Entry{fill}; // overwrites the existing object IN PLACE
    }

    // Note there is nothing wrong with this function's own locking. The
    // mutex is held for every access it makes. The problem is what it
    // returns: an address inside entries_, which the caller will read
    // after this lock has already been released.
    const Entry* find(const std::string& key) const {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        auto it = entries_.find(key);
        return it == entries_.end() ? nullptr : &it->second;
    } // <-- lock released here, while the caller keeps the pointer

private:
    mutable std::shared_mutex mutex_;
    std::unordered_map<std::string, Entry> entries_;
};

// ---------------------------------------------------------------------
// FIXED: values are immutable and shared, so a write installs a NEW one
// rather than modifying the one a reader is already holding.
// ---------------------------------------------------------------------
class SafeStore {
public:
    void put(const std::string& key, int fill) {
        std::unique_lock<std::shared_mutex> lock(mutex_);
        entries_[key] = std::make_shared<const Entry>(fill); // new object
    }

    std::shared_ptr<const Entry> find(const std::string& key) const {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        auto it = entries_.find(key);
        return it == entries_.end() ? nullptr : it->second; // copies the pointer
    }

private:
    mutable std::shared_mutex mutex_;
    std::unordered_map<std::string, std::shared_ptr<const Entry>> entries_;
};

constexpr int kWrites = 100'000;

template <typename Store>
void run(const char* label, const char* note) {
    Store store;
    store.put("k", 1);

    std::atomic<bool> stop{false};
    std::atomic<size_t> reads{0};
    std::atomic<size_t> torn{0};

    std::thread reader([&] {
        while (!stop.load(std::memory_order_relaxed)) {
            auto entry = store.find("k"); // raw pointer, or shared_ptr
            if (!entry) {
                continue;
            }
            // Dereferenced with NO lock held -- this is the whole point.
            bool consistent = true;
            for (int pass = 0; pass < kReadPasses; ++pass) {
                consistent = consistent && entry->isConsistent();
            }
            if (!consistent) {
                ++torn;
            }
            ++reads;
        }
    });

    for (int i = 0; i < kWrites; ++i) {
        store.put("k", 1);
        store.put("k", 2);
    }
    stop.store(true, std::memory_order_relaxed);
    reader.join();

    std::printf("  %-52s\n", label);
    std::printf("      reads %9zu    inconsistent %9zu\n", reads.load(), torn.load());
    std::printf("      %s\n\n", note);
}

} // namespace

int main() {
    std::printf("\nA lock protects a critical section, not a value.\n");
    std::printf("Both stores below lock every access they make. Only one is correct.\n\n");

    run<BrokenStore>("BrokenStore -- find() returns const Entry*",
                     "the pointer outlived its lock, so writes landed mid-read");
    run<SafeStore>("SafeStore  -- find() returns shared_ptr<const Entry>",
                   "the reader holds an immutable snapshot; writes cannot touch it");

    std::printf("Same mutex, same discipline inside each function. The difference is\n"
                "only whether the DATA can escape the section the lock protects.\n\n"
                "If BrokenStore reported zero above, that is not a pass -- it is the\n"
                "race failing to surface on this run. Undefined behaviour is free to\n"
                "look correct. Build with -fsanitize=thread to see it regardless.\n\n");
    return 0;
}
