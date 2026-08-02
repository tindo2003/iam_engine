// Illustrates ONE idea: a lock protects a critical section, not a value.
// If a locked function hands back a pointer to the data it was guarding,
// the caller uses that pointer with no lock held, and the guarantee is
// gone.
//
// This is the bug that was live in RoleGraph::find() -- reduced here to
// the smallest program that shows it, with no iam-engine types involved.
//
//   Thread A (reader)                    Thread B (writer)
//   -----------------------------        --------------------------------
//   p = store.find("k")
//     | lock (shared)
//     | p = &entries_["k"]
//     | unlock          <-- lock gone, but p still points INTO the map
//     v
//                                        store.put("k", 2)
//                                          | lock (unique)   <-- granted:
//                                          |                     A holds nothing
//                                          | entries_["k"] = Entry{2}
//                                          |   <-- writes over the very
//                                          |       object p points at
//                                          v unlock
//   read p->data
//     <-- reads bytes B is midway through rewriting
//
// Note p never dangles: unordered_map is node-based, so the ADDRESS stays
// valid. Assigning to an existing key overwrites the value in place --
// same address, different contents. So there is no crash to notice, just
// a value that is half old and half new.
//
// The fix inverts the last step. Values become immutable and shared, so a
// write installs a NEW object beside the old one rather than over it:
//
//   sp = store.find("k")   -> copies a shared_ptr (refcount 1 -> 2)
//   store.put("k", 2)      -> entries_["k"] = make_shared(Entry{2})
//                             the OLD Entry is untouched, and stays alive
//                             because the reader still holds a reference
//   read sp->data          -> a consistent snapshot of the old value
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

// std::array, NOT std::vector, and that is load-bearing. With a vector,
// `entries_[key] = Entry{...}` move-assigns: the new vector steals its
// buffer and FREES the old one, so a reader holding a pointer to the old
// Entry dereferences freed memory and the program segfaults. (Observed --
// this demo crashed until it was changed.)
//
// That is a perfectly authentic consequence of the bug, just a useless
// one for a demo, since a crashed program cannot report its results. An
// array stores its elements inline, so an overwrite copies them in place
// with nothing to free: the tear is visible and the process survives.
struct Entry {
    std::array<int, kWidth> data{};

    explicit Entry(int fill = 0) { data.fill(fill); }

    bool isConsistent() const {
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

// One reader racing one writer on a single key, counting how often the
// reader saw a value mid-write.
//
// Getting this to demonstrate anything took some tuning, and the tuning
// IS the lesson -- a race can be perfectly real and still invisible.
//
// The window we need to hit is the gap between "reader released the lock
// inside find()" and "reader finished dereferencing". A tear happens only
// when a write lands inside that gap, so the demo has to make the gap wide
// while keeping both critical sections short:
//
//   * kWidth is small, so a write copies little and holds the exclusive
//     lock briefly. An earlier version used 256KB entries, reasoning that
//     a bigger value takes longer to read -- but it also takes longer to
//     WRITE, and the writer starved the reader down to nine reads total.
//
//   * kReadPasses re-reads the same entry many times per find(). That
//     lengthens the unlocked window without slowing writes at all, which
//     is the combination that actually works.
//
// The very first version had neither, and reported zero tears for both
// stores -- a demo that quietly teaches "this code is fine". Tuning was
// needed to make an existing bug observable, not to create one.
//
// Both counters are atomic only so the totals are readable afterwards;
// they are not what makes the broken case broken.
template <typename Store>
void run(const char* label, const char* note) {
    Store store;
    store.put("k", 1);

    std::atomic<bool> stop{false};
    std::atomic<size_t> reads{0};
    std::atomic<size_t> torn{0};

    // reader is spawned from a thread
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
