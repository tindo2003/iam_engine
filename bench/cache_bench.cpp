// Measurements for the caching decisions made across lessons 0002-0007.
//
// Every one of those decisions -- quantization, the three consistency
// levels, the subproblem layer, the revision floor -- was justified by
// argument and never by a number. This closes that gap.
//
// Deliberately hand-rolled rather than google/benchmark: most of what
// matters here is hit RATES and entry counts, which are counters, not
// timings. Only section 4 measures latency, and it does so crudely but
// honestly (fixed iteration counts, results accumulated into a sink so
// nothing is optimised away).

#include <chrono>
#include <cstdio>
#include <string>
#include <vector>

#include "iam/engine.hpp"
#include "iam/roles.hpp"

using namespace iam;
using std::chrono::milliseconds;

namespace {

// Keeps the optimiser from deleting work whose result is unused.
volatile bool g_sink = false;

constexpr milliseconds kTtl{60'000};

Policy allow(const std::string& action, const std::string& resource) {
    return Policy::fromJsonString(
        R"({"Statement": [{"Effect": "Allow", "Action": [")" + action +
        R"("], "Resource": [")" + resource + R"("]}]})");
}

// A role hierarchy `depth` levels deep, each level inheriting the one
// below. Only the deepest role actually grants anything, so every check
// has to traverse the whole chain.
RoleGraph buildGraph(RoleGraph::Clock clock, int depth, int principals) {
    RoleGraph graph(std::move(clock));

    graph.addRole(Role{"level0", {allow("db:read", "urn:table:users")}, {}});
    for (int i = 1; i < depth; ++i) {
        graph.addRole(Role{"level" + std::to_string(i), {}, {"level" + std::to_string(i - 1)}});
    }

    const RoleName top = "level" + std::to_string(depth - 1);
    for (int p = 0; p < principals; ++p) {
        graph.assign("user" + std::to_string(p), top);
    }
    return graph;
}

void rule(const char* title) {
    std::printf("\n=== %s ===\n", title);
}

double pct(size_t hits, size_t total) {
    return total == 0 ? 0.0 : (100.0 * static_cast<double>(hits) / static_cast<double>(total));
}

// --- 1. Does quantization actually buy hits? ----------------------------

void benchBucketSize() {
    rule("1. Hit rate vs bucket size (MinimizeLatency, 1 request/ms)");
    std::printf("%-12s %10s %10s %10s %12s\n", "bucket", "requests", "hits", "entries", "hit rate");

    for (milliseconds bucket : {milliseconds{0}, milliseconds{10}, milliseconds{100},
                                milliseconds{1000}, milliseconds{10'000}}) {
        auto now = std::chrono::steady_clock::now();
        RoleGraph graph = buildGraph([&now] { return now; }, /*depth=*/3, /*principals=*/1);

        DecisionCache checkCache(kTtl, [&now] { return now; }, bucket);
        DecisionCache subproblemCache(kTtl, [&now] { return now; }, bucket);
        const Request req{"user0", "db:read", "urn:table:users"};

        constexpr int kRequests = 5000;
        for (int i = 0; i < kRequests; ++i) {
            g_sink = PolicyEngine::evaluateRbacCached(checkCache, subproblemCache, graph, req);
            now += milliseconds(1); // one request per millisecond of simulated time
        }

        std::printf("%-12s %10d %10zu %10zu %11.1f%%\n",
                    (std::to_string(bucket.count()) + "ms").c_str(), kRequests,
                    checkCache.hits(), checkCache.size(),
                    pct(checkCache.hits(), checkCache.hits() + checkCache.misses()));
    }
    std::printf("\nbucket=0 disables quantization: every request mints a private key.\n");
}

// --- 2. What the consistency levels actually cost -----------------------

void benchConsistencyLevels() {
    rule("2. Hit rate by consistency level (bucket = 1000ms, 1 request/ms)");
    std::printf("%-28s %10s %10s %12s\n", "level", "hits", "entries", "hit rate");

    struct Case {
        const char* name;
        Consistency level;
        bool staleToken;
    };
    const Case cases[] = {
        {"MinimizeLatency", Consistency::MinimizeLatency, false},
        {"AtLeastAsFresh (old token)", Consistency::AtLeastAsFresh, true},
        {"FullyConsistent", Consistency::FullyConsistent, false},
    };

    for (const Case& c : cases) {
        auto now = std::chrono::steady_clock::now();
        RoleGraph graph = buildGraph([&now] { return now; }, 3, 1);

        DecisionCache checkCache(kTtl, [&now] { return now; }, milliseconds{1000});
        DecisionCache subproblemCache(kTtl, [&now] { return now; }, milliseconds{1000});
        const Request req{"user0", "db:read", "urn:table:users"};
        const Snapshot token = c.staleToken ? now - milliseconds(5000) : Snapshot{};

        constexpr int kRequests = 5000;
        for (int i = 0; i < kRequests; ++i) {
            g_sink = PolicyEngine::evaluateRbacCached(checkCache, subproblemCache, graph, req,
                                                        c.level, token);
            now += milliseconds(1);
        }

        std::printf("%-28s %10zu %10zu %11.1f%%\n", c.name, checkCache.hits(), checkCache.size(),
                    pct(checkCache.hits(), checkCache.hits() + checkCache.misses()));
    }
    std::printf("\nFullyConsistent picks an unquantized instant, so it cannot reuse anything.\n");
}

// --- 3. Lesson 0006's thesis, measured ----------------------------------

void benchSubproblemSharing() {
    rule("3. Subproblem layer value vs principals sharing a role");
    std::printf("%-14s %14s %14s %14s %14s\n", "principals", "check entries", "role entries",
                "role hits", "evals saved");

    for (int principals : {1, 2, 10, 100, 1000}) {
        auto now = std::chrono::steady_clock::now();
        RoleGraph graph = buildGraph([&now] { return now; }, /*depth=*/3, principals);

        DecisionCache checkCache(kTtl, [&now] { return now; }, milliseconds{1000});
        DecisionCache subproblemCache(kTtl, [&now] { return now; }, milliseconds{1000});

        // Every principal asks the same question once, within one bucket.
        for (int p = 0; p < principals; ++p) {
            g_sink = PolicyEngine::evaluateRbacCached(
                checkCache, subproblemCache, graph,
                Request{"user" + std::to_string(p), "db:read", "urn:table:users"});
        }

        // Without the subproblem layer each principal would evaluate all 3
        // roles itself; with it, only the misses do real work.
        const size_t wouldHaveEvaluated = static_cast<size_t>(principals) * 3;
        std::printf("%-14d %14zu %14zu %14zu %14zu\n", principals, checkCache.size(),
                    subproblemCache.size(), subproblemCache.hits(),
                    wouldHaveEvaluated - subproblemCache.misses());
    }
    std::printf("\nRole entries stay flat while principals grow -- that is the whole thesis.\n");
}

// --- 4. Where does the time actually go? --------------------------------

template <typename F>
double nsPerOp(int iterations, F&& body) {
    const auto start = std::chrono::steady_clock::now();
    for (int i = 0; i < iterations; ++i) {
        body(i);
    }
    const auto elapsed = std::chrono::steady_clock::now() - start;
    return static_cast<double>(std::chrono::duration_cast<std::chrono::nanoseconds>(elapsed).count()) /
            iterations;
}

void benchWhereTimeGoes(int depth) {
    std::printf("\n-- role hierarchy depth = %d --\n", depth);
    std::printf("%-34s %14s\n", "operation", "ns/op");

    constexpr int kIters = 200'000;
    auto frozen = std::chrono::steady_clock::now();
    RoleGraph graph = buildGraph([&frozen] { return frozen; }, depth, /*principals=*/1);
    const Request req{"user0", "db:read", "urn:table:users"};

    const double traversal = nsPerOp(kIters, [&](int) {
        g_sink = !graph.effectiveRoles(req.principal).empty();
    });
    const double uncached = nsPerOp(kIters, [&](int) {
        g_sink = PolicyEngine::evaluateRbac(graph, req);
    });

    // Warm both layers first, then measure the steady-state cached path.
    auto now = frozen;
    DecisionCache checkCache(kTtl, [&now] { return now; }, milliseconds{1000});
    DecisionCache subproblemCache(kTtl, [&now] { return now; }, milliseconds{1000});
    g_sink = PolicyEngine::evaluateRbacCached(checkCache, subproblemCache, graph, req);

    const double cachedWarm = nsPerOp(kIters, [&](int) {
        g_sink = PolicyEngine::evaluateRbacCached(checkCache, subproblemCache, graph, req);
    });

    std::printf("%-34s %14.1f\n", "effectiveRoles() alone", traversal);
    std::printf("%-34s %14.1f\n", "evaluateRbac (uncached)", uncached);
    std::printf("%-34s %14.1f\n", "evaluateRbacCached (warm)", cachedWarm);
    std::printf("%-34s %13.1f%%\n", "traversal share of uncached",
                uncached == 0 ? 0.0 : 100.0 * traversal / uncached);
}

// --- 5. How OFTEN is the traversal cost paid? ---------------------------
//
// Section 4 shows traversal is expensive. That only matters in proportion
// to how often a request actually reaches it -- i.e. on a layer-1 miss.
// A realistic workload is many principals asking about many resources,
// where every (principal, resource) pair is its own layer-1 key but each
// principal has exactly ONE role set.

void benchTraversalRedundancy() {
    rule("5. Redundant traversals in a realistic workload");
    std::printf("%-12s %12s %14s %18s %14s\n", "principals", "resources", "layer-1 keys",
                "effectiveRoles run", "distinct needed");

    for (int resources : {1, 10, 100}) {
        constexpr int kPrincipals = 50;
        auto now = std::chrono::steady_clock::now();
        RoleGraph graph = buildGraph([&now] { return now; }, /*depth=*/3, kPrincipals);

        DecisionCache checkCache(kTtl, [&now] { return now; }, milliseconds{1000});
        DecisionCache subproblemCache(kTtl, [&now] { return now; }, milliseconds{1000});

        for (int p = 0; p < kPrincipals; ++p) {
            for (int r = 0; r < resources; ++r) {
                g_sink = PolicyEngine::evaluateRbacCached(
                    checkCache, subproblemCache, graph,
                    Request{"user" + std::to_string(p), "db:read",
                            "urn:table:res" + std::to_string(r)});
            }
        }

        // effectiveRoles runs once per layer-1 miss; only `principals`
        // distinct answers exist, and they never change within a bucket.
        const size_t traversals = checkCache.misses();
        std::printf("%-12d %12d %14zu %18zu %14d\n", kPrincipals, resources, checkCache.size(),
                    traversals, kPrincipals);
    }
    std::printf("\nThe gap between the last two columns is what a third cache layer\n"
                "keyed on (principal, snapshot) would eliminate.\n");
}

} // namespace

int main() {
    std::printf("iam-engine cache benchmarks\n");
    std::printf("(single-threaded, simulated clock; see bench/cache_bench.cpp)\n");

    benchBucketSize();
    benchConsistencyLevels();
    benchSubproblemSharing();

    rule("4. Where the time goes -- is a third cache layer worth building?");
    benchWhereTimeGoes(3);
    benchWhereTimeGoes(10);
    benchTraversalRedundancy();
    std::printf(
        "\nThe last row answers it: if traversal is a large share of an uncached\n"
        "check, caching effectiveRoles per (principal, snapshot) is worth it. If\n"
        "it is noise next to statement matching, that third layer is ceremony.\n");

    return 0;
}
