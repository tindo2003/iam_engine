# iam-engine

A from-scratch IAM-style policy evaluation engine in C++, built as a learning
project (not a dependency of any other project). Models the core pieces of
real cloud IAM systems: principals, actions, resources, JSON policy
documents, and a default-deny / explicit-deny-wins evaluation loop.

## Build & run

```
cmake -S . -B build
cmake --build build
./build/iam_demo
```

## Test

```
ctest --test-dir build --output-on-failure
```

## Layout

```
include/iam/   public headers (types, policy, engine, cache)
src/           implementation + demo main()
tests/         GoogleTest unit tests
policies/      example JSON policy documents
demos/         standalone teaching demos, not part of iam_core
teach/         lessons, references, and learning records for this project
```

## Current evaluation semantics

1. Default deny — no matching statement means the request is denied.
2. Any matching `Deny` statement wins immediately, across all attached
   policies, regardless of statement order.
3. Otherwise, any matching `Allow` statement grants the request.
4. `Action`/`Resource` entries support a trailing `*` wildcard (e.g. `db:*`)
   or a bare `*` for "anything".

## Caching semantics

`DecisionCache` is **snapshot-keyed**, modeled on how Zanzibar/SpiceDB key
their check cache. The logical key is `(principal, action, resource,
snapshot)` — a decision computed at snapshot `S` is correct for `S`
permanently, so a key match is always a valid hit with no freshness check.

`PolicyEngine::selectSnapshot` is where the consistency levels differ; it
is a pure function, and everything else follows from which snapshot it
picks:

| Consistency | Snapshot chosen | Effect |
|---|---|---|
| `MinimizeLatency` | `quantize(now, bucket)` | everyone in the window shares one entry |
| `AtLeastAsFresh` | the bucket, unless a token demands newer | shares with the above in the common case |
| `FullyConsistent` | the exact instant, unquantized | never collides, so it always recomputes |

Note that `FullyConsistent` needs no cache-bypass branch — the bypass is a
consequence of the key it selects, not a special case in the control flow.

The two time knobs do genuinely different jobs:

- **`bucketSize` bounds staleness** (correctness). Once the bucket advances,
  new requests compute a new key and miss automatically.
- **`ttl` bounds retention** (capacity) only — how long old snapshots are
  kept for callers still asking about them. It never makes a hit invalid.

Known limitation: eviction runs only on `put` for the identity being
written, so an identity that goes cold is never swept.

## Benchmarks

Every caching decision in this project was originally justified by argument.
These measure whether the arguments hold. Run them yourself:

```
cmake --build build --target cache_bench
./build/cache_bench
```

### Quantization is the whole ballgame

Rounding timestamps into shared buckets is what makes cache hits possible at
all — without it every request mints a private key and the hit rate is
exactly zero.

```
bucket     hit rate
0ms         0.0%
10ms       90.0%  ████████████████████████████████████████████
100ms      99.0%  ████████████████████████████████████████████████
1000ms     99.9%  ████████████████████████████████████████████████
10s       100.0%  █████████████████████████████████████████████████
```

The entry count is the more dramatic half of the same story — 5000 cached
entries collapse to 6 (log scale, or the small bars would be invisible):

```
bucket     entries
0ms           5000  ████████████████████████████████████████████████
10ms           501  ███████████████████████████████████
100ms           51  ██████████████████████
1000ms           6  ██████████
10s              2  ████
```

### Consistency levels cost what they claim

```
level                        hit rate
MinimizeLatency               99.9%   ████████████████████████████████
AtLeastAsFresh (old token)    99.9%   ████████████████████████████████
FullyConsistent                0.0%
```

`AtLeastAsFresh` matching `MinimizeLatency` exactly is the design working: a
token older than the current bucket is already satisfied by it, so those
requests land on the very same shared entry. `FullyConsistent` sits at zero
by construction — it selects an unquantized instant, so it can never collide
with anything.

### The subproblem layer scales with sharing, not with traffic

One question, asked once by each principal. The role cache stays **flat at 3
entries** no matter how many principals ask, because the answer depends on
the role and not on who holds it:

```
principals    role cache entries      evaluations saved
     1            3  ███                              0
     2            3  ███                              3
    10            3  ███                             27
   100            3  ███                            297
  1000            3  ███                          2997
```

### Where the time goes

| operation | depth 3 | depth 10 |
|---|---|---|
| `effectiveRoles()` alone | ~6.0 µs | ~19.1 µs |
| `evaluateRbac` (uncached) | ~9.9 µs | ~28.8 µs |
| `evaluateRbacCached` (warm) | ~1.0 µs | ~2.4 µs |
| **traversal share of an uncached check** | **61%** | **66%** |

Absolute numbers here move by up to 2x run to run; the *ratios* are stable,
and the ratios are the point.

### Is a third cache layer worth building?

Role resolution is 61–66% of an uncached check — not noise. And a realistic
workload pays it far more often than it needs to, because every
`(principal, resource)` pair is its own layer-1 key while each principal has
exactly one role set:

```
50 principals, N resources each

resources   effectiveRoles runs   distinct answers   redundancy
        1                    50                 50          1x
       10                   500                 50         10x
      100                  5000                 50        100x
```

So yes — a third layer keyed `(principal, snapshot)` would pay for itself.

**But one honest caveat the measurements surface:** 6 µs for a breadth-first
walk over *three nodes* is absurd. That cost is allocation, not graph size —
`effectiveRoles` builds a vector, a `std::set`, another vector, and copies
strings on every call. Caching to paper over an allocation problem is worse
than fixing the allocation. Worth measuring that before assuming a cache is
the right answer.

That is exactly the kind of conclusion measurement produces and reasoning
does not.

## Ideas for next steps

- Consistent hashing / a token hashring, so a multi-process cluster
  dedupes work instead of each node caching redundantly
- Thread safety + request coalescing (singleflight)
- Role assumption / temporary credentials
- Condition blocks (IP range, time of day, MFA)
- A real AST-based matcher instead of trailing-`*`-only wildcards
- A tiny CLI or HTTP PDP (Policy Decision Point) server
