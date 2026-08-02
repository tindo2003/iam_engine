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

## Ideas for next steps

- Consistent hashing / a token hashring, so a multi-process cluster
  dedupes work instead of each node caching redundantly
- Thread safety + request coalescing (singleflight)
- Role assumption / temporary credentials
- Condition blocks (IP range, time of day, MFA)
- A real AST-based matcher instead of trailing-`*`-only wildcards
- A tiny CLI or HTTP PDP (Policy Decision Point) server
