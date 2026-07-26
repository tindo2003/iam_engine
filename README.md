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
include/iam/   public headers (types, policy, engine)
src/           implementation + demo main()
tests/         assert-based unit tests
policies/      example JSON policy documents
```

## Current evaluation semantics

1. Default deny — no matching statement means the request is denied.
2. Any matching `Deny` statement wins immediately, across all attached
   policies, regardless of statement order.
3. Otherwise, any matching `Allow` statement grants the request.
4. `Action`/`Resource` entries support a trailing `*` wildcard (e.g. `db:*`)
   or a bare `*` for "anything".

## Ideas for next steps

- Role assumption / temporary credentials
- Condition blocks (IP range, time of day, MFA)
- A real AST-based matcher instead of trailing-`*`-only wildcards
- Benchmark + bitmask-based action matching for performance
- A tiny CLI or HTTP PDP (Policy Decision Point) server
