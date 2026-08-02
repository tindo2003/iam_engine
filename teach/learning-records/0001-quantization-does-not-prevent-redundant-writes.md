---
title: Quantization makes concurrent writes agree, it doesn't prevent them
date: 2026-07-30
lesson: 0004-quantization-and-hotspots
---

## The assumption that turned out wrong

While working through lesson 0004's quantization exercise: if 10 identical
requests fire at nearly the same time, quantizing their timestamps down to
a shared bucket would mean the underlying `entries_` hashmap only gets
written once instead of ten times.

## What's actually true

Quantization only affects **what value** gets written into `cachedAt` once
a write happens. It does nothing to stop the write from happening in the
first place.

Walk through 10 genuinely concurrent requests (each checks the cache, sees
a miss, and starts computing *before any of the others has finished* —
this requires real concurrency; `iam-engine`'s single-threaded tests can't
actually produce this scenario, see below): all 10 independently call
`evaluate()`, and all 10 independently call `put()`. Because they're all
within the same quantization bucket, all 10 writes compute the identical
rounded `cachedAt` — so the map's *end state* looks exactly like it was
written once. But the *work* — 10 evaluations, 10 map writes each
overwriting the last — genuinely happened. Quantization makes the
redundancy harmless to correctness (no staggered, inconsistent expiry
times across the burst), not absent.

## What would actually prevent the redundant work

**Request coalescing** (aka "singleflight"): when a request arrives for a
key that's already being computed by an in-flight request, it waits on
*that* computation and reuses its result, instead of starting its own.
This is a different, complementary mechanism to quantization — quantization
is about which value multiple *already-completed* writes converge to;
coalescing is about preventing the redundant computation from starting at
all. Not built in `iam-engine`.

## A prerequisite gap surfaced along the way

This whole scenario (10 truly concurrent requests) requires real thread
concurrency to even occur. `DecisionCache::entries_` is a plain
`std::unordered_map` with no locking — using it from multiple threads today
would be a data race (undefined behavior), not just a missed optimization.
Thread-safety would need to exist *before* coalescing is meaningful to add.
Both are deferred as a future lesson (see `teach/NOTES.md`), deliberately
not folded into the quantization work, since neither is a caching-
consistency concern the way lessons 0001–0004 have been — they're
concurrent-programming concerns that happen to intersect the same class.
