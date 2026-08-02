---
title: Why a real IAM cache keys by snapshot timestamp, and how that differs from iam-engine's cachedAt/ttl and PolicyVersion
date: 2026-07-30
lesson: 0004-quantization-and-hotspots
related: 0001-quantization-does-not-prevent-redundant-writes.md
---

## Why time is in the key at all (not a caching decision)

A Zanzibar check isn't a timeless fact ("can X do Y on Z") — it's "could X
do Y on Z, as of this exact snapshot of the data." This is forced by the
storage layer, not chosen for caching reasons: ACLs live in Spanner, a
globally-distributed database, and answering one check can require several
separate reads (group membership, then what that group can access,
possibly several levels deep) that could physically live on different
replicas. If those reads don't agree on one point in time, the check can
combine pre-write and post-write state into an answer that was never true
at any real instant.

Why not just always read the absolute latest state and skip snapshots
entirely? Because "the absolute latest" in a globally-replicated system
requires synchronizing across every replica before answering — that
wrecks latency and availability. Reading "as of timestamp T" can be
answered cheaply from a local replica with no coordination, as long as T
is specified. So naming a snapshot isn't optional: it's what makes
distributed reads fast at all. The cache key just reflects that real,
unavoidable input, same as it reflects `principal`/`action`/`resource`.

Demonstrated concretely in `demos/snapshot_consistency_race.cpp`: two
reads not pinned to one snapshot can observe a combination (`engineers`
AND `managers` both holding access mid-handoff) that never existed in
reality. `iam-engine`'s real `PolicyEngine::evaluate()` never has this
problem — it reads one already-assembled `std::vector<Policy>&` in a
single step, so there's nothing for a concurrent write to interleave
with. The demo is illustrative context for *why* the concept exists, not
a description of anything `iam-engine`'s actual code does.

## How the real fix differs from a mutex

The demo's own fix (`checkWithSnapshot()`) uses a lock spanning both
reads — pessimistic, "stop the writer from running while a read is in
flight." **Real Zanzibar/Spanner does not do this.** Spanner is
multi-versioned: a write doesn't overwrite a field, it adds a new version
tagged with the timestamp it became effective at, and the old version
stays frozen and readable forever (until GC). A read doesn't ask "what's
the value right now" — it asks "what was the value as of T." If a check
fixes one T and reuses it for every read, each read looks up an
already-frozen, immutable record — there's nothing to race over, so no
lock is needed. This is also *why* it scales across a distributed
cluster where a lock wouldn't: "give me the version as of T" needs no
cross-replica coordination, while a distributed lock would.

## Why this isn't the same as `cachedAt`/`ttl`

`DecisionCache`'s `ttl_`/`cachedAt` answer a completely different
question: "how long is this cached *answer* allowed to be trusted before
we stop believing it." It's a bound on staleness, not a pin on which data
version produced the answer — an optimistic bet ("probably nothing
changed in the last `ttl`"), not an exact guarantee. A real snapshot
timestamp makes the correctness guarantee exact and permanent for that
specific T; TTL makes it merely bounded and temporary for the *current*,
single mutable entry. Confirmed empirically in
[[0001-quantization-does-not-prevent-redundant-writes]]: quantizing
`cachedAt` doesn't create the sharing benefit a real snapshot-timestamp
key does, because `CacheKey` never included time to begin with —
`(principal, action, resource)` already lets unrelated-in-time requests
share one entry, for free, without needing a snapshot concept at all.

## Why this isn't the same as `PolicyVersion`

`PolicyVersion`/`minVersion` (the ZedToken stand-in from lesson 0003) is
a **caller-specified floor checked against one mutable entry** — "don't
give me an answer tagged older than this." It's a real, useful
approximation of "at least as fresh as a token I already have," but
structurally different from a real snapshot key in two ways:

1. It never touches evaluation itself — `evaluate()` doesn't take a
   version parameter, so nothing guarantees the `policies` vector it
   reads actually *corresponds* to the version being asserted. It's
   asserted by whichever caller passes it into `cache.put()` (tests
   hardcode `1`, `2`, `3` directly), not derived from or verified against
   a real source of truth. There's no PAP (Policy Administration Point)
   in `iam-engine` that stamps and enforces it.
2. It's one mutable slot per key, overwritten on every `put()` — the
   *previous* version's answer is gone once a newer one lands. A real
   snapshot-keyed cache keeps every snapshot's answer as a separate,
   permanently-valid entry; nothing is ever overwritten, only added to.

`PolicyVersion` gets you a similar-shaped *outcome* (reject stale
answers) through a much shallower mechanism (a floor comparison on one
mutable field) than the real design (many immutable, separately-keyed,
never-invalidated snapshot answers).

## Addendum (same day): the redesign happened

The two sections above describe `iam-engine` as it stood *before* the
snapshot-keyed redesign. That redesign has since landed, so those
contrasts are now historical rather than current:

- `PolicyVersion` is **gone**, replaced by `Snapshot` (a `time_point`).
  A real ZedToken *is* a timestamp, so carrying both was two names for
  one idea.
- `Entry` no longer stores `cachedAt` or `version` — both dissolved into
  the key. Entries are now `identity -> ordered map of snapshot -> bool`,
  so many snapshots coexist per identity instead of one mutable slot.
- `ttl` was **repurposed**, exactly as this record predicted: it no
  longer gates whether a hit is valid (a snapshot answer is valid
  forever), only how long entries are retained. `bucketSize` took over
  the staleness-bounding job.
- `PolicyEngine::evaluateCached` lost its `FullyConsistent` bypass
  branch entirely. Snapshot selection moved into a pure
  `selectSnapshot()`, and "fully consistent" is now just "pick an exact
  unquantized instant," which never collides. The bypass became a
  property of the key rather than a branch in the control flow.
