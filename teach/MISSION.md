# Mission

*Note: the `teach` skill references `MISSION-FORMAT.md` for exact structure, but that
file wasn't available in this session — this is a best-effort draft based on the
conversation so far. Edit freely; treat it as a starting point, not gospel.*

## Topic

How Identity and Access Management (IAM) / policy-based authorization systems
work — learned by designing and building one from scratch in C++. **Primary
interest, confirmed by the user: how IAM evaluation is made fast at scale,
specifically caching** (decision caching, invalidation strategies, and the
"new enemy problem" of a stale cached Allow surviving a real revocation).
Everything else (ABAC/RBAC/ReBAC theory, wildcard/AST matching, role
assumption) is useful supporting context, but caching is the thing lessons
should build toward, not a side topic among equals.

## Why

This is a standalone learning project, deliberately separate from any
production app (`used_cars_finder` is unrelated). Motivation:

- Curiosity specifically about **why/how real IAM evaluation is so fast**,
  and in particular how caching works in a system where a wrong cache hit
  is a security bug, not just a performance bug.
- Wants a deeper systems-design understanding of least-privilege / Zero Trust
  architecture, the kind that underlies cloud IAM (AWS/GCP policies), as
  context for the caching question.
- Chose C++ specifically for the rigor: strict typing and manual memory/data
  structure control, versus a dynamically-typed language that "feels too
  loose" for security-adjacent infrastructure.

## Current level

- Comfortable with basic-to-intermediate C++. Has already built a working
  policy-evaluation engine (`iam-engine/`, sibling directory to this
  workspace): `Principal`/`Action`/`Resource` request model, JSON policy
  parsing via `nlohmann/json`, default-deny evaluation with explicit-deny-
  overrides-allow semantics, trailing-`*` wildcard matching, and a test suite
  (6 passing cases) proving the deny-override and cross-policy-deny behavior.
- New to: formal ABAC/RBAC/ReBAC theory, Zanzibar-style large-scale
  architecture, policy indexing/caching strategies, AST-based policy
  matching, and role assumption / temporary credentials.

## Goals

- **Primary**: deeply understand IAM evaluation caching — decision caching,
  TTL vs. version-stamped vs. event-driven invalidation, Zanzibar's zookies/
  "new enemy problem," and why caching Allow and Deny decisions is not
  symmetric. Extend `iam-engine` with a real `DecisionCache` that has a test
  proving a policy reload invalidates stale entries.
- Supporting: understand the theoretical models (NIST ABAC's PEP/PDP/PIP/PAP
  split, RBAC role graphs, Zanzibar's ReBAC/Leopard indexing) enough to know
  where caching fits in the overall evaluation pipeline.
- **RBAC (roles + inheritance) is in scope *because* of caching, not as a
  pivot away from it.** Added 2026-07-30. SpiceDB caches *subproblems*,
  not whole checks — but `evaluate()` was a single flat statement scan
  with nothing smaller inside it to cache, so that entire topic was
  unreachable. Roles create a traversal, and each role visited is a
  separable, reusable, cacheable question. If a future session reads
  "caching is primary" and wonders why the work moved to role graphs,
  this is why.
- Secondary, lower priority than caching: role assumption, condition blocks
  (IP/time/MFA), a real AST/trie-based policy matcher (replacing the current
  trailing-`*`-only wildcard).
- Be able to explain, from memory, how a real cloud IAM evaluation pipeline
  gets both fast *and* correctly revocable — not just recognize the terms.

## Constraints / preferences

- Purely educational. Never trust parametric knowledge for factual claims —
  ground lessons in the sources listed in `RESOURCES.md`.
- Prefers building test-verified code over reading passively.
- For quiz-style checks: every answer choice should be the same length
  (word count and, where possible, character count) so formatting never
  gives away the correct answer.

## Status

Drafted 2026-07-26, same day as the `iam-engine` scaffold. Not yet confirmed
line-by-line with the user — first real lesson should sanity-check this
against what they actually meant.
