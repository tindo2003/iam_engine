# Resources

*Note: `RESOURCES-FORMAT.md` wasn't available in this session — using a
simple table. Adjust format later if the real convention differs.*

| Resource | Type | Why it matters |
|---|---|---|
| [Zanzibar: Google's Consistent, Global Authorization System](https://research.google/pubs/zanzibar-googles-consistent-global-authorization-system/) | Paper (USENIX ATC 2019) | The foundational whitepaper for modern large-scale authorization. Introduces ReBAC (relationship-based access control), the "new enemy problem" for cache invalidation, and the Leopard indexing system. Primary source for the caching/indexing lesson. |
| [Cedar (cedar-policy/cedar)](https://github.com/cedar-policy/cedar) | Open-source engine (Rust) | AWS's open-sourced policy language + evaluator, used in Verified Access / Verified Permissions. Built for formal verification. Good reference for schema validation and safe policy parsing in a strictly-typed language — closest real-world analogue to what `iam-engine` is doing in C++. |
| [Open Policy Agent (OPA)](https://www.openpolicyagent.org/) | Open-source engine (Go) + docs | Industry-standard policy-as-code engine, CNCF graduated project. Good reference for decoupling policy decision from enforcement (PDP/PEP split) and for its Rego query language. |
| [NIST SP 800-162: Guide to Attribute Based Access Control (ABAC)](https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-162.pdf) | Government standard/guide | Defines the PEP / PDP / PIP / PAP architecture referenced across this project. The clearest formal source for the ABAC vocabulary. |
| [SpiceDB (authzed/spicedb)](https://github.com/authzed/spicedb) | Open-source engine (Go) | A production, open-source implementation of Zanzibar — user-found, 2026-07-26. Its "ZedTokens" are a real, shipped version of the paper's zookies. Directly relevant: this is a working system you can read, not just a paper describing one. |
| [How Caching Works in SpiceDB](https://authzed.com/blog/how-caching-works-in-spicedb) | Blog post (AuthZed) | **Primary source for lesson 0002.** Describes SpiceDB's actual decision-cache design and invalidation — the concrete, shipped answer to the exact question this project's mission is built around. |
| [Hotspot Caching in Google Zanzibar and SpiceDB](https://authzed.com/blog/hotspot-caching-in-google-zanzibar-and-spicedb) | Blog post (AuthZed) | Covers the paper's hotspot-handling design (distributed cache, consistent hashing, timestamp-keyed entries) and how SpiceDB implemented it. Good companion to the Leopard-indexing mention in the Zanzibar paper row above. |
| [Zed Tokens, Zookies, Consistency for Authorization](https://authzed.com/blog/zedtokens) | Blog post (AuthZed) | Plain-language walkthrough of zookies/ZedTokens and the `at_least_as_fresh` consistency level — a good second pass after lesson 0001's External Consistency section, in a real system's own words rather than the paper's. |
| [Consistency (AuthZed Docs)](https://authzed.com/docs/spicedb/concepts/consistency) | Docs | SpiceDB's actual API-level consistency options (`minimize_latency`, `at_least_as_fresh`, `at_exact_snapshot`, `fully_consistent`) — shows how the Allow/Deny caching asymmetry and external-consistency tradeoff become a real, callable choice a client makes per-request. |

## To add later

- A primary source specifically on RBAC role-hierarchy graph resolution
  (not yet found/verified).
- A primary source on wildcard/AST-based policy matcher design (compare
  Cedar's approach directly once its docs are read in a lesson).
