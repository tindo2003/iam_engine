# Resources

*Note: `RESOURCES-FORMAT.md` wasn't available in this session — using a
simple table. Adjust format later if the real convention differs.*

| Resource | Type | Why it matters |
|---|---|---|
| [Zanzibar: Google's Consistent, Global Authorization System](https://research.google/pubs/zanzibar-googles-consistent-global-authorization-system/) | Paper (USENIX ATC 2019) | The foundational whitepaper for modern large-scale authorization. Introduces ReBAC (relationship-based access control), the "new enemy problem" for cache invalidation, and the Leopard indexing system. Primary source for the caching/indexing lesson. |
| [Cedar (cedar-policy/cedar)](https://github.com/cedar-policy/cedar) | Open-source engine (Rust) | AWS's open-sourced policy language + evaluator, used in Verified Access / Verified Permissions. Built for formal verification. Good reference for schema validation and safe policy parsing in a strictly-typed language — closest real-world analogue to what `iam-engine` is doing in C++. |
| [Open Policy Agent (OPA)](https://www.openpolicyagent.org/) | Open-source engine (Go) + docs | Industry-standard policy-as-code engine, CNCF graduated project. Good reference for decoupling policy decision from enforcement (PDP/PEP split) and for its Rego query language. |
| [NIST SP 800-162: Guide to Attribute Based Access Control (ABAC)](https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-162.pdf) | Government standard/guide | Defines the PEP / PDP / PIP / PAP architecture referenced across this project. The clearest formal source for the ABAC vocabulary. |

## To add later

- A primary source specifically on RBAC role-hierarchy graph resolution
  (not yet found/verified).
- A primary source on wildcard/AST-based policy matcher design (compare
  Cedar's approach directly once its docs are read in a lesson).
