# [Skill: stride-threat-modeling-matrix]

Execute **STRIDE & DREAD Threat Modeling** across software architecture, data flows, and trust boundaries before writing implementation code.

---

## 🎯 The STRIDE Threat Matrix

| Threat Category | Risk Description | Defensive Architecture Control | Verification Test |
|---|---|---|---|
| **S - Spoofing** | Adversary pretends to be a valid user or service. | Mutual TLS (mTLS), asymmetric JWT verification (RS256/Ed25519), WebAuthn FIDO2. | Replay forged token tests, verify signature rejection. |
| **T - Tampering** | Adversary modifies data in transit or storage. | HMAC-SHA256 payload signing, TLS 1.3 strict ciphers, DB row-level checksums. | Send altered request body with valid header signature. |
| **R - Repudiation** | Adversary denies performing an action. | Immutable append-only audit log with monotonic sequence IDs and timestamps. | Verify audit trail log emission on all financial mutations. |
| **I - Information Disclosure** | Adversary accesses unauthorized data/PII. | Envelope encryption at rest via KMS, dynamic PII masking, strict zero-log policy for secrets. | Automated regex scanner across all stdout and log sinks. |
| **D - Denial of Service** | System capacity exhausted by high traffic. | Token Bucket rate limiter, Envoy circuit breaker, bounded channel buffers, read replicas. | K6 load test spike profile (10x baseline capacity). |
| **E - Elevation of Privilege** | User gains unauthorized admin rights. | Strict ABAC/RBAC authorization middleware, DB Row-Level Security (RLS). | Attempt cross-role API calls with lower-tier bearer token. |
