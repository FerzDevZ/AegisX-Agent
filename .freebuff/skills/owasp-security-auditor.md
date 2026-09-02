---
name: owasp-security-auditor
description: >-
  Audit and remediate web security vulnerabilities against OWASP Top 10, SAST/DAST standards,
  CORS/CSP security headers, dependency CVE audits, and hardcoded secret scanning.
  Use when conducting security reviews, hardening APIs, or preparing for security audits.
---

# OWASP Security Auditor & DevSecOps Expert

This skill provides checklists, configuration templates, and automated scanners to protect applications against the OWASP Top 10 and common software supply chain vulnerabilities.

---

## 🛡️ OWASP Top 10 Core Defense Matrix

```mermaid
graph TD
    Threat[Web Application Threats] --> A01[A01: Broken Access Control -> RBAC / Enforce Tenant Boundaries]
    Threat --> A02[A02: Cryptographic Failures -> TLS 1.3 / AES-GCM / Argon2id]
    Threat --> A03[A03: Injection -> Parameterized Queries / ORMs]
    Threat --> A05[A05: Security Misconfiguration -> Hardened Headers / CSP]
    Threat --> A07[A07: Identification & Auth Failures -> MFA / Token Rotation]
```

---

## 🎯 Security Invariants

1. **Parameterized Queries Only**: Never concatenate user input directly into SQL strings.
2. **Strict Content Security Policy (CSP)**: Disallow `unsafe-inline` and `unsafe-eval` in production script-src.
3. **No Hardcoded Secrets**: Secrets must only enter via environment variables or secret vaults (Vault, AWS Secrets Manager).

---

## 📋 Prosedur Eksekusi

1. **Audit OWASP Top 10**:
   - Rujuk panduan mitigasi di [references/owasp-top10-mitigation.md](./references/owasp-top10-mitigation.md).
2. **Terapkan Security Headers**:
   - Gunakan konfigurasi NGINX di [resources/security-headers-nginx.conf](./resources/security-headers-nginx.conf).
3. **Scan Hardcoded Secrets**:
   - Jalankan `python3 skills/owasp-security-auditor/scripts/scan-hardcoded-secrets.py <codebase_dir>`.