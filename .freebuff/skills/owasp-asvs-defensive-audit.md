# [Skill: owasp-asvs-defensive-audit]

Perform comprehensive defensive security audits against the **OWASP Application Security Verification Standard (ASVS v4.0)** Level 2 & 3.

---

## 🛡️ Core Verification Domains

### 1. Architecture & Threat Boundaries (V1)
- Verify that security controls are centralized in well-tested framework middleware rather than scattered ad-hoc.
- Enforce strict component boundary isolation (e.g. database credentials accessible only by data layer services).

### 2. Authentication & Credential Storage (V2)
- Passwords must be hashed using memory-hard functions: **Argon2id** (preferred) or **bcrypt (work factor >= 12)**.
- Implement rate limiting on login/registration endpoints using distributed sliding window counters to mitigate credential stuffing.
- Enforce multi-factor authentication (MFA) via TOTP / WebAuthn for privileged accounts.

### 3. Session Management & Token Lifecycles (V3)
- Session identifiers must possess at least 128 bits of cryptographic entropy (`crypto.randomBytes(32)`).
- Cookies must always include: `HttpOnly; Secure; SameSite=Strict; Path=/`.
- JWT access tokens must have short lifespans (<= 15 minutes) with rotating refresh tokens stored securely.

### 4. Access Control & Authorization (V4)
- **IDOR / BOLA Prevention**: Every query touching tenant data must explicitly scope by authenticated user ID:
  \`\`\`sql
  -- SECURE: Explicit ownership check
  SELECT * FROM documents WHERE id = :doc_id AND user_id = :auth_user_id;
  \`\`\`
- Prevent privilege escalation by validating roles server-side on every RPC / HTTP handler.

### 5. Input Validation & Encoding (V5)
- Use strict runtime validation schemas (**Zod**, **TypeBox**, **Pydantic**).
- Parameterize all SQL/NoSQL queries to eliminate injection flaws.
