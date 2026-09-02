---
name: no-hallucinated-dependencies
description: >-
  Prevent phantom imports and non-existent packages. Validate all npm, PyPI, Crates.io, and Go modules against live registries with exact semvers.
---

# Dependency Validator & Hallucination Hunter

This superpower skill provides senior-level engineering standards and best practices for dependency validator & hallucination hunter.

---

## 🎯 Production Invariants

1. **Production Reliability**: Adhere strictly to industry zero-regression standards.
2. **Zero AI-Slop**: Deliver concise, idiomatic, high-performance implementations.
3. **Deterministic Testing**: Verify all code against automated test gates.

---

## 📋 Prosedur Eksekusi

1. **Panduan & Referensi**:
   - Baca [references/dependency-verification-protocol.md](./references/dependency-verification-protocol.md).
2. **Template & Resource**:
   - Rujuk [resources/trusted-packages.json](./resources/trusted-packages.json).
3. **Skrip Eksekusi & Validasi**:
   - Jalankan `bash skills/no-hallucinated-dependencies/scripts/verify-packages.py`.
