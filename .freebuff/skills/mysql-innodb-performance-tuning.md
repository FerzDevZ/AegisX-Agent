---
name: mysql-innodb-performance-tuning
description: >-
  Tune MySQL InnoDB storage engine: buffer pool sizing, redo log flush policies (innodb_flush_log_at_trx_commit), deadlock detection, and slow query logs.
---

# MySQL InnoDB Performance & Tuning Master

This superpower skill provides senior-level engineering standards and best practices for mysql innodb performance & tuning master.

---

## 🎯 Production Invariants

1. **Production Reliability**: Adhere strictly to industry zero-regression standards.
2. **Zero AI-Slop**: Deliver concise, idiomatic, high-performance implementations.
3. **Deterministic Testing**: Verify all code against automated test gates.

---

## 📋 Prosedur Eksekusi

1. **Panduan & Referensi**:
   - Baca [references/innodb-tuning-parameters.md](./references/innodb-tuning-parameters.md).
2. **Template & Resource**:
   - Rujuk [resources/my.cnf](./resources/my.cnf).
3. **Skrip Eksekusi & Validasi**:
   - Jalankan `bash skills/mysql-innodb-performance-tuning/scripts/check-mysql-status.sh`.
