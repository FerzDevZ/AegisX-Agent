---
name: database-architect-optimization
description: >-
  Optimize SQL schemas, indexing, query execution plans (EXPLAIN ANALYZE), connection pooling (PgBouncer),
  and diagnose slow queries. Use when tuning database performance, eliminating table scans,
  or resolving lock contention.
---

# Database Architect & Query Optimization Expert

This skill provides advanced query profiling techniques, indexing strategies, and database connection tuning for high-load PostgreSQL and MySQL deployments.

---

## ⚡ Query Optimization Flow

```mermaid
graph TD
    SlowQuery[Slow Query Detected] --> Plan[Run EXPLAIN (ANALYZE, BUFFERS)]
    Plan --> CheckScan{Seq Scan vs Index Scan?}
    CheckScan -->|Seq Scan| AddIndex[Create Targeted / Partial / Covering Index]
    CheckScan -->|Index Scan but High Buffers| Rewrite[Rewrite Subqueries to CTE / JOINs or Filter Early]
    AddIndex --> Recheck[Verify Execution Time & Buffer Hits]
    Rewrite --> Recheck
    Recheck --> Pool[Tune Connection Pooler: PgBouncer / HikariCP]
```

---

## 🎯 Optimization Invariants

1. **Avoid Sequential Table Scans**: Any query filtering millions of rows without an index scan will degrade I/O throughput.
2. **Covering Indexes (`INCLUDE`)**: Use `CREATE INDEX idx ON orders (user_id) INCLUDE (total_amount, status)` to enable Index-Only Scans without touching heap pages.
3. **Connection Pooling**: Never open direct database connections per HTTP request in serverless/microservices. Always use connection poolers (PgBouncer / HikariCP).

---

## 📋 Prosedur Eksekusi

1. **Analisis Execution Plan**:
   - Pelajari pembacaan cost dan node types di [references/explain-analyze-guide.md](./references/explain-analyze-guide.md).
2. **Monitoring Query Terlambat**:
   - Gunakan query `pg_stat_statements` di [resources/pg-stat-statements.sql](./resources/pg-stat-statements.sql).
3. **Analisis Slow Log**:
   - Jalankan `python3 skills/database-architect-optimization/scripts/analyze-slow-queries.py <log_file>`.