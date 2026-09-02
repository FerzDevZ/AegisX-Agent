---
name: redis-distributed-locking-caching
description: >-
  Implement Redlock distributed locking, Token Bucket rate limiting, Bloom Filters,
  Redis Streams, and sorted set leaderboards in high-concurrency systems.
  Use when preventing race conditions in distributed systems, throttling APIs, or building high-speed caching.
---

# Redis Distributed Locking & Advanced Caching Master

This skill provides enterprise blueprints for implementing distributed locks with safe release semantics, high-throughput rate limiters, and probabilistic data structures using Redis.

---

## 🔒 Distributed Lock Architecture (Redlock & Safe Release)

```mermaid
sequenceDiagram
    autonumber
    actor W1 as Worker 1
    actor W2 as Worker 2
    participant Redis as Redis Cluster

    W1->>Redis: SET resource_key random_token_1 NX PX 30000
    Redis-->>W1: OK (Lock Acquired)
    W2->>Redis: SET resource_key random_token_2 NX PX 30000
    Redis-->>W2: nil (Lock Denied / Retry with Jitter)
    Note over W1: W1 executes critical section
    W1->>Redis: EVAL Lua Script (Verify token == random_token_1 then DEL)
    Redis-->>W1: 1 (Safely Released)
```

---

## 🎯 Production Invariants

1. **Lua Script for Safe Release**: Never release a lock with a bare `DEL key`. A slow process could delete a lock acquired by another worker. Always verify ownership token via Lua script.
2. **Auto-Extending Heartbeat**: For long-running background tasks, spawn a watchdog thread that renews the TTL while the job is alive.
3. **Sliding Window Rate Limiter**: Use Redis Sorted Sets (`ZADD`, `ZREMRANGEBYSCORE`, `ZCARD`) for millisecond-accurate rate limiting.

---

## 📋 Prosedur Eksekusi

1. **Algoritma Redlock & Rate Limiting**:
   - Baca [references/redlock-algorithm.md](./references/redlock-algorithm.md).
2. **Template Distributed Lock**:
   - Rujuk [resources/distributed-lock.ts](./resources/distributed-lock.ts).
3. **Audit Memori & Keyspace**:
   - Jalankan `bash skills/redis-distributed-locking-caching/scripts/check-redis-memory.sh`.