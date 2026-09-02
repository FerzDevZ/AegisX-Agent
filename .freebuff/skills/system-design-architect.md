---
name: system-design-architect
description: >-
  Design highly scalable, resilient, event-driven, and distributed system architectures.
  Evaluate CAP theorem, caching patterns (Cache-Aside, Write-Through), message queues (Kafka, RabbitMQ),
  CQRS, and fault-tolerant topologies. Use when architecting large systems or conducting design reviews.
---

# System Design & High Scalability Architect

This skill provides architectural frameworks to design distributed systems capable of handling high throughput, low latency, and zero single points of failure (SPOF).

---

## 🏛️ Scalable Distributed Architecture

```mermaid
graph TD
    Client[Clients / Mobile / Web] --> CDN[Cloudflare / Edge CDN]
    CDN --> LB[Global Load Balancer: NGINX / Envoy]
    LB --> Gateway[API Gateway: Auth, Rate Limit, Routing]
    
    Gateway --> ServiceA[Order Microservice]
    Gateway --> ServiceB[User Microservice]
    
    ServiceA --> Cache[(Redis Cluster)]
    ServiceA --> RDB[(PostgreSQL Primary / Replica)]
    ServiceA --> MQ[(Kafka / Event Bus)]
    
    MQ --> Consumer[Async Worker / Analytics Service]
    Consumer --> Search[(Elasticsearch / Vector DB)]
```

---

## 🎯 Architectural Invariants

1. **Decouple Synchronous Dependencies**: Never make synchronous RPC calls across >2 microservices in the critical path. Use event-driven choreography.
2. **Caching Strategy**: Implement Cache-Aside with jittered TTLs to prevent cache stampedes.
3. **Resilience**: Implement Circuit Breakers, Bulkheads, and Exponential Backoff with Jitter for all downstream dependencies.

---

## 📋 Prosedur Eksekusi

1. **Pola Arsitektur Terdistribusi**:
   - Rujuk [references/distributed-systems-patterns.md](./references/distributed-systems-patterns.md).
2. **Strategi Caching & Redis**:
   - Rujuk [references/caching-strategies.md](./references/caching-strategies.md).
3. **Kalkulasi Kapasitas & Bottleneck**:
   - Jalankan `python3 skills/system-design-architect/scripts/calc-system-capacity.py` untuk menghitung kebutuhan throughput QPS, IOPS, dan storage.