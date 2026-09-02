---
name: performance-load-testing-k6
description: >-
  Script and execute load, stress, spike, and soak tests using Grafana k6 with SLA assertions,
  virtual user ramps (VUs), and p95/p99 latency thresholds.
  Use when benchmarking APIs, measuring system capacity, or validating performance SLAs.
---

# Performance & Load Testing with k6 Master

This skill provides industry standards for designing realistic load testing scenarios, defining rigorous SLA thresholds, and discovering system breaking points using Grafana k6.

---

## ⚡ Load Testing Stages & Types

```mermaid
graph TD
    Smoke[1. Smoke Test: 1-5 VUs - Verify Script Integrity] --> Load[2. Load Test: Steady-state normal traffic]
    Load --> Stress[3. Stress Test: Ramp VUs beyond capacity to find breaking point]
    Stress --> Spike[4. Spike Test: Instant surge to test autoscaling & queueing]
    Spike --> Soak[5. Soak / Endurance Test: Sustained load to detect memory leaks]
```

---

## 🎯 Production Invariants

1. **Strict SLA Thresholds**: Fail the test automatically if error rate > 1% or p99 latency > 500ms (`thresholds: { http_req_failed: ['rate<0.01'], http_req_duration: ['p(99)<500'] }`).
2. **Realistic User Think Time**: Include dynamic sleep intervals (`sleep(Math.random() * 2 + 1)`) to model human behavior.
3. **No Distributed Testing Blindness**: Monitor server CPU, Memory, and DB Connection Pool utilization concurrently while running tests.

---

## 📋 Prosedur Eksekusi

1. **Metodologi Pengujian Beban**:
   - Baca [references/load-testing-methodology.md](./references/load-testing-methodology.md).
2. **Template Script k6**:
   - Terapkan kode dari [resources/load-test.js](./resources/load-test.js).
3. **Eksekusi Pengujian**:
   - Jalankan `bash skills/performance-load-testing-k6/scripts/run-k6-test.sh`.