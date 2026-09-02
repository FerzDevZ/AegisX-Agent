---
name: chaos-engineering-resilience
description: >-
  Conduct chaos experiments, fault injection (latency, network packet loss, random pod termination),
  circuit breaker verification, and graceful degradation testing.
  Use when validating system resilience, preparing for game days, or proving high-availability architectures.
---

# Chaos Engineering & Resilience Master

This skill provides an empirical framework to test distributed system reliability by injecting controlled failures and proving steady-state hypotheses.

---

## 💥 Chaos Engineering Lifecycle

```mermaid
graph LR
    Steady[1. Define Steady-State Metrics: P99 < 200ms, Error Rate < 0.01%] --> Hypo[2. Formulate Hypothesis: Redis crash will not take down Web UI]
    Hypo --> Inject[3. Inject Fault: Terminate Redis Pod / Add 500ms Latency]
    Inject --> Verify[4. Observe & Verify: Circuit breaker tripped, cached fallback returned]
    Verify --> Fix[5. Identify Weakness & Harden Resilience]
```

---

## 🎯 Production Invariants

1. **Blast Radius Containment**: Always run chaos experiments with automated abort triggers (`stop if overall error rate exceeds 5%`).
2. **Steady-State Hypothesis**: Never run an experiment without measurable baseline indicators (Prometheus latency histograms, error counters).
3. **Graceful Degradation**: If an upstream dependency fails, downstream services must degrade gracefully (e.g. show cached recommendations or informative fallback) instead of rendering HTTP 500 pages.

---

## 📋 Prosedur Eksekusi

1. **Formulasi Hipotesis**:
   - Baca [references/steady-state-hypothesis.md](./references/steady-state-hypothesis.md).
2. **Template Eksperimen Chaos**:
   - Format: [resources/chaos-experiment.json](./resources/chaos-experiment.json).
3. **Simulasi Latency & Fault**:
   - Jalankan `bash skills/chaos-engineering-resilience/scripts/simulate-latency.sh`.