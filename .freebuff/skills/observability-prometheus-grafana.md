---
name: observability-prometheus-grafana
description: >-
  Implement full observability with Prometheus metrics (RED / USE method),
  OpenTelemetry distributed tracing, Grafana dashboards, and Loki structured log aggregation.
  Use when instrumenting applications, configuring alerting thresholds, or troubleshooting production latency.
---

# Observability, Prometheus & Grafana Master

This skill provides complete blueprints for instrumenting distributed microservices using the RED method (Rate, Errors, Duration), OpenTelemetry context propagation, and Prometheus scraping.

---

## 📈 The Three Pillars of Observability

```mermaid
graph TD
    App[Microservice / API] --> M[Metrics: Prometheus - RED Method]
    App --> T[Traces: OpenTelemetry / Jaeger - Distributed Spans]
    App --> L[Logs: Loki / FluentBit - Structured Correlation IDs]
    
    M --> Grafana[Unified Grafana Dashboard & Alertmanager]
    T --> Grafana
    L --> Grafana
```

---

## 🎯 Production Invariants

1. **The RED Method on Every Endpoint**:
   - **Rate**: `http_requests_total` counter (req/sec).
   - **Errors**: `http_requests_failed_total` counter (error rate / HTTP 5xx).
   - **Duration**: `http_request_duration_seconds` histogram (p50, p95, p99 latency).
2. **Trace ID Injection**: Inject `trace_id` and `span_id` into all structured log lines to correlate logs with distributed traces.

---

## 📋 Prosedur Eksekusi

1. **RED Method & OpenTelemetry**:
   - Rujuk [references/red-method-and-opentelemetry.md](./references/red-method-and-opentelemetry.md).
2. **Template Konfigurasi Prometheus**:
   - Config: [resources/prometheus.yml](./resources/prometheus.yml).
3. **Audit Endpoint Metrics**:
   - Jalankan `bash skills/observability-prometheus-grafana/scripts/check-metrics-endpoint.sh`.