---
name: distributed-tracing-opentelemetry
description: >-
  Implement end-to-end distributed tracing using OpenTelemetry (OTel), context propagation (W3C traceparent), Jaeger, and Tempo.
---

# OpenTelemetry Distributed Tracing Master

This superpower skill provides senior-level engineering standards and best practices for opentelemetry distributed tracing master.

---

## 🎯 Production Invariants

1. **Production Reliability**: Adhere strictly to industry zero-regression standards.
2. **Zero AI-Slop**: Deliver concise, idiomatic, high-performance implementations.
3. **Deterministic Testing**: Verify all code against automated test gates.

---

## 📋 Prosedur Eksekusi

1. **Panduan & Referensi**:
   - Baca [references/otel-trace-propagation.md](./references/otel-trace-propagation.md).
2. **Template & Resource**:
   - Rujuk [resources/tracer-setup.ts](./resources/tracer-setup.ts).
3. **Skrip Eksekusi & Validasi**:
   - Jalankan `bash skills/distributed-tracing-opentelemetry/scripts/test-trace-propagation.sh`.
