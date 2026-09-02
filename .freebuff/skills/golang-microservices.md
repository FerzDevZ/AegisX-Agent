---
name: golang-microservices
description: >-
  Develop concurrent, high-performance Go microservices, HTTP handlers (Gin/Fiber/Chi),
  gRPC endpoints, structured logging (Uber Zap), and context lifecycle management.
  Use when building Go backend systems, concurrent workers, or high-throughput microservices.
---

# Go Microservices & High-Concurrency Master

This skill provides idiomatic Go standards for designing concurrent microservices, handling `context.Context` cancellation, managing worker pools, and writing production HTTP/gRPC services.

---

## ⚡ Concurrency & Worker Pool Model

```mermaid
graph LR
    Jobs[Job Channel buffered] --> W1[Worker Goroutine 1]
    Jobs --> W2[Worker Goroutine 2]
    Jobs --> W3[Worker Goroutine 3]
    
    W1 --> Results[Results Channel]
    W2 --> Results
    W3 --> Results
    
    Ctx[context.Context with Timeout/Cancel] -.->|Propagate Cancellation| W1
    Ctx -.->|Propagate Cancellation| W2
    Ctx -.->|Propagate Cancellation| W3
```

---

## 🎯 Production Invariants

1. **Context Propagation**: Always pass `ctx context.Context` as the very first argument in functions performing I/O or network requests. Respect `ctx.Done()`.
2. **Prevent Goroutine Leaks**: Every goroutine spawned MUST have a guaranteed exit path (via buffered channels or context cancellation).
3. **Structured Logging**: Never use `fmt.Println` or default `log.Print`. Use structured logging with Uber Zap or `log/slog`.

---

## 📋 Prosedur Eksekusi

1. **Pola Concurrency & Channel**:
   - Baca [references/goroutines-and-channels.md](./references/goroutines-and-channels.md).
2. **Boilerplate Server**:
   - Terapkan kode dari [resources/main.go](./resources/main.go).
3. **Audit Go Vet & Race Detector**:
   - Jalankan `bash skills/golang-microservices/scripts/check-go-vet.sh`.