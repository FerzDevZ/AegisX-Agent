---
name: temporal-workflow-orchestrator
description: >-
  Architect and implement long-running, fault-tolerant, stateful workflows using Temporal.io / Inngest.
  Enforce workflow determinism, Saga compensation transactions, automatic retries with exponential jitter, and durable timers.
  Use when building payment flows, order fulfillment, long-running AI pipelines, or multi-step background jobs.
---

# Temporal & Durable Workflow Orchestration Master

This skill provides enterprise standards for architecting fault-tolerant, durable distributed workflows that automatically resume execution after server crashes or network outages.

---

## ⏳ Durable Workflow & Saga Pattern Architecture

```mermaid
sequenceDiagram
    autonumber
    participant App as Temporal Client
    participant Engine as Temporal Cluster
    participant Act1 as Reserve Inventory Activity
    participant Act2 as Process Payment Activity
    participant Act3 as Dispatch Courier Activity

    App->>Engine: Start OrderWorkflow(orderId)
    Engine->>Act1: Execute ReserveInventory
    Act1-->>Engine: Inventory Reserved
    Engine->>Act2: Execute ProcessPayment
    Note over Act2: Payment Failed (Declined)
    Act2-->>Engine: Error: InsufficientFunds
    Note over Engine: Trigger Saga Compensation
    Engine->>Act1: Compensate ReleaseInventory
    Act1-->>Engine: Inventory Released
    Engine-->>App: Workflow Failed (Safely Compensated)
```

---

## 🎯 Production Invariants

1. **Strict Determinism Law**: Workflows must be 100% deterministic. Never use `Math.random()`, `Date.now()`, or direct non-deterministic network I/O inside workflow functions; run all side effects inside Activities.
2. **Saga Compensations**: For every state-mutating activity, register a corresponding rollback compensation function to handle unexpected failures gracefully.
3. **Durable Sleep**: Use `workflow.sleep()` instead of system `setTimeout` so timers survive infrastructure restarts across months.

---

## 📋 Prosedur Eksekusi

1. **Prinsip Saga & Eksekusi Tahan Banting**:
   - Baca [references/saga-and-durable-execution.md](./references/saga-and-durable-execution.md).
2. **Template Workflow**:
   - Rujuk [resources/order-workflow.ts](./resources/order-workflow.ts).
3. **Audit Determinisme**:
   - Jalankan `bash skills/temporal-workflow-orchestrator/scripts/check-workflow-determinism.sh`.
