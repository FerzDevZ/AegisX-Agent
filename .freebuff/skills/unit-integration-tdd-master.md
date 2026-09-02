---
name: unit-integration-tdd-master
description: >-
  Master Test-Driven Development (TDD: Red-Green-Refactor), unit & integration testing with Vitest/Jest/Pytest,
  mocking strategies (Mocks vs Stubs vs Spies vs Fakes), and mutation testing.
  Use when writing unit tests, practicing TDD, or enforcing high test code coverage.
---

# TDD, Unit & Integration Testing Master

This skill provides comprehensive standards for practicing Test-Driven Development (TDD), utilizing test doubles effectively, and isolating integration tests with in-memory containers.

---

## 🧪 The Red-Green-Refactor TDD Cycle

```mermaid
graph LR
    Red[1. RED: Write a failing unit test asserting desired behavior] --> Green[2. GREEN: Write minimal code to pass the test]
    Green --> Refactor[3. REFACTOR: Clean architecture, remove duplication, maintain passing tests]
    Refactor --> Red
```

---

## 🎯 Testing Invariants

1. **Test Behavior, Not Implementation Details**: Never mock private methods. Assert outputs given specific inputs.
2. **Fast Unit Tests**: Unit tests must execute in memory in milliseconds without hitting real network sockets or disk I/O.
3. **Integration Tests with Testcontainers**: For testing database queries or Redis interactions, use real Docker containers managed by Testcontainers.

---

## 📋 Prosedur Eksekusi

1. **Pola TDD & Test Doubles (Mocks vs Stubs vs Fakes)**:
   - Baca [references/tdd-and-test-doubles.md](./references/tdd-and-test-doubles.md).
2. **Template Vitest / Jest**:
   - Terapkan kode dari [resources/user-service.test.ts](./resources/user-service.test.ts).
3. **Audit Coverage & Mutation**:
   - Jalankan `bash skills/unit-integration-tdd-master/scripts/check-coverage.sh`.