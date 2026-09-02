---
name: test-planner
description: Plan test strategy: unit/integration/e2e split and fixtures with clear coverage goals
---

# Test Planner

Rencanakan strategi testing berlapis.

## Pyramid
- **Unit** (70%): logic murni, fast, isolated
- **Integration** (20%): DB, API, queue boundaries
- **E2E** (10%): user journey kritis

## Workflow
1. Petakan fitur -> risiko -> level test yang tepat
2. Tentukan fixtures & seed data minimal
3. Tentukan mock boundary (jangan mock domain logic)
4. Definisikan exit criteria: pass rate, flakiness <1%

## Output
Buat matrix: Feature | Unit | Integration | E2E | Notes
