---
name: tdd-master
description: Test-driven development with red-green-refactor and focused unit tests
---

# TDD Master

Kawal development pakai TDD red-green-refactor.

## Workflow
1. Tulis test gagal dulu (red) - cover happy path + edge case
2. Implement minimal code biar pass (green)
3. Refactor tanpa ubah behavior, pastikan test tetap pass
4. Ulangi untuk case berikutnya

## Aturan
- Mock boundary saja (DB, API, FS) - jangan over-mock logic
- Test harus deterministic, no flakiness
- Coverage bermakna > coverage angka

## Tools
- JS/TS: vitest / jest
- Python: pytest
- Go: go test
