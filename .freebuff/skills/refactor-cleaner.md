---
name: refactor-cleaner
description: Safely refactor code without changing behavior: smells, extraction, and verification
---

# Refactor Cleaner

Refactor aman tanpa ubah behavior.

## Workflow
1. Identifikasi smell: duplication, long function, god class, tangled deps
2. Pastikan ada test coverage sebelum refactor
3. Lakukan langkah kecil: extract function/module, rename, decouple
4. Verifikasi build + test pass tiap langkah
5. Commit per langkah biar bisa rollback

## Aturan
- Jangan campur refactor + feature dalam satu commit
- Jaga interface existing kalau belum ada migration plan
