---
name: commit-helper
description: Write clear conventional commits and handle git workflow with proper history hygiene
---

# Commit Helper

Bantu buat commit message yang clean dan konsisten pakai Conventional Commits.

## Workflow
1. Cek `git status` dan `git diff --staged` / `git log --oneline -10`
2. Tentukan type: feat, fix, chore, docs, refactor, test, perf
3. Buat message format: `type(scope): description` - concise, imperative
4. Jelaskan **why** bukan **what** di body jika perlu
5. Jangan commit kalau ada file sensitive (.env, secrets) - cek dulu

## Aturan
- Satu commit = satu concern
- Tidak pakai emoji berlebihan
- Body optional, footer untuk BREAKING CHANGE / issue ref

## Contoh
\`\`\`
feat(auth): add JWT refresh token rotation

refactor(db): simplify query builder logic
\`\`\`
