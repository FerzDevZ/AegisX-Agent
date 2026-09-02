---
name: git-workflow
description: Advanced git: branching, bisect, rebase, reflog recovery and clean history
---

# Git Workflow

Kuasai git untuk history yang clean dan recovery cepat.

## Workflow
- Branch: feat/*, fix/*, chore/* dari main
- Commit atomic, rebase interactive sebelum PR
- Bisect untuk bug hunting: git bisect start + script
- Recovery: reflog, cherry-pick, stash

## Aturan
- Jangan force push ke main
- Squash hanya saat merge PR, jangan di tengah kolaborasi
- Tulis PR description: context, change, test, risk
