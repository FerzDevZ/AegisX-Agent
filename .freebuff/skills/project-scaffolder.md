---
name: project-scaffolder
description: Scaffold new projects with consistent structure, lint, git, CI and README
---

# Project Scaffolder

Scaffold project baru yang production-ready dari nol.

## Workflow
1. Pilih stack, tentukan folder structure & module boundaries
2. Init git, lint/format (eslint+prettier / ruff), .gitignore
3. Setup CI (GitHub Actions): lint, test, build
4. Buat README: setup, run, test, deploy
5. Verifikasi build + test pass di fresh clone

## Checklist
- Env example (.env.example) tanpa secrets real
- Scripts: dev, build, test, lint konsisten
