---
name: memory-by-ferz
description: "All-in-one memory by Ferz — polyglot super powerful. Auto-create memory/ folder in project, langsung terkoneksi ke agent programmer. Detect multi-bahasa (Next+Go+Python+Rust) + monorepo + stale check."
compatibility: opencode
metadata:
  category: core
  autocreate: true
  connected_agent: programmer
  version: "2.1-polyglot"
---

# Memory-by-Ferz v2.1 — Polyglot Super Powerful

> Untuk project campur bahasa. Detect semua stack sekaligus, bukan cuma 1.

## Problem Campur Bahasa
Project real sering:
- `frontend/` Next.js + `backend/` Go + `ml/` Python + `infra/` Docker
- Root `package.json` + `go.mod` + `pyproject.toml` barengan
- Monorepo `turbo.json` / `pnpm-workspace.yaml` / `go.work`

Memory lama `if-elif` hanya deteksi 1 stack → miss. **v2.1 polyglot detect semua.**

## Lokasi (Polyglot Modular)

```
<project>/
├── memory/
│   ├── MEMORY.md      → RINGKAS table polyglot (load tiap session)
│   ├── full.md        → DETAIL per-stack (package.json, go.mod, pyproject raw)
│   ├── decisions.md   → ADR per-stack
│   └── gotchas.md     → bug per-stack
├── .opencode/MEMORY.md
└── ~/.config/opencode/memory/<slug>.md (+ -full.md)
```

## Smart Polyglot Scan

`init.sh` sekarang:

1. **Scan root + 1 level subdirs** (`frontend`, `backend`, `services`, `apps`, `packages`, `ml`, dll + brute `*/` jika ada stack file)
2. **Detect per path:**
   - `package.json` → Next/Nuxt/Vue/React, Prisma
   - `go.mod` → Go + Gin/Fiber/Echo
   - `pyproject.toml`/`requirements.txt` → Python + FastAPI/Django
   - `Cargo.toml` → Rust
   - `composer.json` → PHP/Laravel
   - `pubspec.yaml` → Flutter
   - `Dockerfile`/`compose`/`k8s`/`turbo.json`
3. **Output:**
   - `stacks: Next.js ... @ /; Go 1.22 @ backend/; Python @ ml/`
   - Table markdown di `MEMORY.md ##2`
   - `polyglot: yes (3 stacks)` flag

## Auto-Behavior (Programmer Step 0)

```bash
bash ~/.config/opencode/skills/memory-by-ferz/scripts/init.sh  # polyglot smart
read memory/MEMORY.md   # table ringkas
# if need per-stack detail: read memory/full.md
bash ~/.config/opencode/skills/memory-by-ferz/scripts/check.sh  # cek stale per-stack
```

Stale: jika `backend/go.mod` baru muncul tapi belum di memory table → warning.

## Scripts

- `init.sh` — polyglot detect all stacks + monorepo table + sync
- `sync.sh` — sync 3 arah + update timestamp
- `check.sh` — polyglot health (missing stack, new monorepo dir, drift)
- `search.sh <kw>` — grep global polyglot stacks (`search.sh Go`, `search.sh Next`)

## Workflow Polyglot

1. `memory-by-ferz` init → table `| root | Next @ / | ... | backend | Go @ backend/ |`
2. Programmer pilih skills per-stack: `frontend-developer` untuk `frontend/`, `golang-pro` untuk `backend/`, `python-pro` untuk `ml/`
3. Update `memory/full.md ##2` per-stack, `decisions.md` per-stack
4. `sync.sh` + `check.sh`

> Campur bahasa = tetap 1 memory, tapi isinya table biar AI paham layer mana pakai bahasa apa. Cukup `buka memory` → lihat table langsung paham.
