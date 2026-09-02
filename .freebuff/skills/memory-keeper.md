---
name: memory-keeper
description: "Persistent per-project memory — auto-create MEMORY.md in each project folder, survive across sessions. Use when session starts, when project context matters, or when you need to remember decisions/conventions/progress."
compatibility: opencode
metadata:
  category: core
  autocreate: true
---

# Memory Keeper — Auto-Create Per Project

> Dipakai OTOMATIS oleh agent `programmer` di Step 0 — kamu nggak perlu panggil manual.

## Auto-Behavior (via programmer)
Setiap `programmer` dipanggil, dia WAJIB:
1. `ls .opencode/MEMORY.md` → jika miss → `mkdir -p .opencode && cp template → .opencode/MEMORY.md`
2. `read .opencode/MEMORY.md` full
3. Akhir session → update `last_updated`, Progress Log, TODO

Template dan workflow lengkap ada di `~/.config/opencode/agents/programmer.md` Step 0.

## Manual trigger
Kalau kamu bukan programmer, kamu bisa:
```bash
bash ~/.config/opencode/skills/memory-keeper/scripts/init-memory.sh
# atau
/memory-keeper init memory untuk project ini
```

## Lokasi
- Primary: `./.opencode/MEMORY.md` (per-project, commit ke git)
- Mirror: `~/.config/opencode/memory/<slug>.md` (global backup)

Lihat `programmer.md` untuk template full 7 section.
