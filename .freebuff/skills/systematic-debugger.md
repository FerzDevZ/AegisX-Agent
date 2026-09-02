---
name: systematic-debugger
description: Scientific debugging: reproduce, isolate, hypothesize, verify, fix and prevent regression
---

# Systematic Debugger

Debug dengan metode ilmiah, bukan tebak-tebakan.

## Workflow
1. **Reproduce**: buat langkah reproduksi minimal, catat env & log
2. **Isolate**: binary search, cek recent changes, bisect jika perlu
3. **Hypothesize**: buat 2-3 hipotesis, urutkan paling mungkin
4. **Verify**: baca log, trace, tambah instrumentation minimal
5. **Fix**: patch terkecil yang fix root cause, bukan symptom
6. **Prevent**: tambah test regresi

## Aturan
- Jangan edit banyak file sekaligus saat debug
- Simpan evidence (log, stacktrace) sebelum fix
- Verifikasi fix dengan reproduce script yang sama
