---
name: self-evolving-agent-memory
description: >-
  Autonomous self-evolving agent memory, Reflexion learning loops, and error post-mortems.
  Enables the agent to remember failure modes, self-correct systematically, and persist insights across sessions.
  Use when teaching agents to avoid repeating mistakes, updating long-term memory, or recording reflections.
---

# Self-Evolving Agent Memory & Reflexion Loop Master

This skill provides an autonomous feedback mechanism enabling agents to learn from runtime errors, evaluate past actions, and persist structured lessons in long-term memory.

---

## 🧠 The Reflexion & Self-Correction Architecture

```mermaid
graph TD
    Execution[Agent Tool Execution] --> Result{Execution Success or Error?}
    Result -->|Error Trace / Failure| Reflect[Reflexion Engine: What failed and why?]
    Reflect --> Lesson[Generate Atomic Rule / Invariant Lesson]
    Lesson --> PersistentMemory[(Agent Memory / memories.json / mem0)]
    PersistentMemory --> NextPrompt[Injected into Next Task Context as Guardrail]
    Result -->|Success| Complete[Complete Task]
```

---

## 🎯 Production Invariants

1. **Atomic Lessons**: Store memory reflections as concise, single-sentence actionable invariants (e.g., *"When installing Next.js 15, always specify @tailwindcss/postcss plugin explicitly in postcss.config.mjs"*).
2. **De-duplicate Memories**: Run semantic cosine similarity check before inserting new memory items to prevent memory bloat.

---

## 📋 Prosedur Eksekusi

1. **Pola Reflexion Loop**:
   - Baca [references/reflexion-learning-loop.md](./references/reflexion-learning-loop.md).
2. **Skema Memori**:
   - Format: [resources/memory-schema.json](./resources/memory-schema.json).
3. **Catat Refleksi Otonom**:
   - Jalankan `python3 skills/self-evolving-agent-memory/scripts/log-reflection.py "<task_name>" "<error_summary>" "<lesson_learned>"`.