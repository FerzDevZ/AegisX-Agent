---
name: code-review-excellence-auditor
description: >-
  Audit pull requests against Google/Meta engineering code review rubrics, cognitive load thresholds,
  security vulnerabilities, and architecture conformance.
  Use when conducting rigorous PR reviews, providing code feedback, or enforcing team quality standards.
---

# Code Review Excellence & PR Auditor

This skill provides an objective, senior-level code review rubric based on Google and Meta engineering practices to maximize code health, maintainability, and security while minimizing reviewer turnaround time.

---

## 🔍 The Code Review Assessment Hierarchy

```mermaid
graph TD
    PR[Pull Request Under Review] --> L1[1. Design & Correctness: Does it solve the problem without architectural drift?]
    L1 --> L2[2. Security & Data Integrity: Injection, auth checks, race conditions?]
    L2 --> L3[3. Complexity & Cognitive Load: Can a new engineer understand this in 5 minutes?]
    L3 --> L4[4. Testing & Edge Cases: Are error branches and invariants tested?]
    L4 --> L5[5. Naming & Documentation: Self-documenting code with invariant rationale?]
```

---

## 🎯 Production Invariants

1. **Small, Atomic PRs**: PRs should ideally be `< 400 lines of code`. Large PRs receive superficial reviews and introduce 2x more bugs.
2. **Distinguish Nitpicks from Blockers**: Prefix non-blocking suggestions with `[Nit]` or `[Optional]` so authors know they can merge without blocking.
3. **Praise Good Code**: Acknowledge elegant solutions, comprehensive tests, and clean refactorings.

---

## 📋 Prosedur Eksekusi

1. **Rubrik Code Review Standar**:
   - Baca [references/google-code-review-rubric.md](./references/google-code-review-rubric.md).
2. **Template Review**:
   - Gunakan format di [resources/pr-review-checklist.md](./resources/pr-review-checklist.md).
3. **Analisis Diff PR**:
   - Jalankan `python3 skills/code-review-excellence-auditor/scripts/audit-pr-diff.py <git_diff_file>`.