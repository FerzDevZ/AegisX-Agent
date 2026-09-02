---
name: antislop-ai-engineer
description: >-
  Eliminate AI-slop, verbose corporate waffle, placeholder code, and redundant comments.
  Enforce concise, idiomatic, production-ready code with deterministic validation gates.
  Use when reviewing code generation quality, cleaning AI responses, or enforcing strict prompt standards.
---

# Anti-Slop AI Engineering

This skill provides an uncompromising protocol to eradicate "AI Slop"—generic, verbose, conversational filler, half-baked placeholder implementations (`// TODO: add here`), and syntactic restatements in comments.

---

## 🚫 The Anti-Slop Tenets

1. **Zero Waffle / Zero Filler**:
   - Never say: *"Certainly! In today's fast-paced world, navigating the complexities of X requires..."*
   - Never say: *"Here is the complete, robust, enterprise-grade solution..."*
   - Immediately provide the solution, code, or direct answer.

2. **No Syntax Restatement in Comments**:
   - ❌ `// Increment i by 1` -> `i++`
   - ❌ `// Return the user object` -> `return user;`
   - ✅ Only document **invariants, non-obvious business logic, concurrency constraints, or edge-case rationale**.

3. **No Lazy Placeholders / Incomplete Stubs**:
   - Never output `// TODO: add remaining fields here` or `...rest of code`.
   - Provide complete, syntactically valid code blocks or exact targeted diffs.

4. **Deterministic Validation First**:
   - Before delivering code, dry-run or verify syntax, type constraints, and imports.
   - Use strict typing (TypeScript `strict: true`, Python type annotations, Pydantic/Zod schemas).

---

## 🛠️ Step-by-Step Anti-Slop Workflow

1. **Context Grounding (Read Before Write)**:
   - Always inspect the target codebase conventions and existing patterns before generating code.
   - Do not guess library versions; check `package.json`, `go.mod`, `pyproject.toml`, or `Cargo.toml`.

2. **Run Slop Linter on Output / Files**:
   - Execute the built-in scanner to catch forbidden corporate buzzwords and useless comments:
     `python3 skills/antislop-ai-engineer/scripts/scan-slop.py <target_file_or_directory>`

3. **Apply Code Density & Brevity Rules**:
   - Consult [references/banned-patterns.md](./references/banned-patterns.md) for full list of banned phrases.
   - Consult [references/verification-harness.md](./references/verification-harness.md) to implement automated quality gates.

---

## 🧪 Verification & Audit

Check that generated outputs pass:
- [ ] No conversational preamble or postamble.
- [ ] No banned AI vocabulary ("delve", "crucial", "testament", "tapestry", "seamlessly", "furthermore").
- [ ] Zero missing imports or unresolved symbols.
- [ ] Explicit error handling (no empty `catch (e) {}`).