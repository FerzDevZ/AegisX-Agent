---
name: ai-coding-agent-benchmarking-evaluator
description: >-
  Benchmark and evaluate AI coding agents against industry leaderboards (SWE-bench Verified, HumanEval, Aider benchmark).
  Measure pass@1 rates, multi-file editing precision, tool-calling error rates, and token cost efficiency.
  Use when testing agent intelligence, ranking LLM coding capability, or optimizing agent harnesses.
---

# AI Coding Agent Benchmarking & SWE-bench Evaluator Master

This skill provides an objective evaluation harness to test, measure, and score autonomous AI software engineering agents against production coding benchmarks and pass@1 accuracy.

---

## 🏆 Agent Benchmarking Framework

```mermaid
graph TD
    TestIssue[Real GitHub Issue & Failing Reproduction Test] --> Agent[AI Coding Agent Under Evaluation]
    Agent --> ToolCall[Tool Execution: Search, Read, Patch, Terminal]
    ToolCall --> GitDiff[Generated Git Patch / Commit]
    GitDiff --> TestSandbox[Isolated Docker Sandbox]
    TestSandbox --> EvalScore{Tests Pass & Zero Regressions?}
    EvalScore -->|Yes| Pass[Status: RESOLVED - Pass@1]
    EvalScore -->|No| Fail[Status: FAILED - Diagnostic Logged]
```

---

## 🎯 Production Invariants

1. **Clean Hermetic Sandbox**: Always evaluate agent patches in an isolated container sandbox without network access to prevent test leakage.
2. **Pass@1 Rigor**: Measure first-attempt success rate without human intervention in the loop.
3. **Tool Call Efficiency Metric**: Track the ratio of useful tool calls vs unnecessary exploratory calls.

---

## 📋 Prosedur Eksekusi

1. **Rubrik Evaluasi SWE-bench**:
   - Baca [references/swe-bench-rubric.md](./references/swe-bench-rubric.md).
2. **Harness Evaluasi**:
   - Format: [resources/eval-harness.json](./resources/eval-harness.json).
3. **Jalankan Benchmark Suite**:
   - Jalankan `python3 skills/ai-coding-agent-benchmarking-evaluator/scripts/run-agent-benchmark.py`.
