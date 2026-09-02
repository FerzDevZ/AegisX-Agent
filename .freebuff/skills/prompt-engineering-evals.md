---
name: prompt-engineering-evals
description: >-
  LLM-as-a-Judge evaluation benchmarks, Chain-of-Thought calibration, semantic drift detection,
  and structured schema guardrails. Use when designing prompts, benchmarking LLM output quality,
  or preventing prompt regressions across model upgrades.
---

# Prompt Engineering & LLM Evals Master

This skill provides an automated evaluation and prompt engineering framework to eliminate hallucinations, enforce rigid JSON/Pydantic schemas, and run LLM-as-a-Judge benchmark suites.

---

## 🔬 The Continuous LLM Evaluation Loop

```mermaid
graph LR
    Dataset[Gold Standard Dataset] --> Prompt[Prompt Candidate]
    Prompt --> LLM[LLM Generation]
    LLM --> Judge[LLM-as-a-Judge / Rule Evaluators]
    Judge --> Metrics[Score: Faithfulness, Precision, Format Adherence]
    Metrics --> Assert{Pass Benchmark Threshold?}
    Assert -->|Yes| Deploy[Promote Prompt to Production]
    Assert -->|No| Calibrate[Error Analysis & Few-Shot Calibration]
    Calibrate --> Prompt
```

---

## 🎯 Production Invariants

1. **Structured Output Enforcement**: Never rely on raw string parsing. Use constrained decoding (JSON Mode, OpenAI Structured Outputs, or Zod/Pydantic schemas).
2. **Deterministic Calibration**: Always benchmark prompt changes against a fixed gold-standard test set of at least 20-50 diverse inputs including adversarial edge cases.
3. **No Fluff Injections**: Prompts must contain precise behavioral constraints, explicit negative examples, and boundary conditions.

---

## 📋 Prosedur Eksekusi

1. **Metodologi LLM-as-a-Judge**:
   - Baca [references/llm-eval-benchmarks.md](./references/llm-eval-benchmarks.md).
2. **Dataset Evaluasi**:
   - Rujuk format [resources/eval-dataset.json](./resources/eval-dataset.json).
3. **Jalankan Benchmark Evaluasi**:
   - Jalankan `python3 skills/prompt-engineering-evals/scripts/run-evals.py`.