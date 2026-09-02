---
name: multi-model-cost-router
description: >-
  Smart Multi-Model Cost & Intelligence Routing. Routes light parsing tasks to fast, low-cost models
  (Llama 8B, Gemini Flash, GLM) and complex architectural planning to heavy reasoning models (Grok, Claude Sonnet, Gemini Pro).
  Use when optimizing LLM API token costs, reducing latency, or configuring multi-model agent harnesses.
---

# Multi-Model Hybrid Cost & Intelligence Router

This skill provides an intelligent dispatching mechanism to route prompts to the optimal LLM based on task complexity, context length, and token cost economics.

---

## 🔀 Multi-Model Routing Architecture

```mermaid
graph TD
    Prompt[Inbound Prompt / Subagent Task] --> Classifier[Complexity Classifier: Token Length, Code vs Formatting, Reasoning Depth]
    
    Classifier -->|Tier 1: High Reasoning / Architecture / Multi-File Refactor| Heavy[Tier 1: Grok 4.6 / Claude Sonnet / Gemini Pro]
    Classifier -->|Tier 2: Code Gen / Unit Tests / Bug Fixes| Mid[Tier 2: Qwen3 Coder / DeepSeek V3 / Llama 3.3 70B]
    Classifier -->|Tier 3: Formatting / JSON Extraction / Git Commits| Light[Tier 3: Gemini Flash / GLM / Llama 8B]
    
    Heavy --> Out[Consolidated High-Quality Output]
    Mid --> Out
    Light --> Out
```

---

## 🎯 Production Invariants

1. **Tiered Fallback Matrix**: If a Tier 1 model encounters a rate-limit (HTTP 429), automatically failover to a configured fallback provider within 200ms.
2. **Strict Schema Gate**: Validate structured outputs from all tiers with local schema validators before returning to user.

---

## 📋 Prosedur Eksekusi

1. **Heuristik Routing**:
   - Baca [references/routing-heuristics.md](./references/routing-heuristics.md).
2. **Konfigurasi Router**:
   - Format: [resources/router-config.json](./resources/router-config.json).
3. **Kalkulasi Estimasi Biaya Token**:
   - Jalankan `python3 skills/multi-model-cost-router/scripts/estimate-cost.py <input_tokens> <output_tokens>`.