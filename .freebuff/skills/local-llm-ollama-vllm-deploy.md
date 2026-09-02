---
name: local-llm-ollama-vllm-deploy
description: >-
  Deploy, optimize, and serve private self-hosted local LLMs (Llama 3, DeepSeek, Qwen) using Ollama, vLLM, GGUF/AWQ quantization, and OpenAI-compatible endpoints.
---

# Local LLM Deployment (Ollama / vLLM) Master

This superpower skill provides elite developer standards and production guidelines for local llm deployment (ollama / vllm) master.

---

## 🎯 Production Invariants

1. **Enterprise Reliability**: Zero unhandled failure modes, explicit error boundaries, and scalable design.
2. **Zero AI-Slop**: Concise, production-tested, idiomatic code with direct verification.
3. **Deterministic Output**: Backed by automated scripts, executable templates, and reference guides.

---

## 📋 Prosedur Eksekusi

1. **Panduan Teknis & Referensi**:
   - Baca [references/vllm-throughput-tuning.md](./references/vllm-throughput-tuning.md).
2. **Template & Resource**:
   - Rujuk [resources/ollama-model-file](./resources/ollama-model-file).
3. **Skrip Eksekusi & Validasi**:
   - Jalankan `bash skills/local-llm-ollama-vllm-deploy/scripts/benchmark-vllm-tokens.sh`.
