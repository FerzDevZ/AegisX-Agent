---
name: agent-customization-expert
description: >-
  Create, optimize, and debug Antigravity skills, rules, hooks, subagents, and plugins.
  Use when teaching the agent new workflows, configuring workspace rules, creating MCP integrations,
  or authoring reusable skills.
---

# Antigravity Agent Customization Expert

This skill provides comprehensive guidelines for extending Antigravity's capabilities via Skills, Rules, Hooks, Subagents, and Plugins.

---

## 🧩 Customization Architecture

```mermaid
graph TD
    A[Antigravity Agent] --> B[Skills: On-Demand Workflows]
    A --> C[Rules: Contextual & Always-On Constraints]
    A --> D[Hooks: Lifecycle Event Scripts]
    A --> E[Subagents: Delegated Parallel Execution]
    A --> F[MCP: External Tool Integrations]
```

---

## 🛠️ Step-by-Step Customization Workflow

1. **Creating a Skill**:
   - Create `skills/<skill_name>/SKILL.md` with valid YAML frontmatter (`name` and `description`).
   - Use `references/` for large documentation (progressive disclosure) to preserve token context.
   - Put helper tools in `scripts/` and configuration templates in `resources/`.

2. **Creating Rules (`GEMINI.md` / `AGENTS.md`)**:
   - Enforce repository-specific guidelines, coding styles, or API constraints.
   - Use `always_on` for universal constraints or `model_decision` for targeted triggers.

3. **Configuring Hooks (`hooks.json`)**:
   - Attach pre-tool execution, post-tool execution, or startup scripts.

4. **Validating Skills**:
   - Run `bash scripts/validate-skills.sh` to ensure compliance.