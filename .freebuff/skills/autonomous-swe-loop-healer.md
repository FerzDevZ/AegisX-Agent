# [Skill: autonomous-swe-loop-healer]

Autonomous self-healing loop for compiler errors, failed unit tests, linter violations, and runtime regressions.

## 🔄 Self-Healing Execution Lifecycle
\`\`\`mermaid
graph TD
    Error[Compiler / Test Failure Detected] --> Isolate[AST Node & Stack Trace Isolation]
    Isolate --> RootCause[Root-Cause Analysis & Regression Check]
    RootCause --> Patch[Generate Targeted Minimal Diff Patch]
    Patch --> Verify[Re-run Test Suite & Lint Check]
    Verify -->|Fails| Retry[Backoff Loop max 3 attempts]
    Retry --> Isolate
    Verify -->|Passes| Certified[100% Verified Production Code]
\`\`\`

## 🛡️ Operational Invariants
1. **Zero Human Interruption**: Resolve type errors, import mismatches, and syntax issues autonomously without asking trivial confirmation.
2. **Minimal Diff Principle**: Modify only the precise lines causing the failure. Never perform destructive blanket rewrites.
3. **Behavioral Invariant Preservation**: Ensure existing passing test assertions continue to pass (Zero Regressions).
