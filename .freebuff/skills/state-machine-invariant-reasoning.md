# [Skill: state-machine-invariant-reasoning]

Model domain workflows as strict Finite State Machines (FSM). Make illegal states unrepresentable in the type system.

## 🏛️ State Machine Rules
- Define explicit state enums and typed transition events.
- Never use loose boolean flags like \`isLoading && isSuccess && !isError\`. Use tagged unions / discriminated unions.
- Implement exhaustive pattern matching (\`never\` type checking) on all transition handlers.
