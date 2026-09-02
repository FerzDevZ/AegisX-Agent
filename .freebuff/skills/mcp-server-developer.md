---
name: mcp-server-developer
description: >-
  Develop, test, and integrate Model Context Protocol (MCP) servers using stdio or SSE transports.
  Use when building custom tool providers, exposing databases/APIs to AI models, or configuring MCP clients.
---

# MCP (Model Context Protocol) Server Developer

This skill provides comprehensive instructions to build, debug, and publish Model Context Protocol (MCP) servers enabling seamless tool and resource sharing with LLMs.

---

## 🔌 The MCP Architecture

```mermaid
sequenceDiagram
    participant Host as LLM Host (Antigravity/Cursor/Claude)
    participant Client as MCP Client
    participant Server as MCP Server (Stdio/SSE)
    participant DB as External Resource / Tool API

    Host->>Client: Request tool invocation
    Client->>Server: JSON-RPC 2.0 (tools/call)
    Server->>DB: Execute query/action
    DB-->>Server: Result data
    Server-->>Client: JSON-RPC Response (content: text/image)
    Client-->>Host: Formatted Context
```

---

## 🛠️ Step-by-Step Development Workflow

1. **Scaffold MCP Server**:
   - Use TypeScript (`@modelcontextprotocol/sdk`) or Python (`mcp` package).
   - Reference boilerplate in [resources/server-template.ts](./resources/server-template.ts).

2. **Define Tools with Zod Schemas**:
   - Define strict input schemas and unambiguous tool descriptions.

3. **Verify Stdio / SSE Transport**:
   - Run the validation test: `python3 skills/mcp-server-developer/scripts/test-mcp-stdio.py <command>`.
   - Read protocol specifications in [references/mcp-protocol-specs.md](./references/mcp-protocol-specs.md).