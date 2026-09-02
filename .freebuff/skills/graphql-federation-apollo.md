---
name: graphql-federation-apollo
description: >-
  Implement Apollo Federation v2 Supergraph routing, Subgraph entity resolution (@key, @shareable, @external),
  and DataLoader N+1 batching. Use when designing unified GraphQL schemas, connecting distributed subgraphs,
  or resolving GraphQL performance bottlenecks.
---

# GraphQL Federation & Apollo Supergraph Master

This skill provides industry standards for decomposing monolithic GraphQL schemas into declarative Apollo Federation v2 subgraphs with zero N+1 query problems.

---

## 🌐 Apollo Federation v2 Supergraph Architecture

```mermaid
graph TD
    Client[GraphQL Client] --> Router[Apollo Supergraph Router Gateway]
    Router --> SG1[Users Subgraph: @key id]
    Router --> SG2[Orders Subgraph: @key id]
    Router --> SG3[Reviews Subgraph: @key id]
    
    Note over Router: Query plan generated automatically across subgraphs
```

---

## 🎯 Production Invariants

1. **Mandatory DataLoader**: Never perform per-row SQL queries inside GraphQL field resolvers. Always batch IDs using DataLoader.
2. **Entity Keys (`@key`)**: Define clean primary key directives (`@key(fields: "id")`) for federated entities resolved across subgraphs.
3. **Query Depth & Cost Limiting**: Enforce maximum query depth (e.g. max depth 6) and query complexity scores to prevent Denial of Service (DoS) attacks.

---

## 📋 Prosedur Eksekusi

1. **Pola Federasi & Direktif Schema**:
   - Baca [references/federation-key-directives.md](./references/federation-key-directives.md).
2. **Template Subgraph Schema**:
   - Rujuk [resources/subgraph.graphql](./resources/subgraph.graphql).
3. **Audit DataLoader & Resolvers**:
   - Jalankan `bash skills/graphql-federation-apollo/scripts/check-dataloader.sh`.