---
name: rag-graph-knowledge-neo4j
description: >-
  Architect and build GraphRAG (Knowledge Graph Augmented Generation) pipelines with Neo4j, Cypher querying,
  entity-relationship extraction, community clustering (Leiden algorithm), and hybrid Graph-Vector retrieval.
  Use when connecting complex relational knowledge, multi-hop reasoning, or structuring domain ontologies.
---

# GraphRAG & Neo4j Knowledge Graph Master

This skill provides industry standards for combining structured Knowledge Graphs with semantic Vector Search to achieve multi-hop, highly accurate Retrieval-Augmented Generation (GraphRAG).

---

## 🕸️ GraphRAG Hybrid Retrieval Pipeline

```mermaid
graph TD
    Query[User Multi-Hop Question] --> Extract[1. Extract Query Entities & Relationships]
    Extract --> GraphSearch[2. Cypher Graph Traversal: Neighbors, Path, Communities]
    Extract --> VectorSearch[3. Vector Semantic Chunk Retrieval]
    GraphSearch --> Merge[4. Knowledge Graph Context + Chunk Fusion]
    VectorSearch --> Merge
    Merge --> LLM[5. Grounded LLM Response with Entity Citations]
```

---

## 🎯 Production Invariants

1. **Entity Disambiguation**: Run fuzzy and semantic similarity resolution before creating graph nodes to avoid duplicate entities (e.g. "Apple Inc" vs "Apple").
2. **Directed & Typed Relationships**: Always declare explicit relationship types with metadata properties (`[:AUTHORED_BY { since: 2024 }]`).
3. **Graph Traversal Depth Limit**: Limit multi-hop traversals to max 2-3 hops to avoid exponential query time explosions.

---

## 📋 Prosedur Eksekusi

1. **Pola Ekstraksi Entitas & Relasi**:
   - Baca [references/graphrag-entity-extraction.md](./references/graphrag-entity-extraction.md).
2. **Template Cypher Queries**:
   - Format: [resources/cypher-queries.cql](./resources/cypher-queries.cql).
3. **Validasi Query Cypher**:
   - Jalankan `bash skills/rag-graph-knowledge-neo4j/scripts/check-cypher-syntax.sh`.
