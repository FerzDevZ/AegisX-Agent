---
name: api-design-rest-grpc-graphql
description: >-
  Design production OpenAPI 3.1 REST APIs, gRPC Protocol Buffers, and GraphQL schemas with consistent
  error models (RFC 7807), idempotency keys, pagination (Cursor-based), and API versioning.
  Use when defining API contracts, designing endpoints, writing schemas, or reviewing interfaces.
---

# API Design Master (REST, gRPC, GraphQL)

This skill provides industry standards for designing robust, evolvable, and developer-friendly APIs across REST (OpenAPI 3.1), gRPC (Protobuf), and GraphQL.

---

## 📡 API Protocol Selection Matrix

| Protocol | Transport | Best Used For | Serialization |
|---|---|---|---|
| **REST (OpenAPI 3.1)** | HTTP/1.1, HTTP/2 | Public web APIs, developer portals, standard CRUD | JSON |
| **gRPC** | HTTP/2, HTTP/3 | Internal microservice-to-microservice, high throughput | Binary (Protobuf) |
| **GraphQL** | HTTP POST | Complex frontend dashboards with heterogeneous data needs | JSON |

---

## 🎯 Production Invariants

1. **Standard Error Schema (RFC 7807 / RFC 9457)**:
   - Always return `application/problem+json` containing `type`, `title`, `status`, `detail`, and `instance`.
2. **Cursor-Based Pagination**:
   - Never use `OFFSET / LIMIT` on large datasets. Always use cursor-based pagination (`limit`, `after_cursor`).
3. **Idempotency on Mutations**:
   - Support `Idempotency-Key` header on all `POST` operations.

---

## 📋 Prosedur Eksekusi

1. **Memilih & Mendesain Kontrak API**:
   - Baca [references/api-standards-comparison.md](./references/api-standards-comparison.md).
2. **Template Spesifikasi**:
   - OpenAPI 3.1: [resources/openapi-spec.yaml](./resources/openapi-spec.yaml).
   - gRPC Protobuf: [resources/service.proto](./resources/service.proto).
3. **Validasi Kontrak**:
   - Jalankan `bash skills/api-design-rest-grpc-graphql/scripts/validate-openapi.sh`.