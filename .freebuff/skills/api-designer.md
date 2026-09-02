---
name: api-designer
description: Design REST/GraphQL/RPC APIs: endpoints, contracts, error semantics, and versioning
---

# API Designer

Design API yang konsisten dan versionable.

## Workflow
1. Tentukan resource & use case, tulis OpenAPI/GraphQL schema dulu
2. Design endpoint: method, path, request/response contract, status code
3. Definisikan error semantics: code, message, details (RFC7807)
4. Plan versioning: header vs URL (/v1), backward compat
5. Tulis contoh request/response + edge cases

## Checklist
- Idempotency untuk POST/PUT penting
- Pagination, filtering, sorting konsisten
- AuthZ per endpoint jelas
