---
name: node-typescript-backend
description: >-
  Build robust Node.js/TypeScript backend services with Fastify, NestJS, or Express,
  strict TypeScript types, Prisma/Drizzle ORM, Zod validation, and structured error handling.
  Use when architecting Node.js services, writing backend APIs, or setting up TypeScript tooling.
---

# Node.js & TypeScript Backend Master

This skill provides architectural standards for developing high-throughput Node.js microservices using Fastify / Express, strict TypeScript (`strict: true`, `noUncheckedIndexedAccess: true`), and modern type-safe ORMs (Prisma / Drizzle).

---

## ⚡ Core Backend Standards

1. **Fastify > Express for Throughput**: Favor Fastify for up to 3-5x higher RPS and native schema validation.
2. **End-to-End Type Safety with Zod**: Parse all incoming request bodies, query params, and headers with Zod schemas.
3. **Structured JSON Logging**: Use Pino logger with standard correlation IDs (`req.id`).

---

## 📋 Prosedur Eksekusi

1. **Pola Fastify & Drizzle/Prisma**:
   - Baca [references/fastify-prisma-patterns.md](./references/fastify-prisma-patterns.md).
2. **Boilerplate Server**:
   - Terapkan kode dari [resources/server.ts](./resources/server.ts).
3. **Validasi Strict TS**:
   - Jalankan `bash skills/node-typescript-backend/scripts/check-ts-strict.sh`.