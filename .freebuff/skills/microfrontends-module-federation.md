---
name: microfrontends-module-federation
description: >-
  Architect microfrontends using Webpack 5 / Vite / Rspack Module Federation,
  runtime orchestration, cross-app state sharing, isolated CSS, and decoupled deployment pipelines.
  Use when breaking monolith frontends, managing multi-team web apps, or configuring Module Federation.
---

# Microfrontends & Module Federation Master

This skill provides industry standards for scaling frontend engineering organizations using Module Federation, shared runtime singletons, and isolated micro-apps.

---

## 🧩 Module Federation Architecture

```mermaid
graph TD
    Host[Host Shell App: Navigation & Global Auth] --> Remote1[Remote Microfrontend: Checkout App]
    Host --> Remote2[Remote Microfrontend: Dashboard App]
    Host --> Remote3[Remote Microfrontend: User Profile App]
    
    Shared[Shared Singletons: React, React-DOM, Zustand, Tailwind Tokens] -.-> Host
    Shared -.-> Remote1
    Shared -.-> Remote2
    Shared -.-> Remote3
```

---

## 🎯 Production Invariants

1. **Shared Singletons**: Always mark `react` and `react-dom` as `{ singleton: true, requiredVersion: "..." }` to prevent dual-React runtime crashes.
2. **Resilient Fallbacks & Error Boundaries**: Wrap every remote microfrontend in a React Error Boundary with a graceful offline fallback UI.
3. **Decoupled CI/CD**: Each remote repository must be buildable and deployable independently to S3/Cloudflare Pages without redeploying the Host Shell.

---

## 📋 Prosedur Eksekusi

1. **Pola Module Federation**:
   - Baca [references/module-federation-patterns.md](./references/module-federation-patterns.md).
2. **Template Konfigurasi Federation**:
   - Rujuk [resources/rspack-mf.config.js](./resources/rspack-mf.config.js).
3. **Audit Ketergantungan Shared**:
   - Jalankan `bash skills/microfrontends-module-federation/scripts/check-shared-deps.sh`.