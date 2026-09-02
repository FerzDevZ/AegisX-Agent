---
name: vue-nuxt-master
description: >-
  Develop scalable Vue 3 and Nuxt 3 applications with Composition API, script setup,
  Pinia state stores, Nitro engine SSR, and auto-imported composables.
  Use when building Vue applications, migrating Vue 2 to 3, or optimizing Nuxt 3 architectures.
---

# Vue 3 & Nuxt 3 Master

This skill provides modern standards for developing high-performance Vue 3 and Nuxt 3 applications using Composition API `<script setup lang="ts">`, Pinia, and server-side rendering (SSR) via Nitro.

---

## ⚡ Core Vue 3 / Nuxt 3 Standards

1. **Strict Composition API**: Always use `<script setup lang="ts">` instead of Options API.
2. **Data Fetching with `useAsyncData` & `useFetch`**: In Nuxt 3, always use `useFetch` with unique keys to prevent hydration mismatch and double-fetching.
3. **Pinia State**: Keep stores modular with setup store syntax (`defineStore('id', () => { ... })`).

---

## 📋 Prosedur Eksekusi

1. **Composition & Pinia Architecture**:
   - Baca [references/composition-api-pinia.md](./references/composition-api-pinia.md).
2. **Template Composable**:
   - Terapkan pola dari [resources/nuxt-composable.ts](./resources/nuxt-composable.ts).
3. **Audit Struktur Proyek**:
   - Jalankan `bash skills/vue-nuxt-master/scripts/check-vue-structure.sh`.