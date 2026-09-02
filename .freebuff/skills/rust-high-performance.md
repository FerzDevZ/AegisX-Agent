---
name: rust-high-performance
description: >-
  Develop safe, concurrent, high-throughput systems and async web servers with Rust,
  Tokio async runtime, Axum framework, ownership/borrowing mechanics, and zero-cost abstractions.
  Use when building mission-critical low-latency systems, CLI tools, or WASM modules.
---

# Rust High-Performance & Systems Engineer

This skill provides idiomatic Rust patterns for leveraging ownership/borrowing semantics, avoiding unnecessary clones, managing async tasks with Tokio, and building blazingly fast HTTP microservices with Axum.

---

## 🦀 Core Rust Systems Standards

1. **Borrowing & Lifetimes**: Prefer passing borrowed references (`&str`, `&[T]`) over taking ownership or calling `.clone()` unless strictly necessary.
2. **Error Handling**: Use `Result<T, E>` with `thiserror` for library domains and `anyhow` for applications. Never `.unwrap()` in production paths.
3. **Tokio Async Runtime**: Use `tokio::spawn` with `Arc<Mutex<T>>` or `tokio::sync::RwLock` for shared concurrent state.

---

## 📋 Prosedur Eksekusi

1. **Pola Tokio Async & Ownership**:
   - Baca [references/ownership-tokio-async.md](./references/ownership-tokio-async.md).
2. **Boilerplate Axum Web Server**:
   - Terapkan kode dari [resources/main.rs](./resources/main.rs).
3. **Audit Clippy & Compiler Checks**:
   - Jalankan `bash skills/rust-high-performance/scripts/check-clippy.sh`.