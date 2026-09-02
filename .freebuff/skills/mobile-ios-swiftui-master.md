---
name: mobile-ios-swiftui-master
description: >-
  Build native iOS applications with SwiftUI, Swift Concurrency (async/await, Actors),
  the @Observable macro, SwiftData / CoreData persistence, and smooth 120 FPS ProMotion animations.
  Use when developing native iOS/iPadOS/watchOS applications or optimizing Swift code.
---

# Native iOS & SwiftUI Master

This skill provides industry standards for building native, robust Apple platform apps with SwiftUI, modern Swift concurrency, actor isolation, and SwiftData.

---

## 📱 SwiftUI Architecture & Observation Flow

```mermaid
graph TD
    View[SwiftUI View: Declarative Hierarchy] --> Model[@Observable ViewModel / Model Actor]
    Model --> Network[Async / Await Network Client: URLSession]
    Model --> LocalStore[(SwiftData / SQLite Local Cache)]
    LocalStore --> View
```

---

## 🎯 Production Invariants

1. **MainActor UI Isolation**: Always decorate UI state mutation classes with `@MainActor` to prevent background thread UI glitches.
2. **Modern Observation Framework**: Use the `@Observable` macro instead of legacy `ObservableObject` and `@Published` properties.
3. **Actor Data Isolation**: Encapsulate shared mutable state (like database managers or token refreshers) inside `actor` types to prevent data races.

---

## 📋 Prosedur Eksekusi

1. **Panduan Swift Concurrency & Observation**:
   - Baca [references/swiftui-observation-concurrency.md](./references/swiftui-observation-concurrency.md).
2. **Template View SwiftUI**:
   - Rujuk [resources/ContentView.swift](./resources/ContentView.swift).
3. **Audit Kesiapan Swift**:
   - Jalankan `bash skills/mobile-ios-swiftui-master/scripts/check-swift-syntax.sh`.
