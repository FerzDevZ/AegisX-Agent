---
name: adr-tech-documentation
description: >-
  Write clear Architecture Decision Records (ADR), technical RFCs, and structured system docs
  using the Diátaxis framework (Tutorials, How-Tos, Reference, Explanation).
  Use when documenting architectural decisions, authoring engineering RFCs, or structuring project wikis.
---

# Architecture Decision Records (ADR) & Technical Documentation Master

This skill provides industry standards for recording architectural decisions, managing technical RFCs, and structuring software documentation using the Diátaxis framework.

---

## 📚 The Diátaxis Documentation Framework

```mermaid
graph TD
    subgraph Practical Learning
        T[1. Tutorials: Learning-oriented for beginners]
        H[2. How-To Guides: Goal-oriented for real-world tasks]
    end
    subgraph Theoretical Knowledge
        R[3. Reference: Information-oriented technical specs]
        E[4. Explanation: Understanding-oriented architectural context]
    end
```

---

## 🎯 ADR Production Invariants

1. **Immutable Historical Record**: Once an ADR is `Accepted`, it is never modified. If a decision is superseded, create a new ADR referencing the old one (`Supersedes: ADR-0002`).
2. **Context & Consequences**: Every ADR must document why a choice was made and explicitly list the trade-offs and negative consequences accepted.

---

## 📋 Prosedur Eksekusi

1. **Pola Diátaxis**:
   - Baca [references/diataxis-documentation-framework.md](./references/diataxis-documentation-framework.md).
2. **Template ADR**:
   - Terapkan format dari [resources/adr-template.md](./resources/adr-template.md).
3. **Scaffold ADR Baru**:
   - Jalankan `bash skills/adr-tech-documentation/scripts/new-adr.sh "<judul_keputusan>"`.