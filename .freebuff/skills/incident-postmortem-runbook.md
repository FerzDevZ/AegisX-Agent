---
name: incident-postmortem-runbook
description: >-
  Triage production incidents, execute SRE mitigation runbooks, perform Root Cause Analysis (5 Whys),
  and conduct blameless postmortems with actionable preventions.
  Use during live production outages, on-call escalations, or writing post-incident reviews.
---

# Production Incident Triage & Blameless Postmortem Master

This skill provides an SRE-grade operational protocol to triage live production incidents, restore service availability, isolate root causes using the 5 Whys, and conduct blameless postmortems.

---

## 🚨 Incident Response Lifecycle

```mermaid
graph TD
    Alert[1. Detection & Alert: PagerDuty / Grafana] --> Triage[2. Incident Commander: Declare Severity P1-P4 & Establish War Room]
    Triage --> Mitigate[3. Mitigation First: Rollback / Traffic Drain / Scale Up - Restore SLA]
    Mitigate --> RCA[4. Root Cause Analysis: 5 Whys & Timeline Reconstruction]
    RCA --> Postmortem[5. Blameless Postmortem & Action Item Tracking]
```

---

## 🎯 Incident Invariants

1. **Mitigate First, Debug Later**: During a live outage, the primary objective is restoring service (e.g. rollback, restart, failover), not fixing the code in place.
2. **Blameless Culture**: Postmortems assume humans operate with good intent given the tools and context they had. Focus on systemic and structural failure modes.
3. **Action Items with Owners**: Every postmortem MUST produce preventive action items with an assigned owner and due date.

---

## 📋 Prosedur Eksekusi

1. **Root Cause Analysis (5 Whys)**:
   - Baca [references/five-whys-rca.md](./references/five-whys-rca.md).
2. **Template Postmortem**:
   - Format: [resources/postmortem-template.md](./resources/postmortem-template.md).
3. **Triage Checklist**:
   - Jalankan `bash skills/incident-postmortem-runbook/scripts/incident-triage-checklist.sh`.