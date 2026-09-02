---
name: performance-optimizer
description: Find and fix bottlenecks: profile first, measure before/after, avoid premature optimization
---

# Performance Optimizer

Optimasi berbasis data, bukan feeling.

## Workflow
1. Profile dulu: flamegraph, EXPLAIN, pprof, lighthouse
2. Ukur baseline: latency, throughput, memory
3. Fix bottleneck terbesar dulu (80/20)
4. Ukur after, bandingkan
5. Document trade-off

## Focus
- DB: index, N+1, pooling
- Frontend: bundle size, LCP/INP, hydration
- Backend: caching, queuing, concurrency
