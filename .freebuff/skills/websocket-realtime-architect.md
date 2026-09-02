---
name: websocket-realtime-architect
description: >-
  Design real-time WebSockets, Server-Sent Events (SSE), Redis Pub/Sub cluster scaling,
  heartbeat ping-pong reconnects, presence tracking, and backpressure handling.
  Use when building live chat, real-time collaboration, notification feeds, or streaming dashboards.
---

# WebSockets & Real-Time Systems Master

This skill provides production standards for building horizontal, fault-tolerant real-time architectures with WebSocket clustering, automatic reconnection with exponential backoff, and heartbeat health checks.

---

## ⚡ Scaled WebSocket Clustering Architecture

```mermaid
graph TD
    Client1[Client A: Browser / App] --> WS1[WebSocket Server Node 1]
    Client2[Client B: Browser / App] --> WS2[WebSocket Server Node 2]
    
    WS1 <--> PubSub[(Redis Pub/Sub / Dragonfly Cluster)]
    WS2 <--> PubSub
    
    Note over PubSub: Message broadcast across nodes seamlessly
```

---

## 🎯 Production Invariants

1. **Heartbeat / Ping-Pong**: Send periodic server-initiated ping every 30s. Disconnect dead TCP sockets after 2 missed pongs.
2. **Cluster Scaling via Redis Pub/Sub**: Never assume connected clients live on the same container node. Route cross-node broadcasts via Redis Pub/Sub channels.
3. **SSE for Unidirectional Streaming**: For LLM token streaming and server-to-client notifications, use **Server-Sent Events (SSE)** instead of heavy full-duplex WebSockets.

---

## 📋 Prosedur Eksekusi

1. **Pola Clustering Real-Time**:
   - Baca [references/realtime-cluster-scaling.md](./references/realtime-cluster-scaling.md).
2. **Template WebSocket Server**:
   - Rujuk [resources/ws-server.ts](./resources/ws-server.ts).
3. **Uji Koneksi WebSocket**:
   - Jalankan `bash skills/websocket-realtime-architect/scripts/test-ws-connection.sh`.