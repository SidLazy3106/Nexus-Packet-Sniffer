# NEXUS architecture

```
┌────────────── React UI (WebView2) ──────────────┐
│ pages/* → lib/store (external store) → lib/api  │
│   packet rows: append-only array, rAF-batched   │
└───────────▲──────────────────────┬──────────────┘
   events   │ nexus://packets      │ invoke(commands)
   (100 ms) │ nexus://snapshot(1s) ▼
┌───────────┴───────── Rust backend ──────────────┐
│ commands.rs  →  state.rs (AppState)             │
│                    │                            │
│  capture.rs  ──bounded sync_channel──▶ processor│
│  (pcap thread)       try_send, drops counted    │
│                                      │          │
│                              engine.rs (1 lock per batch)
│                ┌─────────────┼───────────────┐  │
│          decoder/*      analytics.rs    diagnostics/*
│       (pure functions)  (aggregates)   (TCP/DNS/ICMP/traffic)
│                │                                │
│          ring buffer ─▶ pcap_io.rs (spool/export)│
│  storage.rs (SQLite: settings, session metadata)│
└─────────────────────────────────────────────────┘
```

## Modules (`src-tauri/src`)

| Module | Responsibility |
|---|---|
| `constants.rs`, `config.rs` | Protocol numbers/limits; user settings and diagnostic thresholds with defaults and clamping |
| `decoder/` | Bounds-checked Ethernet/VLAN, IPv4, IPv6 (+extension headers), TCP (+options), UDP, ICMP, ICMPv6, ARP, DNS, DHCP. Produces a field tree with byte offsets, metadata for analysers, and anomalies |
| `capture.rs` | Interface discovery, BPF validation, the `PacketSource` trait (Npcap implementation + in-memory test source), capture thread, stats polling, processor thread |
| `engine.rs` | Ring buffer of packets, payload retention, session spooling, export, redaction |
| `analytics.rs` | Totals, protocol mix, top talkers, connection tracking, per-second series |
| `diagnostics/` | Findings, evidence, health, latency observations. `tcp.rs` is the flow state machine plus one handler per event; `services.rs` DNS/ICMP/traffic; findings are built with the `Spec`/`Evidence` builders in `mod.rs` |
| `pcap_io.rs` | Streaming PCAP/PCAPNG reader and writers (no Npcap needed) |
| `storage.rs` | SQLite persistence |
| `report.rs` | JSON/CSV report generation |
| `npcap.rs` | Detects Npcap, sets the DLL search path, produces guidance |
| `state.rs`, `commands.rs` | Operations and the Tauri command surface |

## Design rules

- **Bounded everywhere**: capture queue (`queue_capacity`), packet ring (`max_packets_in_memory`), flow tables, DNS/ping tables, per-flow segment history, findings, evidence, time series, session file size.
- **Backpressure is explicit**: a full queue increments `pipeline_dropped`; it never blocks the capture thread.
- **Two kinds of "missing" are never confused**: driver/kernel drops (`ps_drop`, `ps_ifdrop`), queue drops, and network behaviour (retransmissions etc.). Drops appear as their own *capture integrity* findings and as limitations on TCP/latency findings.
- **Testable seams**: packet sources sit behind `PacketSource`, so the queue, backpressure, pause and failure paths are tested without a driver; every tunable threshold lives in `DiagConfig`, fixed limits in `constants.rs`.
- **No panics on input**: all reads go through checked helpers; exhaustive truncation and random-byte tests; per-packet `catch_unwind` in the pipeline.
- **Findings are reproducible**: analysis is a pure function of packets and thresholds (timeouts use packet time offline, wall clock only for live ticks).
- **Offload awareness**: checksums are not validated; zero/oversized length fields on locally captured outbound frames are listed as a possible cause of malformed observations.

## Diagnostics method

TCP is tracked per canonical 4-tuple. For each direction the engine keeps next expected sequence, recent segment history, and gaps ("holes").

| Observation | Rule |
|---|---|
| Retransmission | Same sequence number seen again, or a late segment filling a gap after more than `reorder_window_ms` (original not observed → lower confidence) |
| Out-of-order | A segment filling a gap within `reorder_window_ms` |
| Duplicate ACK | Pure ACK repeating the previous ack number with unchanged window while later data is outstanding; reported from `dupack_threshold` repeats |
| Sequence gap | Segment beyond expected sequence; reported as *not present in capture*, never as loss |
| Keep-alive | `seq = next-1`, 1 byte: excluded |
| Handshake timing | SYN → SYN-ACK → ACK intervals (measured; capture location unknown so no RTT claim) |
| RTT sample | Data packet to the ACK whose number equals its end sequence; cleared on retransmission (Karn) |
| Connection failure | SYN answered by RST (refused), or no reply within `syn_timeout_s` (unanswered, lower confidence) |

DNS pairs queries and responses by (client, server, ID, name). ICMP echo pairs by (src, dst, id, seq).
Health = 100 − Σ(severity weight × confidence) over network findings; capture findings are excluded and shown as integrity.

## Limitations

- Live capture requires Npcap and (by default) Administrator rights; not tested in CI.
- IP fragments are flagged but not reassembled; DNS over TCP and application protocols beyond DNS/DHCP are not decoded; TLS is never decrypted.
- Checksums are not validated.
- Diagnostics reflect only the capture point; asymmetric routing and offloads can hide or create observations.
- PCAPNG import supports section/interface/enhanced/simple packet blocks (options other than `if_tsresol` are ignored); export writes a single interface.
- Packet numbers restart at 1 per capture; evicted packets cannot be inspected or exported.
