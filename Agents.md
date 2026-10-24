# Agents.md

Notes for anyone (human or AI) continuing work on tcp-trace.

## Goal

A TCP connection viewer for ordinary programmers, mainly for front-end debugging where HTTP-level tools are not enough or the protocol is not HTTP. It is not a Wireshark replacement: stay at the "one connection, explained in plain words" level.

## Layout

```
capture source ──► decode ──► tracker ──► server (HTTP API) ──► web UI
(file/stdin/        (link →    (connections,  │
 dumpcap/tcpdump)    IP → TCP)  seq analysis,  └► cli (tables / JSON / agent-guide)
                                reassembly)
```

| File | Responsibility |
| --- | --- |
| `src/main.rs` | argh subcommands: open, capture, interfaces, summary, show, record, agent-guide; tests at the bottom |
| `src/source.rs` | pcap-parser streaming reader; spawns dumpcap (preferred, no root with ChmodBPF) or tcpdump |
| `src/decode.rs` | Ethernet, BSD loopback (macOS `lo0`), Linux SLL/SLL2, raw IP → `Segment` |
| `src/tracker.rs` | connection table, client/server roles, relative seq/ack, notes (retrans, gap, out-of-order, dup ACK, zero window, keepalive), per-direction chunks capped at 16 MB |
| `src/proto.rs` | protocol guess, TLS SNI/ALPN, HTTP/1.x message split, WebSocket frames with permessage-deflate |
| `src/cli.rs` | terminal/JSON output, `findings` (stable codes), `AGENT_GUIDE` text |
| `src/server.rs` | axum on 127.0.0.1: `/api/summary`, `/api/conns`, `/api/conns/{id}`, `/{id}/stream`, `/{id}/messages`; serves `web/dist` via rust-embed |
| `web/src/` | Preact UI: `App.tsx` (toolbar, connection table), `Detail.tsx` (overview, messages, stream, packets, ladder), `format.ts` (diagnosis text in Chinese), `styles.css` (tokens, light/dark) |

The live UI polls `/api/summary` once a second and refetches when `version` changes.

## Conventions

- Rust uses `rustfmt.toml` (2 spaces, width 140); run `cargo fmt`.
- UI text is Chinese; CLI and agent-facing output is English with stable codes. When adding a diagnosis, add it to both `web/src/format.ts` (`diagnose`) and `src/cli.rs` (`findings`), and list new codes in `AGENT_GUIDE`.
- `web/dist` is committed so `cargo build` works without Node. After changing `web/`, run `npm run build` in `web/` and commit `dist` (delete the old hashed assets).
- CI must stay light: fmt, `cargo test`, web typecheck. No release builds or long jobs.

## Testing

- `cargo test` runs against `examples/demo.pcap` (HTTP keep-alive, POST, WebSocket with deflate, a line protocol, a refused connection, a client RST, TLS with SNI) and `examples/demo-issues.pcap` (same capture with one segment delayed and one duplicated).
- New sample captures: record loopback traffic with tcpdump while driving a small Node script, then add assertions in `main.rs` tests.
- UI check: `cargo run -- open examples/demo-issues.pcap`, or Playwright screenshots for visual review.

## Status

Preview, built and tested on Linux only. Not yet verified on macOS (dumpcap path discovery, `lo0` link type, ChmodBPF permissions).

## Ideas not done yet

- TLS decryption via SSLKEYLOGFILE (or delegate to tshark)
- HTTP/2 / gRPC frame decoding
- Push updates over WebSocket instead of polling; incremental conn list for big live captures
- Export one connection as pcap; copy as curl / websocat
- Seq-vs-time (tcptrace style) chart for throughput and loss
- Memory cap / ring buffer for long live captures
