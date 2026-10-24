//! Terminal output for scripts and AI agents: tables, JSON, findings.

use crate::proto;
use crate::tracker::{
  Conn, ConnSummary, Dir, Packet, NOTE_DUP_ACK, NOTE_KEEPALIVE, NOTE_OUT_OF_ORDER, NOTE_PREV_LOST, NOTE_RETRANS, NOTE_ZERO_WINDOW,
};
use crate::State;
use base64::Engine;
use serde::Serialize;
use std::io::Write;

/// Print and ignore a closed pipe (e.g. `| head`).
macro_rules! out {
  ($($arg:tt)*) => {{
    let _ = writeln!(std::io::stdout().lock(), $($arg)*);
  }};
}

fn print_json<T: Serialize>(v: &T) {
  let _ = serde_json::to_writer_pretty(std::io::stdout().lock(), v);
  out!();
}

#[derive(Serialize)]
pub struct Finding {
  pub code: &'static str,
  pub level: &'static str,
  pub message: String,
}

fn first_data(c: &Conn, dir: Dir) -> Option<f64> {
  c.packets.iter().find(|p| p.dir == dir && p.len > 0).map(|p| p.ts)
}

/// Same rules as the web UI's diagnosis panel, with stable codes for tools.
pub fn findings(c: &Conn) -> Vec<Finding> {
  let s = c.summary();
  let mut out = Vec::new();
  let mut add = |code, level, message: String| out.push(Finding { code, level, message });
  match s.state {
    "syn-sent" => add(
      "no_syn_ack",
      "error",
      "client sent SYN but got no reply: host unreachable or packets dropped by a firewall".into(),
    ),
    "reset" if s.rst_from == Some(Dir::S2c) && s.handshake_ms.is_none() && !s.partial => add(
      "connection_refused",
      "error",
      "server answered the SYN with RST: nothing is listening on that port".into(),
    ),
    "reset" => {
      let who = if s.rst_from == Some(Dir::C2s) { "client" } else { "server" };
      add(
        if who == "client" { "reset_by_client" } else { "reset_by_server" },
        "error",
        format!("{who} aborted the connection with RST (process killed, request cancelled, or proxy/load balancer timeout)"),
      )
    }
    _ => {}
  }
  if s.retrans > 0 {
    add(
      "retransmissions",
      "warn",
      format!("{} retransmitted segments: packet loss or a slow receiver", s.retrans),
    );
  }
  if s.lost > 0 {
    add(
      "data_gaps",
      "warn",
      format!("{} gaps where data was not captured (loss, reordering, or capture drops)", s.lost),
    );
  }
  if s.dup_acks > 0 {
    add(
      "dup_acks",
      "warn",
      format!("{} duplicate ACKs: receiver is waiting for missing data", s.dup_acks),
    );
  }
  if s.zero_windows > 0 {
    add(
      "zero_window",
      "warn",
      format!("{} zero-window advertisements: receiver cannot keep up", s.zero_windows),
    );
  }
  if let (Some(a), Some(b)) = (first_data(c, Dir::C2s), first_data(c, Dir::S2c)) {
    let wait = (b - a) * 1000.0;
    if wait > 200.0 {
      add(
        "slow_first_byte",
        "warn",
        format!("server sent its first byte {wait:.0} ms after the client's first data: time is spent in the server, not the network"),
      );
    }
  }
  if s.partial {
    add(
      "partial",
      "info",
      "capture started mid-connection; client/server roles are guessed from ports".into(),
    );
  }
  if s.truncated {
    add("truncated", "info", "payload beyond 16 MB per connection was not kept".into());
  }
  out
}

pub fn issue_count(s: &ConnSummary) -> u32 {
  s.retrans + s.lost + s.dup_acks + s.zero_windows + matches!(s.state, "reset" | "syn-sent") as u32
}

pub struct ListOpts {
  pub json: bool,
  pub issues: bool,
  pub port: Option<u16>,
  pub grep: Option<String>,
}

pub fn list(st: &State, o: &ListOpts) {
  if let Some(e) = &st.error {
    eprintln!("tcp-trace: {e}");
  }
  let t = &st.tracker;
  let grep = o.grep.as_ref().map(|g| g.to_lowercase());
  let rows: Vec<ConnSummary> = t
    .conns
    .iter()
    .map(|c| c.summary())
    .filter(|s| !o.issues || issue_count(s) > 0)
    .filter(|s| {
      o.port
        .map(|p| s.server_port == p || s.client.ends_with(&format!(":{p}")))
        .unwrap_or(true)
    })
    .filter(|s| {
      grep
        .as_ref()
        .map(|g| {
          format!(
            "{} {} {} {} {}",
            s.client,
            s.server,
            s.proto,
            s.state,
            s.label.as_deref().unwrap_or("")
          )
          .to_lowercase()
          .contains(g)
        })
        .unwrap_or(true)
    })
    .collect();
  if o.json {
    #[derive(Serialize)]
    struct List<'a> {
      frames: u64,
      tcp_frames: u64,
      connections: &'a [ConnSummary],
    }
    print_json(&List {
      frames: t.frames,
      tcp_frames: t.tcp_frames,
      connections: &rows,
    });
    return;
  }
  out!(
    "{} frames, {} TCP segments, {} connections ({} shown)",
    t.frames,
    t.tcp_frames,
    t.conns.len(),
    rows.len()
  );
  out!(
    "{:>4}  {:<44} {:<12} {:<12} {:>6} {:>10} {:>10} {:>6}  label",
    "id",
    "client → server",
    "proto",
    "state",
    "pkts",
    "↑ bytes",
    "↓ bytes",
    "issues"
  );
  for s in rows {
    out!(
      "{:>4}  {:<44} {:<12} {:<12} {:>6} {:>10} {:>10} {:>6}  {}",
      s.id,
      format!("{} → {}", s.client, s.server),
      s.proto,
      s.state,
      s.packets,
      s.bytes_c2s,
      s.bytes_s2c,
      issue_count(&s),
      s.label.as_deref().unwrap_or("")
    );
  }
}

pub struct ShowOpts {
  pub json: bool,
  pub packets: bool,
  pub stream: bool,
  pub messages: bool,
  pub limit: usize,
  pub encoding: String,
}

#[derive(Serialize)]
struct StreamOut {
  dir: Dir,
  ts: f64,
  first_no: u64,
  last_no: u64,
  gap: bool,
  len: usize,
  encoding: &'static str,
  data: String,
}

fn encode(data: &[u8], enc: &str) -> (&'static str, String) {
  match enc {
    "base64" => ("base64", base64::engine::general_purpose::STANDARD.encode(data)),
    "hex" => ("hex", data.iter().map(|b| format!("{b:02x}")).collect()),
    _ => match std::str::from_utf8(data) {
      Ok(s) => ("text", s.to_string()),
      Err(_) => ("base64", base64::engine::general_purpose::STANDARD.encode(data)),
    },
  }
}

pub fn notes_text(n: u16) -> Vec<&'static str> {
  [
    (NOTE_RETRANS, "retransmission"),
    (NOTE_PREV_LOST, "previous_segment_lost"),
    (NOTE_OUT_OF_ORDER, "out_of_order"),
    (NOTE_DUP_ACK, "dup_ack"),
    (NOTE_ZERO_WINDOW, "zero_window"),
    (NOTE_KEEPALIVE, "keepalive"),
  ]
  .iter()
  .filter(|(b, _)| n & b != 0)
  .map(|(_, s)| *s)
  .collect()
}

fn flags_text(f: u8) -> String {
  ["FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"]
    .iter()
    .enumerate()
    .filter(|(i, _)| f & (1 << i) != 0)
    .map(|(_, n)| *n)
    .collect::<Vec<_>>()
    .join(",")
}

#[derive(Serialize)]
struct PacketOut<'a> {
  #[serde(flatten)]
  p: &'a Packet,
  flag_names: String,
  note_names: Vec<&'static str>,
}

pub fn show(st: &State, id: usize, o: &ShowOpts) -> Result<(), String> {
  let c = st
    .tracker
    .conns
    .get(id)
    .ok_or_else(|| format!("no connection with id {id}; run `tcp-trace summary <file>` to list ids"))?;
  let s = c.summary();
  let f = findings(c);
  let timing = serde_json::json!({
    "handshake_ms": s.handshake_ms,
    "duration_ms": (s.last_ts - s.first_ts) * 1000.0,
    "first_byte_ms": match (first_data(c, Dir::C2s), first_data(c, Dir::S2c)) {
      (Some(a), Some(b)) if b > a => Some((b - a) * 1000.0),
      _ => None,
    },
  });
  let packets: Vec<PacketOut> = if o.packets {
    c.packets
      .iter()
      .take(o.limit)
      .map(|p| PacketOut {
        p,
        flag_names: flags_text(p.flags),
        note_names: notes_text(p.notes),
      })
      .collect()
  } else {
    vec![]
  };
  let stream: Vec<StreamOut> = if o.stream {
    c.chunks
      .iter()
      .take(o.limit)
      .map(|ch| {
        let (encoding, data) = encode(&ch.data, &o.encoding);
        StreamOut {
          dir: ch.dir,
          ts: ch.ts,
          first_no: ch.first_no,
          last_no: ch.last_no,
          gap: ch.gap,
          len: ch.data.len(),
          encoding,
          data,
        }
      })
      .collect()
  } else {
    vec![]
  };
  let messages = o.messages.then(|| proto::messages(c));

  if o.json {
    let mut v = serde_json::json!({ "connection": s, "timing": timing, "findings": f });
    if o.packets {
      v["packets"] = serde_json::to_value(&packets).unwrap();
    }
    if o.stream {
      v["stream"] = serde_json::to_value(&stream).unwrap();
    }
    if let Some(m) = &messages {
      v["messages"] = serde_json::to_value(m).unwrap();
    }
    print_json(&v);
    return Ok(());
  }

  out!("#{}  {} → {}  {}  {}", s.id, s.client, s.server, s.proto, s.state);
  if let Some(l) = &s.label {
    out!("label: {l}");
  }
  out!("packets {}  bytes ↑{} ↓{}  {}", s.packets, s.bytes_c2s, s.bytes_s2c, timing);
  for x in &f {
    out!("[{}] {}: {}", x.level, x.code, x.message);
  }
  if o.packets {
    out!();
    out!(
      "{:>6} {:>12} {:>4} {:<16} {:>10} {:>10} {:>6} {:>8}  notes",
      "no",
      "+ms",
      "dir",
      "flags",
      "seq",
      "ack",
      "len",
      "win"
    );
    for p in &packets {
      let p0 = p.p;
      out!(
        "{:>6} {:>12.3} {:>4} {:<16} {:>10} {:>10} {:>6} {:>8}  {} {}",
        p0.no,
        (p0.ts - s.first_ts) * 1000.0,
        if p0.dir == Dir::C2s { "→" } else { "←" },
        p.flag_names,
        p0.rel_seq,
        p0.rel_ack,
        p0.len,
        p0.win,
        p.note_names.join(","),
        p0.opts.as_deref().unwrap_or("")
      );
    }
  }
  if o.stream {
    for ch in &stream {
      out!();
      out!(
        "{} {} bytes  frames #{}-#{}{}  ({})",
        if ch.dir == Dir::C2s { "→ client" } else { "← server" },
        ch.len,
        ch.first_no,
        ch.last_no,
        if ch.gap { "  [gap before]" } else { "" },
        ch.encoding
      );
      out!("{}", ch.data);
    }
  }
  if let Some(m) = &messages {
    for msg in &m.messages {
      out!();
      out!(
        "{} +{:.3}ms {} {}  ({} bytes){}",
        if msg.dir == Dir::C2s { "→" } else { "←" },
        (msg.ts - s.first_ts) * 1000.0,
        msg.kind,
        msg.title,
        msg.size,
        msg.note.as_ref().map(|n| format!("  [{n}]")).unwrap_or_default()
      );
      if !matches!(msg.kind.as_str(), "text") {
        out!("{}", msg.body);
      }
    }
  }
  Ok(())
}

pub const AGENT_GUIDE: &str = r#"# tcp-trace for AI agents

tcp-trace groups captured packets into TCP connections and explains them.
Use the commands below; all of them are non-interactive. Add --json for
machine-readable output. Connection ids are stable for a given capture file.

## Typical workflow

1. Get a capture (pick one):
   - existing file:     any .pcap / .pcapng
   - record one:        tcp-trace record -i lo0 -f "tcp port 5173" --seconds 10 -w /tmp/t.pcapng
                        (needs Wireshark's dumpcap with ChmodBPF on macOS, or root for tcpdump;
                         `tcp-trace interfaces` lists interface names)
2. List connections:    tcp-trace summary /tmp/t.pcapng --json [--issues] [--port 5173] [--grep host]
3. Inspect one:         tcp-trace show /tmp/t.pcapng <id> --json --messages
                        add --packets for TCP-level detail, --stream for raw bytes
                        (--encoding text|hex|base64, --limit N caps packets/chunks, default 200)
4. Hand the human a UI: tcp-trace open /tmp/t.pcapng   (web UI on http://127.0.0.1:9330;
                        long-running, do not wait for it to exit)

## Reading the output

- connection.state: syn-sent | syn-received | established | closing | closed | reset
- connection.proto: HTTP/1.1, WebSocket, TLS (· h2 / · http/1.1 from ALPN), HTTP/2 (h2c),
  SSH, Redis, or a port-based guess ending in "?" / plain "TCP"
- connection.label: first HTTP request line, TLS SNI host, or first Redis command
- direction: "c2s" = client→server, "s2c" = server→client; the client is whoever sent SYN
- findings[].code (stable): connection_refused, no_syn_ack, reset_by_client,
  reset_by_server, retransmissions, data_gaps, dup_acks, zero_window,
  slow_first_byte, partial, truncated
- packets[].note_names: retransmission, previous_segment_lost, out_of_order,
  dup_ack, zero_window, keepalive
- timing: handshake_ms (SYN→SYN/ACK ≈ network RTT), first_byte_ms (client's first
  data → server's first data ≈ server think time), duration_ms
- messages.kind: "http" (request/response pairs with headers and bodies) or
  "websocket" (frames, permessage-deflate already inflated); null for other protocols,
  in which case read --stream instead

## Limits

- TLS payloads are encrypted; only handshake metadata is visible.
- HTTP/2 frames are not decoded.
- At most 16 MB of payload is kept per connection.
- Exit code 1 with a message on stderr means the file could not be read or the id
  does not exist.
"#;
