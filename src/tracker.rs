//! Groups TCP segments into connections, tracks sequence numbers, flags
//! problems (retransmissions, gaps, dup ACKs, zero windows) and keeps the
//! reassembled byte stream of each direction.

use crate::decode::*;
use serde::Serialize;
use std::collections::HashMap;
use std::net::SocketAddr;

/// Payload bytes kept per connection; later data is counted but dropped.
pub const MAX_STREAM_BYTES: usize = 16 * 1024 * 1024;

pub const NOTE_RETRANS: u16 = 0x01;
pub const NOTE_OUT_OF_ORDER: u16 = 0x02;
pub const NOTE_PREV_LOST: u16 = 0x04;
pub const NOTE_DUP_ACK: u16 = 0x08;
pub const NOTE_ZERO_WINDOW: u16 = 0x10;
pub const NOTE_KEEPALIVE: u16 = 0x20;

/// Direction relative to the connection: client → server or server → client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Dir {
  C2s,
  S2c,
}

#[derive(Debug, Clone, Serialize)]
pub struct Packet {
  /// Frame number in the capture, starting at 1.
  pub no: u64,
  pub ts: f64,
  pub dir: Dir,
  pub flags: u8,
  pub seq: u32,
  pub ack: u32,
  /// Sequence numbers relative to each side's initial sequence number.
  pub rel_seq: u32,
  pub rel_ack: u32,
  pub len: u32,
  pub win: u32,
  pub notes: u16,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub opts: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Chunk {
  pub dir: Dir,
  pub ts: f64,
  pub ts_end: f64,
  pub first_no: u64,
  pub last_no: u64,
  /// Bytes before this chunk were never captured.
  pub gap: bool,
  /// Sequence number of the first byte.
  #[serde(skip)]
  pub seq: u32,
  #[serde(skip)]
  pub data: Vec<u8>,
}

#[derive(Debug, Default)]
pub struct Side {
  pub base: Option<u32>,
  pub next_seq: Option<u32>,
  pub last_ack: Option<u32>,
  pub last_win: u32,
  pub wscale: Option<u8>,
  pub mss: Option<u16>,
  pub sack_perm: bool,
  pub fin: bool,
  pub packets: u32,
  pub bytes: u64,
  pub stored: usize,
  /// Sequence ranges skipped over and not yet seen.
  pub gaps: Vec<(u32, u32)>,
}

pub struct Conn {
  pub id: u32,
  pub client: SocketAddr,
  pub server: SocketAddr,
  pub first_ts: f64,
  pub last_ts: f64,
  /// The capture began after the three-way handshake.
  pub partial: bool,
  pub syn_ts: Option<f64>,
  pub synack_ts: Option<f64>,
  pub hs_ack_ts: Option<f64>,
  pub rst: bool,
  pub rst_from: Option<Dir>,
  pub c: Side,
  pub s: Side,
  pub packets: Vec<Packet>,
  pub chunks: Vec<Chunk>,
  pub retrans: u32,
  pub lost: u32,
  pub out_of_order: u32,
  pub dup_acks: u32,
  pub zero_windows: u32,
  pub truncated: bool,
}

#[derive(Serialize)]
pub struct ConnSummary {
  pub id: u32,
  pub client: String,
  pub server: String,
  pub server_port: u16,
  pub state: &'static str,
  pub partial: bool,
  pub first_ts: f64,
  pub last_ts: f64,
  pub packets: usize,
  pub bytes_c2s: u64,
  pub bytes_s2c: u64,
  pub handshake_ms: Option<f64>,
  pub retrans: u32,
  pub lost: u32,
  pub out_of_order: u32,
  pub dup_acks: u32,
  pub zero_windows: u32,
  pub rst_from: Option<Dir>,
  pub proto: String,
  pub label: Option<String>,
  pub truncated: bool,
}

impl Conn {
  fn side_mut(&mut self, dir: Dir) -> (&mut Side, &mut Side) {
    match dir {
      Dir::C2s => (&mut self.c, &mut self.s),
      Dir::S2c => (&mut self.s, &mut self.c),
    }
  }

  pub fn state(&self) -> &'static str {
    if self.rst {
      "reset"
    } else if self.c.fin && self.s.fin {
      "closed"
    } else if self.c.fin || self.s.fin {
      "closing"
    } else if self.syn_ts.is_some() && self.synack_ts.is_none() {
      "syn-sent"
    } else if self.synack_ts.is_some() && self.hs_ack_ts.is_none() && self.c.bytes == 0 {
      "syn-received"
    } else {
      "established"
    }
  }

  pub fn is_finished(&self) -> bool {
    self.rst || (self.c.fin && self.s.fin)
  }

  pub fn summary(&self) -> ConnSummary {
    let info = crate::proto::identify(self);
    ConnSummary {
      id: self.id,
      client: self.client.to_string(),
      server: self.server.to_string(),
      server_port: self.server.port(),
      state: self.state(),
      partial: self.partial,
      first_ts: self.first_ts,
      last_ts: self.last_ts,
      packets: self.packets.len(),
      bytes_c2s: self.c.bytes,
      bytes_s2c: self.s.bytes,
      handshake_ms: match (self.syn_ts, self.synack_ts) {
        (Some(a), Some(b)) => Some((b - a) * 1000.0),
        _ => None,
      },
      retrans: self.retrans,
      lost: self.lost,
      out_of_order: self.out_of_order,
      dup_acks: self.dup_acks,
      zero_windows: self.zero_windows,
      rst_from: self.rst_from,
      proto: info.proto,
      label: info.label,
      truncated: self.truncated,
    }
  }

  /// All stored bytes sent in one direction, with the chunk that holds each range.
  pub fn direction_bytes(&self, dir: Dir) -> (Vec<u8>, Vec<(usize, f64)>) {
    let mut out = Vec::new();
    let mut marks = Vec::new();
    for ch in self.chunks.iter().filter(|c| c.dir == dir) {
      out.extend_from_slice(&ch.data);
      marks.push((out.len(), ch.ts_end));
    }
    (out, marks)
  }
}

/// `a < b` in 32 bit sequence space.
fn seq_lt(a: u32, b: u32) -> bool {
  (a.wrapping_sub(b) as i32) < 0
}

type Key = (SocketAddr, SocketAddr);

fn key(a: SocketAddr, b: SocketAddr) -> Key {
  if a <= b {
    (a, b)
  } else {
    (b, a)
  }
}

#[derive(Default)]
pub struct Tracker {
  pub conns: Vec<Conn>,
  index: HashMap<Key, u32>,
  pub frames: u64,
  pub tcp_frames: u64,
  pub decode_errors: u64,
  pub first_ts: Option<f64>,
  pub last_ts: Option<f64>,
}

impl Tracker {
  pub fn note_frame(&mut self, ts: f64) {
    self.frames += 1;
    if self.first_ts.is_none() {
      self.first_ts = Some(ts);
    }
    self.last_ts = Some(ts);
  }

  pub fn add(&mut self, seg: &Segment) {
    self.tcp_frames += 1;
    let src = SocketAddr::new(seg.src, seg.sport);
    let dst = SocketAddr::new(seg.dst, seg.dport);
    let k = key(src, dst);
    let syn_only = seg.flags & FLAG_SYN != 0 && seg.flags & FLAG_ACK == 0;

    let existing = self.index.get(&k).copied().filter(|&id| {
      let conn = &self.conns[id as usize];
      // A fresh SYN on a finished connection means the port pair was reused.
      !(syn_only && conn.is_finished() && conn.client == src && conn.c.base != Some(seg.seq))
    });
    let id = match existing {
      Some(id) => id,
      None => {
        let id = self.conns.len() as u32;
        let (client, server) = guess_roles(seg, src, dst);
        self.conns.push(Conn {
          id,
          client,
          server,
          first_ts: seg.ts,
          last_ts: seg.ts,
          partial: !(seg.flags & FLAG_SYN != 0),
          syn_ts: None,
          synack_ts: None,
          hs_ack_ts: None,
          rst: false,
          rst_from: None,
          c: Side::default(),
          s: Side::default(),
          packets: Vec::new(),
          chunks: Vec::new(),
          retrans: 0,
          lost: 0,
          out_of_order: 0,
          dup_acks: 0,
          zero_windows: 0,
          truncated: false,
        });
        self.index.insert(k, id);
        id
      }
    };
    let no = self.frames;
    let conn = &mut self.conns[id as usize];
    track(conn, seg, src, no);
  }
}

fn is_ephemeral_guess(port: u16) -> bool {
  port >= 32768
}

fn guess_roles(seg: &Segment, src: SocketAddr, dst: SocketAddr) -> (SocketAddr, SocketAddr) {
  let syn = seg.flags & FLAG_SYN != 0;
  let ack = seg.flags & FLAG_ACK != 0;
  if syn && !ack {
    return (src, dst);
  }
  if syn && ack {
    return (dst, src);
  }
  // Mid-stream: the side with the lower, non-ephemeral port is probably the server.
  let src_server = !is_ephemeral_guess(seg.sport) && (is_ephemeral_guess(seg.dport) || seg.sport < seg.dport);
  if src_server {
    (dst, src)
  } else {
    (src, dst)
  }
}

fn track(conn: &mut Conn, seg: &Segment, src: SocketAddr, no: u64) {
  let dir = if src == conn.client { Dir::C2s } else { Dir::S2c };
  let syn = seg.flags & FLAG_SYN != 0;
  let fin = seg.flags & FLAG_FIN != 0;
  let rst = seg.flags & FLAG_RST != 0;
  let ack = seg.flags & FLAG_ACK != 0;
  conn.last_ts = seg.ts;

  // Handshake timing
  if syn && !ack && conn.syn_ts.is_none() {
    conn.syn_ts = Some(seg.ts);
  }
  if syn && ack && conn.synack_ts.is_none() {
    conn.synack_ts = Some(seg.ts);
  }
  if !syn && ack && dir == Dir::C2s && conn.synack_ts.is_some() && conn.hs_ack_ts.is_none() {
    conn.hs_ack_ts = Some(seg.ts);
  }
  if rst {
    conn.rst = true;
    conn.rst_from.get_or_insert(dir);
  }

  let payload_len = seg.payload.len() as u32;
  let seg_len = payload_len + syn as u32 + fin as u32;
  let mut notes: u16 = 0;

  let (me, peer) = conn.side_mut(dir);
  me.packets += 1;
  if syn {
    me.base = Some(seg.seq);
    me.mss = seg.options.mss;
    me.wscale = seg.options.wscale;
    me.sack_perm = seg.options.sack_perm;
  }
  if me.base.is_none() {
    me.base = Some(seg.seq.wrapping_sub(1));
  }
  if fin {
    me.fin = true;
  }
  // Window scaling only applies when both sides offered it in the handshake.
  let scale = match (me.wscale, peer.wscale) {
    (Some(a), Some(_)) if !syn => a,
    _ => 0,
  };
  let win = (seg.window as u32) << scale;

  // Sequence analysis
  let mut store = false;
  let mut gap = false;
  let mut skip = 0usize;
  match me.next_seq {
    None => {
      me.next_seq = Some(seg.seq.wrapping_add(seg_len));
      store = payload_len > 0;
    }
    Some(next) => {
      if seg_len > 0 {
        let end = seg.seq.wrapping_add(seg_len);
        if seg.seq == next {
          me.next_seq = Some(end);
          store = true;
        } else if seq_lt(seg.seq, next) {
          if payload_len == 1 && seg.seq == next.wrapping_sub(1) && !syn && !fin {
            notes |= NOTE_KEEPALIVE;
          } else if let Some(gi) = me.gaps.iter().position(|&(a, b)| seq_lt(seg.seq, b) && seq_lt(a, end)) {
            // Fills a hole left by an earlier segment that arrived late.
            notes |= NOTE_OUT_OF_ORDER;
            let (a, b) = me.gaps[gi];
            if !seq_lt(seg.seq, a) && !seq_lt(b, end) {
              me.gaps.remove(gi);
            } else {
              me.gaps[gi] = if seq_lt(seg.seq, a) || seg.seq == a {
                (end, b)
              } else {
                (a, seg.seq)
              };
            }
            store = true;
            gap = true;
          } else if seq_lt(next, end) {
            // Overlaps old data but carries some new bytes.
            notes |= NOTE_RETRANS;
            skip = next.wrapping_sub(seg.seq) as usize;
            me.next_seq = Some(end);
            store = true;
          } else {
            notes |= NOTE_RETRANS;
          }
        } else {
          notes |= NOTE_PREV_LOST;
          gap = true;
          if me.gaps.len() < 64 {
            me.gaps.push((next, seg.seq));
          }
          me.next_seq = Some(end);
          store = true;
        }
      } else if !syn && !rst && ack && me.last_ack == Some(seg.ack) && me.last_win == win && peer.next_seq.is_some() {
        // A bare ACK repeating the previous one while data is in flight.
        if peer.next_seq != Some(seg.ack) {
          notes |= NOTE_DUP_ACK;
        }
      }
    }
  }
  if win == 0 && !syn && !rst {
    notes |= NOTE_ZERO_WINDOW;
  }
  if ack {
    me.last_ack = Some(seg.ack);
  }
  me.last_win = win;
  me.bytes += payload_len as u64;

  let rel_seq = seg.seq.wrapping_sub(me.base.unwrap_or(seg.seq));
  let rel_ack = match (ack, peer.base) {
    (true, Some(b)) => seg.ack.wrapping_sub(b),
    _ => 0,
  };

  if store && payload_len > 0 && skip < seg.payload.len() {
    let data = &seg.payload[skip..];
    let room = MAX_STREAM_BYTES.saturating_sub(me.stored);
    let take = data.len().min(room);
    if take < data.len() {
      conn.truncated = true;
    }
    if take > 0 {
      let (me, _) = conn.side_mut(dir);
      me.stored += take;
      let data = &data[..take];
      let seq = seg.seq.wrapping_add(skip as u32);
      let chunk = Chunk {
        dir,
        ts: seg.ts,
        ts_end: seg.ts,
        first_no: no,
        last_no: no,
        gap,
        seq,
        data: data.to_vec(),
      };
      if notes & NOTE_OUT_OF_ORDER != 0 {
        // Late data goes back in front of the bytes that followed it.
        let at = conn
          .chunks
          .iter()
          .position(|c| c.dir == dir && seq_lt(seq, c.seq))
          .unwrap_or(conn.chunks.len());
        conn.chunks.insert(at, chunk);
      } else {
        match conn.chunks.last_mut() {
          Some(last) if last.dir == dir && !gap => {
            last.data.extend_from_slice(data);
            last.ts_end = seg.ts;
            last.last_no = no;
          }
          _ => conn.chunks.push(chunk),
        }
      }
    }
  }

  if notes & NOTE_RETRANS != 0 {
    conn.retrans += 1;
  }
  if notes & NOTE_PREV_LOST != 0 {
    conn.lost += 1;
  }
  if notes & NOTE_OUT_OF_ORDER != 0 {
    conn.out_of_order += 1;
  }
  if notes & NOTE_DUP_ACK != 0 {
    conn.dup_acks += 1;
  }
  if notes & NOTE_ZERO_WINDOW != 0 {
    conn.zero_windows += 1;
  }

  let opts = if syn {
    let o = &seg.options;
    let mut parts = Vec::new();
    if let Some(m) = o.mss {
      parts.push(format!("MSS={m}"));
    }
    if let Some(w) = o.wscale {
      parts.push(format!("WS={}", 1u32 << w));
    }
    if o.sack_perm {
      parts.push("SACK_PERM".into());
    }
    if o.timestamp {
      parts.push("TS".into());
    }
    Some(parts.join(" "))
  } else if seg.options.sack_blocks > 0 {
    Some(format!("SACK×{}", seg.options.sack_blocks))
  } else {
    None
  };

  conn.packets.push(Packet {
    no,
    ts: seg.ts,
    dir,
    flags: seg.flags,
    seq: seg.seq,
    ack: seg.ack,
    rel_seq,
    rel_ack,
    len: payload_len,
    win,
    notes,
    opts,
  });
}
