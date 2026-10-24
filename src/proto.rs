//! Light application-layer recognition: enough to label a connection and to
//! split HTTP/1.x and WebSocket traffic into messages. Everything else is
//! shown as a raw byte stream.

use crate::tracker::{Conn, Dir};
use base64::Engine;
use serde::Serialize;

pub struct Info {
  pub proto: String,
  pub label: Option<String>,
}

fn first_bytes(conn: &Conn, dir: Dir) -> &[u8] {
  conn.chunks.iter().find(|c| c.dir == dir).map(|c| c.data.as_slice()).unwrap_or(&[])
}

const HTTP_METHODS: [&str; 9] = [
  "GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE ",
];

fn is_http_request(b: &[u8]) -> bool {
  HTTP_METHODS.iter().any(|m| b.starts_with(m.as_bytes()))
}

fn header_value<'a>(head: &'a str, name: &str) -> Option<&'a str> {
  head.lines().skip(1).find_map(|l| {
    let (k, v) = l.split_once(':')?;
    k.trim().eq_ignore_ascii_case(name).then(|| v.trim())
  })
}

pub fn identify(conn: &Conn) -> Info {
  let c = first_bytes(conn, Dir::C2s);
  let s = first_bytes(conn, Dir::S2c);

  if is_http_request(c) {
    let head = String::from_utf8_lossy(&c[..c.len().min(4096)]);
    let line = head.lines().next().unwrap_or("");
    let mut parts = line.split(' ');
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("");
    let host = header_value(&head, "host").unwrap_or("");
    let upgrade = header_value(&head, "upgrade")
      .map(|v| v.eq_ignore_ascii_case("websocket"))
      .unwrap_or(false);
    let switched = s.starts_with(b"HTTP/1.1 101") || s.starts_with(b"HTTP/1.0 101");
    let proto = if upgrade && (switched || s.is_empty()) {
      "WebSocket"
    } else {
      "HTTP/1.1"
    };
    return Info {
      proto: proto.into(),
      label: Some(format!("{method} {host}{path}")),
    };
  }
  if c.starts_with(b"PRI * HTTP/2.0") {
    return Info {
      proto: "HTTP/2 (h2c)".into(),
      label: None,
    };
  }
  if c.len() > 5 && c[0] == 0x16 && c[1] == 0x03 {
    let (sni, alpn) = parse_client_hello(c);
    let proto = match alpn.as_deref() {
      Some("h2") => "TLS · h2",
      Some("http/1.1") => "TLS · http/1.1",
      _ => "TLS",
    };
    return Info {
      proto: proto.into(),
      label: sni,
    };
  }
  if c.starts_with(b"SSH-") || s.starts_with(b"SSH-") {
    return Info {
      proto: "SSH".into(),
      label: None,
    };
  }
  if c.first() == Some(&b'*') && c.windows(3).any(|w| w == b"\r\n$") {
    let words = String::from_utf8_lossy(&c[..c.len().min(256)])
      .split("\r\n")
      .filter(|l| !l.starts_with('*') && !l.starts_with('$') && !l.is_empty())
      .take(2)
      .collect::<Vec<_>>()
      .join(" ");
    return Info {
      proto: "Redis".into(),
      label: Some(words),
    };
  }
  let by_port = match conn.server.port() {
    80 | 8080 | 3000 | 5173 | 8000 => "HTTP?",
    443 | 8443 => "TLS?",
    53 => "DNS",
    3306 => "MySQL",
    5432 => "PostgreSQL",
    6379 => "Redis",
    27017 => "MongoDB",
    9092 => "Kafka",
    _ => "TCP",
  };
  Info {
    proto: by_port.into(),
    label: None,
  }
}

/// Pulls the SNI host name and the first ALPN protocol out of a TLS ClientHello.
fn parse_client_hello(b: &[u8]) -> (Option<String>, Option<String>) {
  let get = |i: usize| b.get(i).copied().map(|v| v as usize);
  let be16 = |i: usize| Some((get(i)? << 8) | get(i + 1)?);
  let mut sni = None;
  let mut alpn = None;
  let mut parse = || -> Option<()> {
    // record header (5) + handshake header (4) + version (2) + random (32)
    if get(5)? != 1 {
      return None;
    }
    let mut i = 5 + 4 + 2 + 32;
    i += 1 + get(i)?; // session id
    i += 2 + be16(i)?; // cipher suites
    i += 1 + get(i)?; // compression methods
    let ext_end = i + 2 + be16(i)?;
    i += 2;
    while i + 4 <= ext_end.min(b.len()) {
      let typ = be16(i)?;
      let len = be16(i + 2)?;
      let body = i + 4;
      match typ {
        0 => {
          // server_name list: len(2) type(1) name_len(2) name
          let n = be16(body + 3)?;
          let name = b.get(body + 5..body + 5 + n)?;
          sni = Some(String::from_utf8_lossy(name).into_owned());
        }
        16 => {
          let n = get(body + 2)?;
          let name = b.get(body + 3..body + 3 + n)?;
          alpn = Some(String::from_utf8_lossy(name).into_owned());
        }
        _ => {}
      }
      i = body + len;
    }
    Some(())
  };
  let _ = parse();
  (sni, alpn)
}

#[derive(Serialize)]
pub struct Message {
  pub dir: Dir,
  pub ts: f64,
  /// "request", "response", "text", "binary", "ping", "pong", "close", "handshake"
  pub kind: String,
  pub title: String,
  pub size: usize,
  /// Message body: UTF-8 text when printable, otherwise base64.
  pub body: String,
  pub body_b64: bool,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub note: Option<String>,
}

#[derive(Serialize)]
pub struct Messages {
  pub kind: Option<&'static str>,
  pub messages: Vec<Message>,
}

const BODY_PREVIEW: usize = 64 * 1024;

fn body_of(data: &[u8]) -> (String, bool) {
  let data = &data[..data.len().min(BODY_PREVIEW)];
  match std::str::from_utf8(data) {
    Ok(s) => (s.to_string(), false),
    Err(_) => (base64::engine::general_purpose::STANDARD.encode(data), true),
  }
}

fn ts_at(marks: &[(usize, f64)], offset: usize) -> f64 {
  marks
    .iter()
    .find(|(end, _)| *end >= offset)
    .or(marks.last())
    .map(|m| m.1)
    .unwrap_or(0.0)
}

fn find_head_end(b: &[u8]) -> Option<usize> {
  b.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

pub fn messages(conn: &Conn) -> Messages {
  let c = first_bytes(conn, Dir::C2s);
  if !is_http_request(c) {
    return Messages {
      kind: None,
      messages: vec![],
    };
  }
  let info = identify(conn);
  let mut out = Vec::new();
  if info.proto == "WebSocket" {
    websocket(conn, &mut out);
    out.sort_by(|a, b| a.ts.total_cmp(&b.ts));
    return Messages {
      kind: Some("websocket"),
      messages: out,
    };
  }
  for dir in [Dir::C2s, Dir::S2c] {
    let (bytes, marks) = conn.direction_bytes(dir);
    http_messages(&bytes, &marks, dir, &mut out);
  }
  out.sort_by(|a, b| a.ts.total_cmp(&b.ts));
  Messages {
    kind: Some("http"),
    messages: out,
  }
}

fn http_messages(b: &[u8], marks: &[(usize, f64)], dir: Dir, out: &mut Vec<Message>) {
  let mut i = 0;
  while i < b.len() {
    let Some(he) = find_head_end(&b[i..]) else { break };
    let head = String::from_utf8_lossy(&b[i..i + he]).into_owned();
    let first = head.lines().next().unwrap_or("").to_string();
    let mut body_start = i + he;
    let mut body = Vec::new();
    let mut note = None;
    let status_no_body = first.starts_with("HTTP/")
      && (first.contains(" 204 ") || first.contains(" 304 ") || first.split(' ').nth(1).map(|c| c.starts_with('1')).unwrap_or(false));
    if let Some(len) = header_value(&head, "content-length").and_then(|v| v.parse::<usize>().ok()) {
      let end = (body_start + len).min(b.len());
      body.extend_from_slice(&b[body_start..end]);
      if end < body_start + len {
        note = Some(format!("正文不完整：已捕获 {} / {} 字节", end - body_start, len));
      }
      body_start = end;
    } else if header_value(&head, "transfer-encoding")
      .map(|v| v.contains("chunked"))
      .unwrap_or(false)
    {
      let mut j = body_start;
      loop {
        let Some(le) = b[j..].windows(2).position(|w| w == b"\r\n") else {
          note = Some("chunked 正文不完整".into());
          j = b.len();
          break;
        };
        let size_line = String::from_utf8_lossy(&b[j..j + le]);
        let size = usize::from_str_radix(size_line.split(';').next().unwrap_or("").trim(), 16).unwrap_or(0);
        j += le + 2;
        if size == 0 {
          // trailers end with an empty line
          j = find_head_end(&b[j - 2..]).map(|e| j - 2 + e).unwrap_or(b.len());
          break;
        }
        let end = (j + size).min(b.len());
        body.extend_from_slice(&b[j..end]);
        j = (end + 2).min(b.len());
        if end < j - 2 {
          break;
        }
      }
      body_start = j;
    } else if first.starts_with("HTTP/")
      && !status_no_body
      && header_value(&head, "connection")
        .map(|v| v.eq_ignore_ascii_case("close"))
        .unwrap_or(false)
    {
      body.extend_from_slice(&b[body_start..]);
      body_start = b.len();
    }
    if let Some(enc) = header_value(&head, "content-encoding") {
      if !body.is_empty() && note.is_none() {
        note = Some(format!("正文经过 {enc} 压缩，未解码"));
      }
    }
    let (text, b64) = body_of(&body);
    out.push(Message {
      dir,
      ts: ts_at(marks, i + 1),
      kind: if first.starts_with("HTTP/") {
        "response".into()
      } else {
        "request".into()
      },
      title: first,
      size: body.len(),
      body: format!("{}{}", head, text),
      body_b64: b64,
      note,
    });
    if body_start <= i {
      break;
    }
    i = body_start;
  }
}

struct Inflater {
  inner: flate2::Decompress,
  reset_each: bool,
}

impl Inflater {
  fn inflate(&mut self, data: &[u8]) -> Option<Vec<u8>> {
    if self.reset_each {
      self.inner = flate2::Decompress::new(false);
    }
    let mut input = data.to_vec();
    input.extend_from_slice(&[0, 0, 0xff, 0xff]);
    let mut out = Vec::new();
    let mut pos = 0;
    loop {
      out.reserve(64 * 1024);
      let in_before = self.inner.total_in();
      let out_before = self.inner.total_out();
      self
        .inner
        .decompress_vec(&input[pos..], &mut out, flate2::FlushDecompress::Sync)
        .ok()?;
      pos += (self.inner.total_in() - in_before) as usize;
      let stalled = self.inner.total_in() == in_before && self.inner.total_out() == out_before;
      if (pos >= input.len() && out.len() < out.capacity()) || stalled {
        break;
      }
      if out.len() > 32 * 1024 * 1024 {
        return None;
      }
    }
    Some(out)
  }
}

fn websocket(conn: &Conn, out: &mut Vec<Message>) {
  let mut deflate = false;
  let mut client_no_ctx = false;
  let mut server_no_ctx = false;
  for dir in [Dir::C2s, Dir::S2c] {
    let (bytes, marks) = conn.direction_bytes(dir);
    let Some(he) = find_head_end(&bytes) else { continue };
    let head = String::from_utf8_lossy(&bytes[..he]).into_owned();
    if dir == Dir::S2c {
      if let Some(ext) = header_value(&head, "sec-websocket-extensions") {
        deflate = ext.contains("permessage-deflate");
        client_no_ctx = ext.contains("client_no_context_takeover");
        server_no_ctx = ext.contains("server_no_context_takeover");
      }
    }
    out.push(Message {
      dir,
      ts: ts_at(&marks, 1),
      kind: "handshake".into(),
      title: head.lines().next().unwrap_or("").to_string(),
      size: 0,
      body: head,
      body_b64: false,
      note: None,
    });
  }
  for dir in [Dir::C2s, Dir::S2c] {
    let (bytes, marks) = conn.direction_bytes(dir);
    let Some(he) = find_head_end(&bytes) else { continue };
    let mut inflater = Inflater {
      inner: flate2::Decompress::new(false),
      reset_each: if dir == Dir::C2s { client_no_ctx } else { server_no_ctx },
    };
    let mut i = he;
    let mut pending: Option<(u8, bool, Vec<u8>, usize)> = None;
    while i + 2 <= bytes.len() {
      let b0 = bytes[i];
      let b1 = bytes[i + 1];
      let fin = b0 & 0x80 != 0;
      let rsv1 = b0 & 0x40 != 0;
      let opcode = b0 & 0x0f;
      let masked = b1 & 0x80 != 0;
      let mut len = (b1 & 0x7f) as usize;
      let mut j = i + 2;
      if len == 126 {
        let Some(s) = bytes.get(j..j + 2) else { break };
        len = u16::from_be_bytes([s[0], s[1]]) as usize;
        j += 2;
      } else if len == 127 {
        let Some(s) = bytes.get(j..j + 8) else { break };
        len = u64::from_be_bytes(s.try_into().unwrap()) as usize;
        j += 8;
      }
      let mask = if masked {
        let Some(m) = bytes.get(j..j + 4) else { break };
        j += 4;
        Some([m[0], m[1], m[2], m[3]])
      } else {
        None
      };
      let end = j.saturating_add(len);
      let complete = end <= bytes.len();
      let mut payload = bytes[j..end.min(bytes.len())].to_vec();
      if let Some(m) = mask {
        for (k, v) in payload.iter_mut().enumerate() {
          *v ^= m[k % 4];
        }
      }
      let frame_ts = ts_at(&marks, end.min(bytes.len()));
      if opcode >= 8 {
        let (kind, title, body) = match opcode {
          8 => {
            let code = if payload.len() >= 2 {
              Some(u16::from_be_bytes([payload[0], payload[1]]))
            } else {
              None
            };
            let reason = String::from_utf8_lossy(payload.get(2..).unwrap_or(&[])).into_owned();
            (
              "close",
              format!("Close {}", code.map(|c| c.to_string()).unwrap_or_default()),
              reason,
            )
          }
          9 => ("ping", "Ping".to_string(), String::from_utf8_lossy(&payload).into_owned()),
          10 => ("pong", "Pong".to_string(), String::from_utf8_lossy(&payload).into_owned()),
          _ => ("control", format!("opcode {opcode}"), String::new()),
        };
        out.push(Message {
          dir,
          ts: frame_ts,
          kind: kind.into(),
          title,
          size: payload.len(),
          body,
          body_b64: false,
          note: None,
        });
      } else {
        let (op, compressed, mut data, wire) = match pending.take() {
          Some((op, c, mut d, w)) if opcode == 0 => {
            d.extend_from_slice(&payload);
            (op, c, d, w + len)
          }
          _ => (opcode, rsv1 && deflate, payload, len),
        };
        if fin || !complete {
          let mut note = None;
          if !complete {
            note = Some(format!("帧不完整：已捕获 {} / {} 字节", bytes.len().saturating_sub(j), len));
          }
          if compressed && complete {
            match inflater.inflate(&data) {
              Some(d) => {
                note = Some(format!("permessage-deflate 已解压（线上 {wire} 字节）"));
                data = d;
              }
              None => note = Some("permessage-deflate 解压失败".into()),
            }
          }
          let (body, b64) = if op == 2 {
            (
              base64::engine::general_purpose::STANDARD.encode(&data[..data.len().min(BODY_PREVIEW)]),
              true,
            )
          } else {
            body_of(&data)
          };
          let kind = if op == 2 { "binary" } else { "text" };
          let title = if op == 2 {
            format!("Binary · {} B", data.len())
          } else {
            let line: String = String::from_utf8_lossy(&data[..data.len().min(160)])
              .chars()
              .filter(|c| !c.is_control())
              .collect();
            line
          };
          out.push(Message {
            dir,
            ts: frame_ts,
            kind: kind.into(),
            title,
            size: data.len(),
            body,
            body_b64: b64,
            note,
          });
        } else {
          pending = Some((op, compressed, data, wire));
        }
      }
      if !complete {
        break;
      }
      i = end;
    }
  }
}
