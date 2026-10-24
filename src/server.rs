//! Local HTTP API and the embedded web UI.

use crate::tracker::{Chunk, ConnSummary, Packet};
use crate::State;
use axum::extract::{Path, Query, State as AxState};
use axum::http::{header, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use base64::Engine;
use rust_embed::Embed;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, RwLock};

type Shared = Arc<RwLock<State>>;

#[derive(Embed)]
#[folder = "web/dist"]
struct Assets;

pub async fn serve(state: Shared, port: u16, open_browser: bool) {
  let app = Router::new()
    .route("/api/summary", get(summary))
    .route("/api/conns", get(conns))
    .route("/api/conns/{id}", get(conn_detail))
    .route("/api/conns/{id}/stream", get(conn_stream))
    .route("/api/conns/{id}/messages", get(conn_messages))
    .fallback(static_file)
    .with_state(state);

  let listener = match tokio::net::TcpListener::bind(("127.0.0.1", port)).await {
    Ok(l) => l,
    Err(_) => tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.expect("bind a local port"),
  };
  let url = format!("http://{}", listener.local_addr().unwrap());
  eprintln!("tcp-trace: web UI at {url}  (Ctrl+C to quit)");
  if open_browser {
    let _ = open::that_detached(&url);
  }
  axum::serve(listener, app).await.unwrap();
}

#[derive(Serialize)]
struct Summary {
  source: String,
  live: bool,
  done: bool,
  error: Option<String>,
  version: u64,
  frames: u64,
  tcp_frames: u64,
  decode_errors: u64,
  conns: usize,
  first_ts: Option<f64>,
  last_ts: Option<f64>,
}

async fn summary(AxState(state): AxState<Shared>) -> Json<Summary> {
  let st = state.read().unwrap();
  let t = &st.tracker;
  Json(Summary {
    source: st.source.clone(),
    live: st.live,
    done: st.done,
    error: st.error.clone(),
    version: st.version,
    frames: t.frames,
    tcp_frames: t.tcp_frames,
    decode_errors: t.decode_errors,
    conns: t.conns.len(),
    first_ts: t.first_ts,
    last_ts: t.last_ts,
  })
}

async fn conns(AxState(state): AxState<Shared>) -> Json<Vec<ConnSummary>> {
  let st = state.read().unwrap();
  Json(st.tracker.conns.iter().map(|c| c.summary()).collect())
}

#[derive(Serialize)]
struct Side {
  mss: Option<u16>,
  wscale: Option<u8>,
  sack_perm: bool,
  packets: u32,
}

#[derive(Serialize)]
struct Detail {
  summary: ConnSummary,
  client_side: Side,
  server_side: Side,
  syn_ts: Option<f64>,
  synack_ts: Option<f64>,
  hs_ack_ts: Option<f64>,
  first_data_c2s: Option<f64>,
  first_data_s2c: Option<f64>,
  packets: Vec<Packet>,
  packets_total: usize,
}

#[derive(Deserialize)]
struct Paging {
  offset: Option<usize>,
  limit: Option<usize>,
}

fn not_found() -> Response {
  (StatusCode::NOT_FOUND, "no such connection").into_response()
}

async fn conn_detail(AxState(state): AxState<Shared>, Path(id): Path<usize>, Query(p): Query<Paging>) -> Response {
  let st = state.read().unwrap();
  let Some(c) = st.tracker.conns.get(id) else { return not_found() };
  let offset = p.offset.unwrap_or(0).min(c.packets.len());
  let limit = p.limit.unwrap_or(20_000);
  let side = |s: &crate::tracker::Side| Side {
    mss: s.mss,
    wscale: s.wscale,
    sack_perm: s.sack_perm,
    packets: s.packets,
  };
  let first = |d| c.packets.iter().find(|p| p.dir == d && p.len > 0).map(|p| p.ts);
  Json(Detail {
    summary: c.summary(),
    client_side: side(&c.c),
    server_side: side(&c.s),
    syn_ts: c.syn_ts,
    synack_ts: c.synack_ts,
    hs_ack_ts: c.hs_ack_ts,
    first_data_c2s: first(crate::tracker::Dir::C2s),
    first_data_s2c: first(crate::tracker::Dir::S2c),
    packets: c.packets[offset..(offset + limit).min(c.packets.len())].to_vec(),
    packets_total: c.packets.len(),
  })
  .into_response()
}

#[derive(Serialize)]
struct StreamChunk {
  #[serde(flatten)]
  chunk: Chunk,
  len: usize,
  data: String,
}

#[derive(Serialize)]
struct Stream {
  chunks: Vec<StreamChunk>,
  total_bytes: usize,
  clipped: bool,
}

const STREAM_LIMIT: usize = 4 * 1024 * 1024;

async fn conn_stream(AxState(state): AxState<Shared>, Path(id): Path<usize>) -> Response {
  let st = state.read().unwrap();
  let Some(c) = st.tracker.conns.get(id) else { return not_found() };
  let mut sent = 0;
  let mut out = Vec::new();
  let total: usize = c.chunks.iter().map(|c| c.data.len()).sum();
  for ch in &c.chunks {
    if sent >= STREAM_LIMIT {
      break;
    }
    let take = ch.data.len().min(STREAM_LIMIT - sent);
    sent += take;
    out.push(StreamChunk {
      chunk: ch.clone(),
      len: ch.data.len(),
      data: base64::engine::general_purpose::STANDARD.encode(&ch.data[..take]),
    });
  }
  Json(Stream {
    chunks: out,
    total_bytes: total,
    clipped: sent < total,
  })
  .into_response()
}

async fn conn_messages(AxState(state): AxState<Shared>, Path(id): Path<usize>) -> Response {
  let st = state.read().unwrap();
  let Some(c) = st.tracker.conns.get(id) else { return not_found() };
  Json(crate::proto::messages(c)).into_response()
}

async fn static_file(uri: Uri) -> Response {
  let path = uri.path().trim_start_matches('/');
  let path = if path.is_empty() { "index.html" } else { path };
  match Assets::get(path).or_else(|| Assets::get("index.html")) {
    Some(file) => {
      let mime = mime_guess::from_path(if Assets::get(path).is_some() { path } else { "index.html" }).first_or_octet_stream();
      ([(header::CONTENT_TYPE, mime.as_ref().to_string())], file.data).into_response()
    }
    None => (StatusCode::NOT_FOUND, "web UI not built: run `npm run build` in web/").into_response(),
  }
}
