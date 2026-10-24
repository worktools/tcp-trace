export type Dir = 'c2s' | 's2c';

export interface Summary {
  source: string;
  live: boolean;
  done: boolean;
  error: string | null;
  version: number;
  frames: number;
  tcp_frames: number;
  decode_errors: number;
  conns: number;
  first_ts: number | null;
  last_ts: number | null;
}

export interface Conn {
  id: number;
  client: string;
  server: string;
  server_port: number;
  state: 'syn-sent' | 'syn-received' | 'established' | 'closing' | 'closed' | 'reset';
  partial: boolean;
  first_ts: number;
  last_ts: number;
  packets: number;
  bytes_c2s: number;
  bytes_s2c: number;
  handshake_ms: number | null;
  retrans: number;
  lost: number;
  out_of_order: number;
  dup_acks: number;
  zero_windows: number;
  rst_from: Dir | null;
  proto: string;
  label: string | null;
  truncated: boolean;
}

export interface Packet {
  no: number;
  ts: number;
  dir: Dir;
  flags: number;
  seq: number;
  ack: number;
  rel_seq: number;
  rel_ack: number;
  len: number;
  win: number;
  notes: number;
  opts?: string;
}

export interface SideInfo {
  mss: number | null;
  wscale: number | null;
  sack_perm: boolean;
  packets: number;
}

export interface Detail {
  summary: Conn;
  client_side: SideInfo;
  server_side: SideInfo;
  syn_ts: number | null;
  synack_ts: number | null;
  hs_ack_ts: number | null;
  first_data_c2s: number | null;
  first_data_s2c: number | null;
  packets: Packet[];
  packets_total: number;
}

export interface Chunk {
  dir: Dir;
  ts: number;
  ts_end: number;
  first_no: number;
  last_no: number;
  gap: boolean;
  len: number;
  data: string;
}

export interface Stream {
  chunks: Chunk[];
  total_bytes: number;
  clipped: boolean;
}

export interface Message {
  dir: Dir;
  ts: number;
  kind: string;
  title: string;
  size: number;
  body: string;
  body_b64: boolean;
  note?: string;
}

export interface Messages {
  kind: 'http' | 'websocket' | null;
  messages: Message[];
}

export const FLAG = { FIN: 1, SYN: 2, RST: 4, PSH: 8, ACK: 16, URG: 32, ECE: 64, CWR: 128 } as const;
export const NOTE = { RETRANS: 1, OUT_OF_ORDER: 2, PREV_LOST: 4, DUP_ACK: 8, ZERO_WINDOW: 16, KEEPALIVE: 32 } as const;

async function get<T>(path: string): Promise<T> {
  const res = await fetch(path);
  if (!res.ok) throw new Error(`${res.status} ${await res.text()}`);
  return res.json();
}

export const api = {
  summary: () => get<Summary>('/api/summary'),
  conns: () => get<Conn[]>('/api/conns'),
  detail: (id: number) => get<Detail>(`/api/conns/${id}`),
  stream: (id: number) => get<Stream>(`/api/conns/${id}/stream`),
  messages: (id: number) => get<Messages>(`/api/conns/${id}/messages`),
};

export function decodeB64(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
