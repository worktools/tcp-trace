import { useEffect, useMemo, useRef, useState } from 'preact/hooks';
import { api, Chunk, Conn, decodeB64, Detail, Dir, FLAG, Message, Messages, NOTE, Packet, Stream } from './api';
import { bytes, clock, diagnose, flagNames, ms, NOTE_TEXT, STATE_TEXT } from './format';
import { Icon } from './Icon';

type Tab = 'overview' | 'messages' | 'stream' | 'packets' | 'ladder';

function useFetch<T>(fn: () => Promise<T>, deps: unknown[]): T | null {
  const [data, setData] = useState<T | null>(null);
  const idRef = useRef<unknown>(null);
  useEffect(() => {
    let alive = true;
    // Keep showing the previous data while refreshing the same connection.
    if (idRef.current !== deps[0]) setData(null);
    idRef.current = deps[0];
    fn().then((d) => alive && setData(d), () => {});
    return () => {
      alive = false;
    };
  }, deps);
  return data;
}

export function DetailPanel({ conn, version, live, onClose }: { conn: Conn; version: number; live: boolean; onClose: () => void }) {
  const [tab, setTab] = useState<Tab>('overview');
  const refresh = live ? version : 0;
  const detail = useFetch(() => api.detail(conn.id), [conn.id, refresh]);
  const messages = useFetch(() => api.messages(conn.id), [conn.id, refresh]);
  const hasMessages = !!messages?.kind;

  const tabs: [Tab, string][] = [
    ['overview', '概览'],
    ...(hasMessages ? [['messages', messages!.kind === 'websocket' ? 'WS 消息' : 'HTTP 消息'] as [Tab, string]] : []),
    ['stream', '数据流'],
    ['packets', `数据包 ${conn.packets}`],
    ['ladder', '时序图'],
  ];
  const active = tab === 'messages' && !hasMessages ? 'overview' : tab;

  return (
    <div class="detail">
      <div class="detail-head">
        <button class="icon-btn" onClick={onClose} title="关闭 (Esc)">
          <Icon name="close" />
        </button>
        <div class="detail-title">
          <span class="mono">{conn.client}</span>
          <span class="arrow">→</span>
          <span class="mono">{conn.server}</span>
        </div>
        <span class="tag">{conn.proto}</span>
        <span class={`state s-${conn.state}`}>{STATE_TEXT[conn.state]}</span>
      </div>
      <nav class="tabs">
        {tabs.map(([t, label]) => (
          <button key={t} class={`tab ${active === t ? 'on' : ''}`} onClick={() => setTab(t)}>
            {label}
          </button>
        ))}
      </nav>
      <div class="tab-body">
        {!detail ? (
          <div class="loading">加载中…</div>
        ) : active === 'overview' ? (
          <Overview d={detail} conn={conn} />
        ) : active === 'messages' && messages ? (
          <MessagesView m={messages} t0={detail.summary.first_ts} />
        ) : active === 'stream' ? (
          <StreamView id={conn.id} refresh={refresh} />
        ) : active === 'packets' ? (
          <PacketsView d={detail} />
        ) : (
          <Ladder d={detail} />
        )}
      </div>
    </div>
  );
}

function Overview({ d, conn }: { d: Detail; conn: Conn }) {
  const s = d.summary;
  const findings = diagnose(s, d.first_data_c2s, d.first_data_s2c);
  const ttfb = d.first_data_c2s != null && d.first_data_s2c != null && d.first_data_s2c > d.first_data_c2s ? (d.first_data_s2c - d.first_data_c2s) * 1000 : null;
  const clientRtt = d.synack_ts != null && d.hs_ack_ts != null ? (d.hs_ack_ts - d.synack_ts) * 1000 : null;
  return (
    <div class="overview">
      <section class="card findings">
        <h3>诊断</h3>
        {findings.map((f, i) => (
          <div key={i} class={`finding ${f.level}`}>
            <Icon name={f.level === 'error' ? 'error' : f.level === 'warn' ? 'warning' : 'info'} />
            <span>{f.text}</span>
          </div>
        ))}
      </section>
      <section class="card">
        <h3>连接</h3>
        <dl>
          <dt>客户端</dt>
          <dd class="mono">{s.client}</dd>
          <dt>服务端</dt>
          <dd class="mono">{s.server}</dd>
          <dt>协议</dt>
          <dd>{s.proto}</dd>
          {s.label && (
            <>
              <dt>{s.proto.startsWith('TLS') ? 'SNI' : '首个请求'}</dt>
              <dd class="mono wrap">{s.label}</dd>
            </>
          )}
          <dt>状态</dt>
          <dd>
            {STATE_TEXT[s.state]}
            {s.rst_from && <span class="muted">（RST 来自{s.rst_from === 'c2s' ? '客户端' : '服务端'}）</span>}
          </dd>
        </dl>
      </section>
      <section class="card">
        <h3>时间</h3>
        <dl>
          <dt>开始</dt>
          <dd class="mono">{clock(s.first_ts)}</dd>
          <dt>持续</dt>
          <dd>{ms((s.last_ts - s.first_ts) * 1000)}</dd>
          <dt>握手 SYN→SYN/ACK</dt>
          <dd>{ms(s.handshake_ms)}</dd>
          <dt>SYN/ACK→ACK</dt>
          <dd>{ms(clientRtt)}</dd>
          <dt>请求→首字节</dt>
          <dd>{ms(ttfb)}</dd>
        </dl>
      </section>
      <section class="card">
        <h3>流量</h3>
        <table class="mini">
          <thead>
            <tr>
              <th />
              <th>客户端 → 服务端</th>
              <th>服务端 → 客户端</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>数据包</td>
              <td>{d.client_side.packets}</td>
              <td>{d.server_side.packets}</td>
            </tr>
            <tr>
              <td>负载字节</td>
              <td>{bytes(s.bytes_c2s)}</td>
              <td>{bytes(s.bytes_s2c)}</td>
            </tr>
            <tr>
              <td>MSS</td>
              <td>{d.client_side.mss ?? '—'}</td>
              <td>{d.server_side.mss ?? '—'}</td>
            </tr>
            <tr>
              <td>窗口缩放</td>
              <td>{d.client_side.wscale != null ? `×${2 ** d.client_side.wscale}` : '—'}</td>
              <td>{d.server_side.wscale != null ? `×${2 ** d.server_side.wscale}` : '—'}</td>
            </tr>
            <tr>
              <td>SACK</td>
              <td>{d.client_side.sack_perm ? '支持' : '—'}</td>
              <td>{d.server_side.sack_perm ? '支持' : '—'}</td>
            </tr>
          </tbody>
        </table>
      </section>
      <section class="card">
        <h3>问题计数</h3>
        <dl>
          <dt>重传</dt>
          <dd>{conn.retrans}</dd>
          <dt>数据缺口</dt>
          <dd>{conn.lost}</dd>
          <dt>乱序补齐</dt>
          <dd>{conn.out_of_order}</dd>
          <dt>重复 ACK</dt>
          <dd>{conn.dup_acks}</dd>
          <dt>零窗口</dt>
          <dd>{conn.zero_windows}</dd>
        </dl>
      </section>
    </div>
  );
}

function DirIcon({ dir }: { dir: Dir }) {
  return (
    <span class={`dir d-${dir}`} title={dir === 'c2s' ? '客户端 → 服务端' : '服务端 → 客户端'}>
      <Icon name={dir === 'c2s' ? 'up' : 'down'} size={14} />
    </span>
  );
}

function prettyBody(m: Message): string {
  if (m.body_b64) return hexDump(decodeB64(m.body), 0);
  const t = m.body;
  const trimmed = t.trim();
  if ((trimmed.startsWith('{') || trimmed.startsWith('[')) && m.kind !== 'request' && m.kind !== 'response') {
    try {
      return JSON.stringify(JSON.parse(trimmed), null, 2);
    } catch {}
  }
  return t;
}

function MessagesView({ m, t0 }: { m: Messages; t0: number }) {
  const [sel, setSel] = useState<number | null>(null);
  const [q, setQ] = useState('');
  const list = m.messages.map((msg, i) => ({ msg, i })).filter(({ msg }) => !q || msg.title.toLowerCase().includes(q.toLowerCase()) || (!msg.body_b64 && msg.body.toLowerCase().includes(q.toLowerCase())));
  const cur = sel != null ? m.messages[sel] : null;
  return (
    <div class="messages">
      <div class="subbar">
        <label class="filter small">
          <Icon name="filter" />
          <input value={q} onInput={(e) => setQ((e.target as HTMLInputElement).value)} placeholder="过滤消息内容" />
        </label>
        <span class="muted">{m.messages.length} 条消息</span>
      </div>
      <div class="table msg-table">
        <div class="thead">
          <div class="row">
            <div class="m-dir" />
            <div class="m-data">数据</div>
            <div class="m-len">长度</div>
            <div class="m-time">时间</div>
          </div>
        </div>
        <div class="tbody static">
          {list.map(({ msg, i }) => (
            <div key={i} class={`row m-${msg.dir} k-${msg.kind} ${sel === i ? 'selected' : ''}`} onClick={() => setSel(sel === i ? null : i)}>
              <div class="m-dir">
                <DirIcon dir={msg.dir} />
              </div>
              <div class="m-data">
                {msg.kind !== 'text' && msg.kind !== 'request' && msg.kind !== 'response' && <span class="kind">{msg.kind}</span>}
                <span class="mono ellipsis">{msg.title}</span>
              </div>
              <div class="m-len">{msg.size ? bytes(msg.size) : ''}</div>
              <div class="m-time">+{ms((msg.ts - t0) * 1000)}</div>
            </div>
          ))}
        </div>
      </div>
      {cur && (
        <div class="msg-body">
          <div class="msg-body-head">
            <DirIcon dir={cur.dir} />
            <span>{cur.dir === 'c2s' ? '客户端发出' : '服务端发出'}</span>
            <span class="muted">{clock(cur.ts)}</span>
            {cur.note && <span class="tag">{cur.note}</span>}
            <span class="spacer" />
            <button class="text-btn" onClick={() => navigator.clipboard?.writeText(cur.body_b64 ? cur.body : cur.body)}>
              <Icon name="copy" size={14} /> 复制
            </button>
          </div>
          <pre class="code">{prettyBody(cur)}</pre>
        </div>
      )}
    </div>
  );
}

function hexDump(data: Uint8Array, base: number, limit = 64 * 1024): string {
  const lines: string[] = [];
  const n = Math.min(data.length, limit);
  for (let i = 0; i < n; i += 16) {
    const row = data.subarray(i, Math.min(i + 16, n));
    const hex = Array.from(row, (b) => b.toString(16).padStart(2, '0')).join(' ');
    const ascii = Array.from(row, (b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : '·')).join('');
    lines.push(`${(base + i).toString(16).padStart(8, '0')}  ${hex.padEnd(47)}  ${ascii}`);
  }
  if (data.length > n) lines.push(`… 还有 ${bytes(data.length - n)}`);
  return lines.join('\n');
}

const utf8 = new TextDecoder('utf-8', { fatal: false });

function asText(data: Uint8Array, limit = 64 * 1024): string {
  const s = utf8.decode(data.subarray(0, limit)).replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g, '·');
  return data.length > limit ? `${s}\n… 还有 ${bytes(data.length - limit)}` : s;
}

function StreamView({ id, refresh }: { id: number; refresh: number }) {
  const stream = useFetch<Stream>(() => api.stream(id), [id, refresh]);
  const [mode, setMode] = useState<'text' | 'hex'>('text');
  const [only, setOnly] = useState<Dir | 'both'>('both');
  const chunks = useMemo(() => (stream?.chunks ?? []).map((c) => ({ ...c, bytes: decodeB64(c.data) })), [stream]);
  if (!stream) return <div class="loading">加载中…</div>;
  const offsets: Record<Dir, number> = { c2s: 0, s2c: 0 };
  return (
    <div class="stream">
      <div class="subbar">
        <div class="seg">
          <button class={mode === 'text' ? 'on' : ''} onClick={() => setMode('text')}>
            文本
          </button>
          <button class={mode === 'hex' ? 'on' : ''} onClick={() => setMode('hex')}>
            Hex
          </button>
        </div>
        <div class="seg">
          <button class={only === 'both' ? 'on' : ''} onClick={() => setOnly('both')}>
            双向
          </button>
          <button class={only === 'c2s' ? 'on' : ''} onClick={() => setOnly('c2s')}>
            ↑ 客户端
          </button>
          <button class={only === 's2c' ? 'on' : ''} onClick={() => setOnly('s2c')}>
            ↓ 服务端
          </button>
        </div>
        <span class="spacer" />
        <span class="muted">
          {chunks.length} 段 · {bytes(stream.total_bytes)}
          {stream.clipped && '（只显示前 4 MB）'}
        </span>
      </div>
      <div class="stream-body">
        {chunks.length === 0 && <div class="empty small">这条连接没有传输任何应用数据</div>}
        {chunks.map((c: Chunk & { bytes: Uint8Array }, i) => {
          const base = offsets[c.dir];
          offsets[c.dir] += c.len;
          if (only !== 'both' && only !== c.dir) return null;
          return (
            <div key={i} class={`chunk d-${c.dir}`}>
              <div class="chunk-head">
                <DirIcon dir={c.dir} />
                <span>{c.dir === 'c2s' ? '客户端' : '服务端'}</span>
                <span class="muted">{clock(c.ts)}</span>
                <span class="muted">{bytes(c.len)}</span>
                <span class="muted">
                  #{c.first_no}
                  {c.last_no !== c.first_no ? `–#${c.last_no}` : ''}
                </span>
                {c.gap && <span class="tag warn">前面有缺失或乱序</span>}
              </div>
              <pre class="code">{mode === 'hex' ? hexDump(c.bytes, base) : asText(c.bytes)}</pre>
            </div>
          );
        })}
      </div>
    </div>
  );
}

const PROW = 24;

function noteList(n: number) {
  return NOTE_TEXT.filter(([bit]) => n & bit);
}

function PacketsView({ d }: { d: Detail }) {
  const t0 = d.summary.first_ts;
  const scroller = useRef<HTMLDivElement>(null);
  const [view, setView] = useState({ top: 0, height: 600 });
  useEffect(() => {
    const el = scroller.current!;
    const ro = new ResizeObserver(() => setView({ top: el.scrollTop, height: el.clientHeight }));
    ro.observe(el);
    return () => ro.disconnect();
  }, []);
  const pk = d.packets;
  const first = Math.max(0, Math.floor(view.top / PROW) - 10);
  const last = Math.min(pk.length, Math.ceil((view.top + view.height) / PROW) + 10);
  return (
    <div class="table pkt-table">
      <div class="thead">
        <div class="row">
          <div class="p-no">No.</div>
          <div class="p-time">时间</div>
          <div class="p-dir" />
          <div class="p-flags">标志</div>
          <div class="p-num">Seq</div>
          <div class="p-num">Ack</div>
          <div class="p-num">Len</div>
          <div class="p-num">Win</div>
          <div class="p-notes">备注</div>
        </div>
      </div>
      <div class="tbody" ref={scroller} onScroll={(e) => setView({ top: (e.target as HTMLElement).scrollTop, height: (e.target as HTMLElement).clientHeight })}>
        <div style={{ height: pk.length * PROW, position: 'relative' }}>
          {pk.slice(first, last).map((p, k) => {
            const notes = noteList(p.notes);
            const cls = p.flags & FLAG.RST ? 'is-rst' : notes.length && !(p.notes & NOTE.KEEPALIVE) ? 'is-warn' : p.flags & FLAG.SYN ? 'is-syn' : p.flags & FLAG.FIN ? 'is-fin' : '';
            return (
              <div key={p.no} class={`row ${cls}`} style={{ top: (first + k) * PROW, height: PROW }}>
                <div class="p-no">{p.no}</div>
                <div class="p-time">+{ms((p.ts - t0) * 1000)}</div>
                <div class="p-dir">
                  <DirIcon dir={p.dir} />
                </div>
                <div class="p-flags">
                  {flagNames(p.flags).map((f) => (
                    <span key={f} class={`flag f-${f}`}>
                      {f}
                    </span>
                  ))}
                </div>
                <div class="p-num">{p.rel_seq}</div>
                <div class="p-num">{p.flags & FLAG.ACK ? p.rel_ack : ''}</div>
                <div class="p-num">{p.len || ''}</div>
                <div class="p-num">{p.win}</div>
                <div class="p-notes">
                  {notes.map(([bit, label, tip]) => (
                    <span key={bit} class="tag warn" title={tip}>
                      {label}
                    </span>
                  ))}
                  {p.opts && <span class="muted mono">{p.opts}</span>}
                </div>
              </div>
            );
          })}
        </div>
      </div>
      {d.packets_total > d.packets.length && <div class="muted pad">只显示前 {d.packets.length} 个包，共 {d.packets_total} 个</div>}
    </div>
  );
}

const LADDER_MAX = 400;

function packetLabel(p: Packet): string {
  // ACK rides on almost every segment, so only name it when it is the point.
  const f = flagNames(p.flags).filter((x) => x !== 'ACK' || p.flags === FLAG.ACK || p.flags & FLAG.SYN);
  const parts = [f.join(' ')];
  if (p.len) parts.push(`${p.len} B`);
  return parts.filter(Boolean).join(' · ');
}

function Ladder({ d }: { d: Detail }) {
  const pk = d.packets.slice(0, LADDER_MAX);
  const t0 = d.summary.first_ts;
  const W = 640;
  const xl = 150;
  const xr = W - 70;
  const step = 34;
  const top = 56;
  const H = top + pk.length * step + 24;
  return (
    <div class="ladder">
      <svg viewBox={`0 0 ${W} ${H}`} width="100%" style={{ maxWidth: `${W + 40}px` }}>
        <defs>
          {(['c2s', 's2c', 'rst', 'warn'] as const).map((k) => (
            <marker key={k} id={`ah-${k}`} viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
              <path d="M0 0L10 5L0 10z" class={`ah ah-${k}`} />
            </marker>
          ))}
        </defs>
        <text x={xl} y={22} text-anchor="middle" class="lad-name">
          客户端
        </text>
        <text x={xl} y={38} text-anchor="middle" class="lad-addr">
          {d.summary.client}
        </text>
        <text x={xr} y={22} text-anchor="middle" class="lad-name">
          服务端
        </text>
        <text x={xr} y={38} text-anchor="middle" class="lad-addr">
          {d.summary.server}
        </text>
        <line x1={xl} x2={xl} y1={top - 8} y2={H - 8} class="lifeline" />
        <line x1={xr} x2={xr} y1={top - 8} y2={H - 8} class="lifeline" />
        {pk.map((p, i) => {
          const y = top + i * step + 10;
          const c2s = p.dir === 'c2s';
          const x1 = c2s ? xl : xr;
          const x2 = c2s ? xr : xl;
          const warn = p.notes & ~NOTE.KEEPALIVE;
          const kind = p.flags & FLAG.RST ? 'rst' : warn ? 'warn' : p.dir;
          const notes = noteList(p.notes)
            .map((n) => n[1])
            .join(' ');
          return (
            <g key={p.no} class={`lad-row k-${kind}`}>
              <title>{`#${p.no}  ${flagNames(p.flags).join(',')}  seq=${p.rel_seq} ack=${p.rel_ack} len=${p.len} win=${p.win}`}</title>
              <text x={8} y={y + 13} class="lad-time">
                +{ms((p.ts - t0) * 1000)}
              </text>
              <line x1={x1} x2={x2 + (c2s ? -2 : 2)} y1={y} y2={y + 18} class={`lad-arrow a-${kind}`} marker-end={`url(#ah-${kind})`} />
              <text x={(xl + xr) / 2} y={y + 4} text-anchor="middle" class="lad-label">
                {packetLabel(p)}
                {notes && <tspan class="lad-note"> {notes}</tspan>}
              </text>
            </g>
          );
        })}
      </svg>
      {d.packets.length > LADDER_MAX && <div class="muted pad">时序图只画前 {LADDER_MAX} 个包</div>}
    </div>
  );
}
