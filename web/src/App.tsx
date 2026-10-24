import { useEffect, useMemo, useRef, useState } from 'preact/hooks';
import { api, Conn, Summary } from './api';
import { bytes, issueCount, ms, protoGroup, STATE_TEXT } from './format';
import { DetailPanel } from './Detail';
import { Icon } from './Icon';

type Group = 'all' | 'http' | 'ws' | 'tls' | 'other';
const GROUPS: [Group, string][] = [
  ['all', '全部'],
  ['http', 'HTTP'],
  ['ws', 'WebSocket'],
  ['tls', 'TLS'],
  ['other', '其他 TCP'],
];

function matches(c: Conn, tokens: string[]): boolean {
  return tokens.every((t) => {
    const [k, v] = t.includes(':') && !t.includes('.') ? t.split(':', 2) : ['', t];
    switch (k) {
      case 'state':
        return c.state.startsWith(v) || STATE_TEXT[c.state].includes(v);
      case 'port':
        return c.client.endsWith(`:${v}`) || c.server.endsWith(`:${v}`);
      case 'proto':
        return c.proto.toLowerCase().includes(v);
      case 'is':
        return v === 'issue' ? issueCount(c) > 0 : true;
      default: {
        const hay = `${c.client} ${c.server} ${c.proto} ${c.label ?? ''} ${c.state} ${STATE_TEXT[c.state]}`.toLowerCase();
        return hay.includes(t);
      }
    }
  });
}

function useTheme(): [string, () => void] {
  const [theme, setTheme] = useState<string>(() => {
    try {
      return localStorage.getItem('tcp-trace-theme') ?? 'auto';
    } catch {
      return 'auto';
    }
  });
  useEffect(() => {
    if (theme === 'auto') document.documentElement.removeAttribute('data-theme');
    else document.documentElement.setAttribute('data-theme', theme);
    try {
      localStorage.setItem('tcp-trace-theme', theme);
    } catch {}
  }, [theme]);
  const next = () => setTheme((t) => (t === 'auto' ? 'dark' : t === 'dark' ? 'light' : 'auto'));
  return [theme, next];
}

export function App() {
  const [summary, setSummary] = useState<Summary | null>(null);
  const [conns, setConns] = useState<Conn[]>([]);
  const [selected, setSelected] = useState<number | null>(null);
  const [filter, setFilter] = useState('');
  const [group, setGroup] = useState<Group>('all');
  const [issuesOnly, setIssuesOnly] = useState(false);
  const [paused, setPaused] = useState(false);
  const [split, setSplit] = useState(0.38);
  const [theme, nextTheme] = useTheme();
  const versionRef = useRef(-1);
  const filterRef = useRef<HTMLInputElement>(null);
  const mainRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    let alive = true;
    let timer = 0;
    const tick = async () => {
      try {
        const s = await api.summary();
        if (!alive) return;
        setSummary(s);
        if (s.version !== versionRef.current && !paused) {
          versionRef.current = s.version;
          setConns(await api.conns());
        }
        if (s.done && !s.live) return;
        timer = window.setTimeout(tick, s.done ? 3000 : 1000);
      } catch {
        timer = window.setTimeout(tick, 2000);
      }
    };
    tick();
    return () => {
      alive = false;
      clearTimeout(timer);
    };
  }, [paused]);

  const visible = useMemo(() => {
    const tokens = filter.toLowerCase().split(/\s+/).filter(Boolean);
    return conns.filter((c) => (group === 'all' || protoGroup(c) === group) && (!issuesOnly || issueCount(c) > 0) && matches(c, tokens));
  }, [conns, filter, group, issuesOnly]);

  const span = useMemo(() => {
    const t0 = summary?.first_ts ?? 0;
    const t1 = Math.max(summary?.last_ts ?? 0, t0 + 0.001);
    return { t0, t1 };
  }, [summary?.first_ts, summary?.last_ts]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const typing = (e.target as HTMLElement)?.tagName === 'INPUT';
      if (e.key === '/' && !typing) {
        e.preventDefault();
        filterRef.current?.focus();
      } else if (e.key === 'Escape') {
        if (typing) (e.target as HTMLInputElement).blur();
        else setSelected(null);
      } else if ((e.key === 'ArrowDown' || e.key === 'ArrowUp') && !typing && visible.length) {
        e.preventDefault();
        const i = visible.findIndex((c) => c.id === selected);
        const n = e.key === 'ArrowDown' ? Math.min(i + 1, visible.length - 1) : Math.max(i - 1, 0);
        setSelected(visible[i < 0 ? 0 : n].id);
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [visible, selected]);

  const startDrag = (e: PointerEvent) => {
    e.preventDefault();
    const box = mainRef.current!.getBoundingClientRect();
    const move = (ev: PointerEvent) => setSplit(Math.min(0.75, Math.max(0.2, (ev.clientX - box.left) / box.width)));
    const up = () => {
      window.removeEventListener('pointermove', move);
      window.removeEventListener('pointerup', up);
      document.body.classList.remove('dragging');
    };
    document.body.classList.add('dragging');
    window.addEventListener('pointermove', move);
    window.addEventListener('pointerup', up);
  };

  const sel = conns.find((c) => c.id === selected) ?? null;
  const live = summary?.live && !summary.done;
  const counts = useMemo(() => {
    const m: Record<Group, number> = { all: conns.length, http: 0, ws: 0, tls: 0, other: 0 };
    for (const c of conns) m[protoGroup(c)]++;
    return m;
  }, [conns]);
  const issueTotal = useMemo(() => conns.filter((c) => issueCount(c) > 0).length, [conns]);

  return (
    <div class="app">
      <header class="toolbar">
        <div class="brand">
          <span class="brand-mark">
            <Icon name="lines" />
          </span>
          TCP Trace
        </div>
        <div class={`source ${live ? 'is-live' : ''}`} title={summary?.source}>
          {live ? <span class="rec-dot" /> : <Icon name="file" />}
          <span class="source-name">{summary ? (summary.live ? summary.source : summary.source.split('/').pop()) : '加载中…'}</span>
        </div>
        {summary?.live && (
          <button class="icon-btn" title={paused ? '继续刷新' : '暂停刷新'} onClick={() => setPaused((p) => !p)}>
            <Icon name={paused ? 'play' : 'pause'} />
          </button>
        )}
        <div class="divider" />
        <label class="filter">
          <Icon name="filter" />
          <input
            ref={filterRef}
            value={filter}
            onInput={(e) => setFilter((e.target as HTMLInputElement).value)}
            placeholder="过滤：地址、端口、域名…  也可用 state:reset  port:8080  is:issue"
            spellcheck={false}
          />
          {filter && (
            <button class="clear" onClick={() => setFilter('')} title="清除">
              <Icon name="close" />
            </button>
          )}
        </label>
        <div class="chips">
          {GROUPS.map(([g, label]) => (
            <button key={g} class={`chip ${group === g ? 'on' : ''}`} onClick={() => setGroup(g)}>
              {label}
              <span class="count">{counts[g]}</span>
            </button>
          ))}
          <button class={`chip warn ${issuesOnly ? 'on' : ''}`} onClick={() => setIssuesOnly((v) => !v)} title="只看有问题的连接">
            <Icon name="warning" />
            有问题
            <span class="count">{issueTotal}</span>
          </button>
        </div>
        <div class="spacer" />
        <button class="icon-btn" onClick={nextTheme} title={`主题：${theme === 'auto' ? '跟随系统' : theme === 'dark' ? '深色' : '浅色'}`}>
          <Icon name={theme === 'dark' ? 'moon' : theme === 'light' ? 'sun' : 'auto'} />
        </button>
      </header>

      {summary?.error && (
        <div class="banner error">
          <Icon name="warning" />
          {summary.error}
        </div>
      )}

      <div class="main" ref={mainRef}>
        <div class="list-pane" style={sel ? { width: `${split * 100}%` } : undefined}>
          <ConnTable conns={visible} selected={selected} onSelect={setSelected} compact={!!sel} span={span} empty={conns.length === 0} live={!!live} />
        </div>
        {sel && (
          <>
            <div class="resizer" onPointerDown={startDrag as any} />
            <div class="detail-pane">
              <DetailPanel conn={sel} version={summary?.version ?? 0} live={!!live} onClose={() => setSelected(null)} />
            </div>
          </>
        )}
      </div>

      <footer class="statusbar">
        <span>
          {visible.length} / {conns.length} 条连接
        </span>
        <span class="sep" />
        <span>{summary?.tcp_frames ?? 0} 个 TCP 包</span>
        {summary && summary.frames > summary.tcp_frames && <span class="muted">（另有 {summary.frames - summary.tcp_frames} 个非 TCP 帧）</span>}
        {summary && summary.decode_errors > 0 && <span class="muted">{summary.decode_errors} 个帧无法解码</span>}
        <span class="spacer" />
        {summary?.first_ts != null && summary.last_ts != null && <span>时长 {ms((summary.last_ts - summary.first_ts) * 1000)}</span>}
        <span class="sep" />
        <span class="muted">↑↓ 切换 · / 过滤 · Esc 关闭</span>
      </footer>
    </div>
  );
}

const ROW_H = 26;

function ConnTable(props: {
  conns: Conn[];
  selected: number | null;
  onSelect: (id: number) => void;
  compact: boolean;
  span: { t0: number; t1: number };
  empty: boolean;
  live: boolean;
}) {
  const { conns, selected, onSelect, compact, span } = props;
  const scroller = useRef<HTMLDivElement>(null);
  const [scroll, setScroll] = useState({ top: 0, height: 800 });

  useEffect(() => {
    const el = scroller.current!;
    const update = () => setScroll({ top: el.scrollTop, height: el.clientHeight });
    update();
    const ro = new ResizeObserver(update);
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  useEffect(() => {
    if (selected == null || !scroller.current) return;
    const i = conns.findIndex((c) => c.id === selected);
    if (i < 0) return;
    const el = scroller.current;
    const y = i * ROW_H;
    if (y < el.scrollTop) el.scrollTop = y;
    else if (y + ROW_H > el.scrollTop + el.clientHeight - ROW_H) el.scrollTop = y - el.clientHeight + ROW_H * 2;
  }, [selected]);

  const first = Math.max(0, Math.floor(scroll.top / ROW_H) - 10);
  const last = Math.min(conns.length, Math.ceil((scroll.top + scroll.height) / ROW_H) + 10);
  const dur = span.t1 - span.t0;

  return (
    <div class={`table conn-table ${compact ? 'compact' : ''}`}>
      <div class="thead">
        <div class="row">
          <div class="c-id">#</div>
          <div class="c-name">连接</div>
          {!compact && <div class="c-proto">协议</div>}
          <div class="c-state">状态</div>
          {!compact && (
            <>
              <div class="c-num">包</div>
              <div class="c-num">上行</div>
              <div class="c-num">下行</div>
              <div class="c-num">时长</div>
              <div class="c-num">握手</div>
            </>
          )}
          <div class="c-issue">问题</div>
          <div class="c-wf">时间线</div>
        </div>
      </div>
      <div class="tbody" ref={scroller} onScroll={(e) => setScroll({ top: (e.target as HTMLElement).scrollTop, height: (e.target as HTMLElement).clientHeight })}>
        {conns.length === 0 && (
          <div class="empty">
            <Icon name={props.live ? 'radar' : 'inbox'} />
            <div>{props.empty ? (props.live ? '正在抓包，等待 TCP 流量…' : '这个抓包文件里没有 TCP 连接') : '没有匹配过滤条件的连接'}</div>
          </div>
        )}
        <div style={{ height: conns.length * ROW_H, position: 'relative' }}>
          {conns.slice(first, last).map((c, k) => {
            const i = first + k;
            const issues = issueCount(c);
            const left = ((c.first_ts - span.t0) / dur) * 100;
            const width = Math.max(((c.last_ts - c.first_ts) / dur) * 100, 0.4);
            return (
              <div
                key={c.id}
                class={`row ${selected === c.id ? 'selected' : ''} ${c.state === 'reset' || c.state === 'syn-sent' ? 'is-error' : ''}`}
                style={{ top: i * ROW_H }}
                onClick={() => onSelect(c.id)}
              >
                <div class="c-id">{c.id}</div>
                <div class="c-name">
                  <span class={`proto-dot p-${protoGroup(c)}`} />
                  <span class="name-main">{c.label || c.server}</span>
                  <span class="name-sub">{c.label ? c.server : `← ${c.client}`}</span>
                </div>
                {!compact && <div class="c-proto">{c.proto}</div>}
                <div class="c-state">
                  <span class={`state s-${c.state}`}>{STATE_TEXT[c.state]}</span>
                </div>
                {!compact && (
                  <>
                    <div class="c-num">{c.packets}</div>
                    <div class="c-num">{bytes(c.bytes_c2s)}</div>
                    <div class="c-num">{bytes(c.bytes_s2c)}</div>
                    <div class="c-num">{ms((c.last_ts - c.first_ts) * 1000)}</div>
                    <div class="c-num">{ms(c.handshake_ms)}</div>
                  </>
                )}
                <div class="c-issue">{issues > 0 ? <span class="issue-badge">{issues}</span> : <span class="muted">—</span>}</div>
                <div class="c-wf">
                  <div class="wf-track">
                    <div class={`wf-bar s-${c.state}`} style={{ left: `${left}%`, width: `${Math.min(width, 100 - left)}%` }} />
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
