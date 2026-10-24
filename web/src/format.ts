import { Conn, FLAG, NOTE } from './api';

export function bytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

export function ms(v: number | null | undefined): string {
  if (v == null) return '—';
  if (v < 1) return `${(v * 1000).toFixed(0)} µs`;
  if (v < 1000) return `${v < 10 ? v.toFixed(2) : v.toFixed(0)} ms`;
  return `${(v / 1000).toFixed(2)} s`;
}

export function clock(ts: number): string {
  const d = new Date(ts * 1000);
  const pad = (n: number, w = 2) => String(n).padStart(w, '0');
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}.${pad(Math.floor((ts % 1) * 1e6), 6)}`;
}

export function flagNames(f: number): string[] {
  const out: string[] = [];
  if (f & FLAG.SYN) out.push('SYN');
  if (f & FLAG.FIN) out.push('FIN');
  if (f & FLAG.RST) out.push('RST');
  if (f & FLAG.PSH) out.push('PSH');
  if (f & FLAG.ACK) out.push('ACK');
  if (f & FLAG.URG) out.push('URG');
  if (f & FLAG.ECE) out.push('ECE');
  if (f & FLAG.CWR) out.push('CWR');
  return out;
}

export const NOTE_TEXT: [number, string, string][] = [
  [NOTE.RETRANS, '重传', '这段数据之前已经发过，发送方没等到确认又发了一次'],
  [NOTE.PREV_LOST, '前段缺失', '这一段之前的数据没有被抓到：可能丢包，或稍后乱序到达'],
  [NOTE.OUT_OF_ORDER, '乱序', '补上了之前缺失的数据'],
  [NOTE.DUP_ACK, '重复 ACK', '接收方重复确认同一位置，通常说明它在等丢失的数据'],
  [NOTE.ZERO_WINDOW, '零窗口', '接收方缓冲区已满，要求发送方暂停'],
  [NOTE.KEEPALIVE, 'Keep-Alive', 'TCP 保活探测'],
];

export const STATE_TEXT: Record<Conn['state'], string> = {
  'syn-sent': '等待应答',
  'syn-received': '握手中',
  established: '已建立',
  closing: '关闭中',
  closed: '已关闭',
  reset: '已重置',
};

export function issueCount(c: Conn): number {
  return c.retrans + c.lost + c.dup_acks + c.zero_windows + (c.state === 'reset' ? 1 : 0) + (c.state === 'syn-sent' ? 1 : 0);
}

export function protoGroup(c: Conn): 'http' | 'ws' | 'tls' | 'other' {
  if (c.proto === 'WebSocket') return 'ws';
  if (c.proto.startsWith('HTTP')) return 'http';
  if (c.proto.startsWith('TLS')) return 'tls';
  return 'other';
}

/** Plain-language findings for people who don't read TCP every day. */
export function diagnose(c: Conn, firstC2s: number | null, firstS2c: number | null): { level: 'error' | 'warn' | 'info'; text: string }[] {
  const out: { level: 'error' | 'warn' | 'info'; text: string }[] = [];
  const nothingFromServer = c.bytes_s2c === 0;
  if (c.state === 'syn-sent') out.push({ level: 'error', text: '客户端发出了 SYN 但没有收到任何回应：目标可能不可达，或被防火墙静默丢弃。' });
  if (c.state === 'reset' && c.rst_from === 's2c' && c.handshake_ms == null && !c.partial) {
    out.push({ level: 'error', text: '连接被拒绝：服务端直接回了 RST，通常是这个端口没有程序在监听。' });
  } else if (c.state === 'reset') {
    const who = c.rst_from === 'c2s' ? '客户端' : '服务端';
    out.push({ level: 'error', text: `${who}发送 RST 强制中断了连接${nothingFromServer ? '，此前服务端没有返回任何数据' : ''}。常见原因：进程被杀、主动 abort（如浏览器取消请求）、代理或负载均衡超时。` });
  }
  if (c.retrans > 0) out.push({ level: 'warn', text: `出现 ${c.retrans} 次重传：网络丢包，或对端确认太慢。` });
  if (c.lost > 0) out.push({ level: 'warn', text: `有 ${c.lost} 处数据缺口：抓包时漏掉了部分数据（丢包、乱序或抓包缓冲溢出）。` });
  if (c.dup_acks > 0) out.push({ level: 'warn', text: `出现 ${c.dup_acks} 次重复 ACK：接收方在等待丢失的数据。` });
  if (c.zero_windows > 0) out.push({ level: 'warn', text: `出现 ${c.zero_windows} 次零窗口：接收方处理不过来，发送方被迫暂停。` });
  if (c.partial) out.push({ level: 'info', text: '抓包开始时这条连接已经建立，看不到握手过程，客户端/服务端角色是按端口推测的。' });
  if (firstC2s != null && firstS2c != null && firstS2c > firstC2s) {
    const wait = (firstS2c - firstC2s) * 1000;
    if (wait > 200) out.push({ level: 'warn', text: `客户端发出数据后，服务端过了 ${ms(wait)} 才返回第一个字节。时间主要花在服务端处理上，而不是网络。` });
  }
  if (c.truncated) out.push({ level: 'info', text: '数据量超过单连接 16 MB 的保存上限，后面的内容没有保存。' });
  if (out.length === 0) out.push({ level: 'info', text: '没有发现异常：握手、传输和关闭都正常。' });
  return out;
}
