# tcp-trace

在浏览器里查看 TCP 连接的小工具。它读取抓包数据（pcap/pcapng 文件，或 Wireshark/tcpdump 的实时输出），把数据包按连接归组，然后用 Chrome DevTools 风格的界面展示：

- **连接列表**：协议识别（HTTP/1.1、WebSocket、TLS 的 SNI、Redis 等）、状态、流量、握手耗时、问题计数、时间线
- **诊断**：用普通话解释连接拒绝、RST 中断、重传、数据缺口、零窗口、服务端响应慢等情况
- **消息**：HTTP/1.x 请求和响应，WebSocket 帧（支持 permessage-deflate 解压、JSON 美化）
- **数据流**：双向重组后的字节流，可切换文本或 Hex，适合排查非 HTTP 协议
- **数据包**：seq/ack/flags/窗口，标出重传、乱序、重复 ACK
- **时序图**：客户端与服务端之间逐包的交互图

它的目标不是替代 Wireshark，而是让不熟悉 TCP 的程序员能快速看懂某一条连接上发生了什么。

## 构建

需要 Rust 工具链。前端已经构建到 `web/dist`，会被打包进二进制，所以只构建 Rust 部分也可以：

```bash
cargo build --release
# 可执行文件在 target/release/tcp-trace
```

修改前端后重新构建：

```bash
cd web && npm install && npm run build && cd ..
cargo build --release
```

## 使用

### 1. 打开抓包文件（不需要任何权限）

```bash
tcp-trace open examples/demo.pcap
tcp-trace open examples/demo-issues.pcap   # 人为制造了缺包、乱序和重传的版本
```

会在 `http://127.0.0.1:9330` 启动界面并自动打开浏览器。`--port` 改端口，`--no-open` 不打开浏览器。

### 2. 实时抓包

推荐装 Wireshark。macOS 上安装 Wireshark 时勾选 **ChmodBPF**，之后普通用户就能抓包，`tcp-trace` 会自动找到 Wireshark 自带的 `dumpcap`：

```bash
tcp-trace interfaces                       # 列出网卡
tcp-trace capture -i lo0 -f "tcp port 5173"   # 本机开发服务器
tcp-trace capture -i en0 -f "host api.example.com"
```

没有 Wireshark 时，可以只让 tcpdump 以 root 运行，`tcp-trace` 本身保持普通权限：

```bash
sudo tcpdump -i lo0 -U -w - 'tcp port 8080' | tcp-trace open -
```

也可以 `sudo tcp-trace capture -i lo0 --tool tcpdump`，但这样整个程序都以 root 运行，不推荐。

### 3. 命令行与 AI Agent

不需要打开界面的场景（脚本、AI Agent）用这几个命令，都可以加 `--json`：

```bash
tcp-trace agent-guide                                   # 给 Agent 看的完整说明：工作流程、字段含义、诊断代码
tcp-trace record -i lo0 -f "tcp port 5173" --seconds 10 -w /tmp/t.pcapng
tcp-trace summary /tmp/t.pcapng --issues --json         # 也支持 --port、--grep
tcp-trace show /tmp/t.pcapng 3 --messages --json        # 诊断、耗时、HTTP/WebSocket 消息
tcp-trace show /tmp/t.pcapng 3 --packets --stream --encoding hex
```

`show` 的 `findings[].code` 是稳定的诊断代码（`connection_refused`、`reset_by_server`、`retransmissions`、`slow_first_byte` 等），方便 Agent 判断。

## 界面操作

- `/` 聚焦过滤框，支持 `state:reset`、`port:8080`、`proto:ws`、`is:issue` 以及任意文本
- `↑` `↓` 切换连接，`Esc` 关闭详情
- 右上角按钮切换浅色、深色、跟随系统

## 已知限制（预览版）

- HTTPS 内容是加密的，只能看到 TLS 握手、SNI 和 ALPN；暂不支持 SSLKEYLOGFILE 解密
- HTTP/2、gRPC 只识别协议，不拆帧
- 每条连接最多保存 16 MB 负载，详情接口最多返回 2 万个包
- 本机发出的包可能因网卡分段卸载（TSO）显示为超过 MSS 的大包，属于正常现象
- Web 服务只监听 127.0.0.1

## 代码结构

| 路径 | 作用 |
| --- | --- |
| `src/main.rs` | 命令行参数与子命令 |
| `src/cli.rs` | 终端与 JSON 输出、诊断规则、agent-guide |
| `src/source.rs` | 读取 pcap/pcapng 流，启动 dumpcap/tcpdump |
| `src/decode.rs` | 链路层（Ethernet、BSD loopback、SLL）到 TCP 的解码 |
| `src/tracker.rs` | 连接追踪、序列号分析、字节流重组 |
| `src/proto.rs` | 协议识别、TLS SNI、HTTP/1.x 与 WebSocket 消息拆分 |
| `src/server.rs` | 本地 HTTP API 与内嵌前端 |
| `web/` | Preact + Vite + TypeScript 前端 |
