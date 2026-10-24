mod cli;
mod decode;
mod proto;
mod server;
mod source;
mod tracker;

use argh::FromArgs;
use std::sync::{Arc, RwLock};

/// Inspect TCP connections from pcap files or live captures in a DevTools-style web UI.
/// AI agents: run `tcp-trace agent-guide` for non-interactive usage and JSON output notes.
#[derive(FromArgs)]
struct Args {
  #[argh(subcommand)]
  cmd: Cmd,
}

#[derive(FromArgs)]
#[argh(subcommand)]
enum Cmd {
  Open(OpenArgs),
  Capture(CaptureArgs),
  Interfaces(InterfacesArgs),
  Summary(SummaryArgs),
  Show(ShowArgs),
  Record(RecordArgs),
  AgentGuide(AgentGuideArgs),
}

/// open a pcap / pcapng file ("-" reads from stdin) and start the web UI
#[derive(FromArgs)]
#[argh(subcommand, name = "open")]
struct OpenArgs {
  /// capture file, or "-" for stdin (e.g. `sudo tcpdump -U -w - | tcp-trace open -`)
  #[argh(positional)]
  file: String,
  #[argh(option, default = "9330")]
  /// web UI port on 127.0.0.1 (default 9330)
  port: u16,
  #[argh(switch)]
  /// do not open the browser
  no_open: bool,
}

/// capture live traffic through Wireshark's dumpcap (or tcpdump) and start the web UI
#[derive(FromArgs)]
#[argh(subcommand, name = "capture")]
struct CaptureArgs {
  #[argh(option, short = 'i')]
  /// interface to capture on, e.g. en0 or lo0
  iface: String,
  #[argh(option, short = 'f')]
  /// capture filter in BPF syntax, e.g. "tcp port 8080"
  filter: Option<String>,
  #[argh(option)]
  /// capture tool: dumpcap (default when Wireshark is installed) or tcpdump
  tool: Option<String>,
  #[argh(option, default = "9330")]
  /// web UI port on 127.0.0.1 (default 9330)
  port: u16,
  #[argh(switch)]
  /// do not open the browser
  no_open: bool,
}

/// list capture interfaces
#[derive(FromArgs)]
#[argh(subcommand, name = "interfaces")]
struct InterfacesArgs {
  #[argh(option)]
  /// capture tool: dumpcap or tcpdump
  tool: Option<String>,
}

/// list the TCP connections in a capture file (table, or --json)
#[derive(FromArgs)]
#[argh(subcommand, name = "summary")]
struct SummaryArgs {
  #[argh(positional)]
  /// capture file, or "-" for stdin
  file: String,
  #[argh(switch)]
  /// print JSON
  json: bool,
  #[argh(switch)]
  /// only connections with problems (reset, refused, retransmissions, gaps…)
  issues: bool,
  #[argh(option)]
  /// only connections using this port on either side
  port: Option<u16>,
  #[argh(option)]
  /// only connections whose address, protocol, state or label contains this text
  grep: Option<String>,
}

/// show one connection: findings, timing, and optionally messages, packets or raw stream
#[derive(FromArgs)]
#[argh(subcommand, name = "show")]
struct ShowArgs {
  #[argh(positional)]
  /// capture file
  file: String,
  #[argh(positional)]
  /// connection id from `tcp-trace summary`
  id: usize,
  #[argh(switch)]
  /// print JSON
  json: bool,
  #[argh(switch)]
  /// include HTTP/1.x or WebSocket messages
  messages: bool,
  #[argh(switch)]
  /// include TCP packets
  packets: bool,
  #[argh(switch)]
  /// include the reassembled byte stream
  stream: bool,
  #[argh(option, default = "200")]
  /// max packets / stream chunks to print (default 200)
  limit: usize,
  #[argh(option, default = "String::from(\"text\")")]
  /// stream encoding: text (base64 when not UTF-8), hex or base64
  encoding: String,
}

/// capture for a fixed time into a pcapng file, then print the connection table
#[derive(FromArgs)]
#[argh(subcommand, name = "record")]
struct RecordArgs {
  #[argh(option, short = 'i')]
  /// interface to capture on, e.g. en0 or lo0
  iface: String,
  #[argh(option, short = 'f')]
  /// capture filter in BPF syntax, e.g. "tcp port 8080"
  filter: Option<String>,
  #[argh(option, short = 'w')]
  /// output file
  write: String,
  #[argh(option, default = "10")]
  /// seconds to capture (default 10)
  seconds: u64,
  #[argh(option)]
  /// capture tool: dumpcap or tcpdump
  tool: Option<String>,
  #[argh(switch)]
  /// print the connection table as JSON
  json: bool,
}

/// print usage notes for AI agents and scripts
#[derive(FromArgs)]
#[argh(subcommand, name = "agent-guide")]
struct AgentGuideArgs {}

pub struct State {
  pub tracker: tracker::Tracker,
  pub source: String,
  pub live: bool,
  pub done: bool,
  pub error: Option<String>,
  pub version: u64,
}

fn new_state(source: String, live: bool) -> Arc<RwLock<State>> {
  Arc::new(RwLock::new(State {
    tracker: Default::default(),
    source,
    live,
    done: false,
    error: None,
    version: 0,
  }))
}

fn open_input(file: &str) -> Result<Box<dyn std::io::Read + Send>, String> {
  if file == "-" {
    Ok(Box::new(std::io::stdin()))
  } else {
    std::fs::File::open(file)
      .map(|f| Box::new(f) as Box<dyn std::io::Read + Send>)
      .map_err(|e| format!("cannot open {file}: {e}"))
  }
}

fn fail(msg: impl std::fmt::Display) -> ! {
  eprintln!("tcp-trace: {msg}");
  std::process::exit(1)
}

#[tokio::main]
async fn main() {
  let args: Args = argh::from_env();
  match args.cmd {
    Cmd::Open(a) => {
      let input = open_input(&a.file).unwrap_or_else(|e| fail(e));
      let name = if a.file == "-" { "stdin".to_string() } else { a.file.clone() };
      let state = new_state(name, a.file == "-");
      let st = state.clone();
      std::thread::spawn(move || source::ingest(input, st));
      server::serve(state, a.port, !a.no_open).await;
    }
    Cmd::Capture(a) => {
      let (tool, path) = source::pick_tool(a.tool.as_deref()).unwrap_or_else(|e| fail(e));
      let mut child = source::spawn_capture(tool, &path, &a.iface, a.filter.as_deref())
        .unwrap_or_else(|e| fail(format!("cannot start {}: {e}", path.display())));
      let stdout = child.stdout.take().unwrap();
      let label = match &a.filter {
        Some(f) => format!("{} · {}", a.iface, f),
        None => a.iface.clone(),
      };
      eprintln!("tcp-trace: capturing on {label} via {}", path.display());
      let state = new_state(label, true);
      let st = state.clone();
      std::thread::spawn(move || {
        source::ingest(stdout, st.clone());
        let status = child.wait();
        let mut s = st.write().unwrap();
        if let Ok(code) = status {
          if !code.success() && s.tracker.frames == 0 {
            s.error = Some(format!(
              "capture process exited with {code}; see the terminal for details (permissions?)"
            ));
          }
        }
      });
      server::serve(state, a.port, !a.no_open).await;
    }
    Cmd::Interfaces(a) => {
      let (_, path) = source::pick_tool(a.tool.as_deref()).unwrap_or_else(|e| fail(e));
      let _ = source::list_interfaces(&path);
    }
    Cmd::Summary(a) => {
      let input = open_input(&a.file).unwrap_or_else(|e| fail(e));
      let state = new_state(a.file.clone(), false);
      source::ingest(input, state.clone());
      let opts = cli::ListOpts {
        json: a.json,
        issues: a.issues,
        port: a.port,
        grep: a.grep,
      };
      cli::list(&state.read().unwrap(), &opts);
    }
    Cmd::Show(a) => {
      let input = open_input(&a.file).unwrap_or_else(|e| fail(e));
      let state = new_state(a.file.clone(), false);
      source::ingest(input, state.clone());
      let st = state.read().unwrap();
      if let Some(e) = &st.error {
        fail(e);
      }
      let opts = cli::ShowOpts {
        json: a.json,
        packets: a.packets,
        stream: a.stream,
        messages: a.messages,
        limit: a.limit,
        encoding: a.encoding,
      };
      cli::show(&st, a.id, &opts).unwrap_or_else(|e| fail(e));
    }
    Cmd::Record(a) => {
      let (tool, path) = source::pick_tool(a.tool.as_deref()).unwrap_or_else(|e| fail(e));
      let mut child = source::spawn_capture(tool, &path, &a.iface, a.filter.as_deref())
        .unwrap_or_else(|e| fail(format!("cannot start {}: {e}", path.display())));
      let mut stdout = child.stdout.take().unwrap();
      let mut file = std::fs::File::create(&a.write).unwrap_or_else(|e| fail(format!("cannot create {}: {e}", a.write)));
      eprintln!(
        "tcp-trace: recording {} for {}s via {} → {}",
        a.iface,
        a.seconds,
        path.display(),
        a.write
      );
      let copier = std::thread::spawn(move || std::io::copy(&mut stdout, &mut file));
      std::thread::sleep(std::time::Duration::from_secs(a.seconds));
      let _ = child.kill();
      let _ = child.wait();
      let _ = copier.join();
      let input = open_input(&a.write).unwrap_or_else(|e| fail(e));
      let state = new_state(a.write.clone(), false);
      source::ingest(input, state.clone());
      let st = state.read().unwrap();
      if st.tracker.frames == 0 {
        fail("nothing was captured: check the interface name, the filter and capture permissions");
      }
      cli::list(
        &st,
        &cli::ListOpts {
          json: a.json,
          issues: false,
          port: None,
          grep: None,
        },
      );
    }
    Cmd::AgentGuide(_) => print!("{}", cli::AGENT_GUIDE),
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  fn load(path: &str) -> Arc<RwLock<State>> {
    let state = new_state(path.into(), false);
    source::ingest(std::fs::File::open(path).unwrap(), state.clone());
    state
  }

  #[test]
  fn demo_capture() {
    let state = load("examples/demo.pcap");
    let st = state.read().unwrap();
    assert!(st.error.is_none());
    let conns: Vec<_> = st.tracker.conns.iter().map(|c| c.summary()).collect();
    assert_eq!(conns.len(), 7);
    assert_eq!(conns[2].proto, "WebSocket");
    assert_eq!(conns[4].state, "reset");
    assert_eq!(conns[6].label.as_deref(), Some("api.example.dev"));

    let ws = proto::messages(&st.tracker.conns[2]);
    assert_eq!(ws.kind, Some("websocket"));
    assert!(ws.messages.iter().any(|m| m.kind == "text" && m.title == "subscribe:ticker"));
    let http = proto::messages(&st.tracker.conns[0]);
    assert_eq!(http.messages.len(), 6);
  }

  #[test]
  fn issues_capture() {
    let state = load("examples/demo-issues.pcap");
    let st = state.read().unwrap();
    let c = &st.tracker.conns[0];
    assert_eq!((c.lost, c.out_of_order), (1, 1));
    assert_eq!(st.tracker.conns[3].retrans, 1);
    // Late data is put back in order, so HTTP parsing still works.
    assert_eq!(proto::messages(c).messages.len(), 6);
  }
}
