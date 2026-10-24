//! Reads pcap / pcapng data from a file, stdin or a capture process and feeds
//! every TCP segment into the shared tracker.

use crate::decode::{decode, Decoded};
use crate::State;
use pcap_parser::pcapng::Block;
use pcap_parser::{create_reader, PcapBlockOwned, PcapError};
use std::io::Read;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, RwLock};

struct Iface {
  linktype: i32,
  resolution: u64,
  offset: u64,
}

pub fn ingest<R: Read + Send>(input: R, state: Arc<RwLock<State>>) {
  let result = run(input, &state);
  let mut st = state.write().unwrap();
  st.done = true;
  st.version += 1;
  if let Err(e) = result {
    st.error = Some(e);
  }
}

fn run<R: Read + Send>(input: R, state: &Arc<RwLock<State>>) -> Result<(), String> {
  let mut reader = create_reader(1 << 20, input).map_err(|e| format!("not a pcap/pcapng stream: {e:?}"))?;
  let mut legacy_linktype = 1;
  let mut legacy_nanos = false;
  let mut ifaces: Vec<Iface> = Vec::new();
  loop {
    match reader.next() {
      Ok((offset, block)) => {
        let frame: Option<(i32, f64, &[u8], u32)> = match block {
          PcapBlockOwned::LegacyHeader(hdr) => {
            legacy_linktype = hdr.network.0;
            legacy_nanos = hdr.is_nanosecond_precision();
            None
          }
          PcapBlockOwned::Legacy(b) => {
            let frac = if legacy_nanos {
              b.ts_usec as f64 / 1e9
            } else {
              b.ts_usec as f64 / 1e6
            };
            Some((
              legacy_linktype,
              b.ts_sec as f64 + frac,
              &b.data[..(b.caplen as usize).min(b.data.len())],
              b.origlen,
            ))
          }
          PcapBlockOwned::NG(Block::SectionHeader(_)) => {
            ifaces.clear();
            None
          }
          PcapBlockOwned::NG(Block::InterfaceDescription(idb)) => {
            ifaces.push(Iface {
              linktype: idb.linktype.0,
              resolution: idb.ts_resolution().unwrap_or(1_000_000),
              offset: idb.ts_offset().max(0) as u64,
            });
            None
          }
          PcapBlockOwned::NG(Block::EnhancedPacket(epb)) => match ifaces.get(epb.if_id as usize) {
            Some(i) => Some((
              i.linktype,
              epb.decode_ts_f64(i.offset, i.resolution),
              &epb.data[..(epb.caplen as usize).min(epb.data.len())],
              epb.origlen,
            )),
            None => None,
          },
          PcapBlockOwned::NG(Block::SimplePacket(spb)) => ifaces.first().map(|i| (i.linktype, 0.0, spb.data, spb.origlen)),
          _ => None,
        };
        if let Some((linktype, ts, data, wire_len)) = frame {
          let mut st = state.write().unwrap();
          st.tracker.note_frame(ts);
          match decode(linktype, ts, data, wire_len) {
            Ok(Decoded::Tcp(seg)) => st.tracker.add(&seg),
            Ok(Decoded::Other) => {}
            Err(_) => st.tracker.decode_errors += 1,
          }
          st.version += 1;
        }
        reader.consume(offset);
      }
      Err(PcapError::Eof) => return Ok(()),
      Err(PcapError::Incomplete(_)) => {
        reader.refill().map_err(|e| format!("read error: {e:?}"))?;
      }
      Err(PcapError::UnexpectedEof) => return Ok(()),
      Err(PcapError::BufferTooSmall) => {
        let size = reader.data().len().max(1 << 20) * 2;
        if !reader.grow(size) {
          return Err("packet larger than reader buffer".into());
        }
        reader.refill().map_err(|e| format!("read error: {e:?}"))?;
      }
      Err(e) => return Err(format!("parse error: {e:?}")),
    }
  }
}

/// Wireshark's dumpcap can capture without root once ChmodBPF is installed.
pub fn find_dumpcap() -> Option<PathBuf> {
  let candidates = [
    "/Applications/Wireshark.app/Contents/MacOS/dumpcap",
    "/usr/local/bin/dumpcap",
    "/opt/homebrew/bin/dumpcap",
    "/usr/bin/dumpcap",
  ];
  if let Some(p) = which("dumpcap") {
    return Some(p);
  }
  candidates.iter().map(PathBuf::from).find(|p| p.exists())
}

fn which(name: &str) -> Option<PathBuf> {
  let path = std::env::var_os("PATH")?;
  std::env::split_paths(&path).map(|d| d.join(name)).find(|p| p.is_file())
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Tool {
  Dumpcap,
  Tcpdump,
}

pub fn pick_tool(requested: Option<&str>) -> Result<(Tool, PathBuf), String> {
  match requested {
    Some("tcpdump") => which("tcpdump")
      .map(|p| (Tool::Tcpdump, p))
      .ok_or("tcpdump not found in PATH".into()),
    Some("dumpcap") | None => match find_dumpcap() {
      Some(p) => Ok((Tool::Dumpcap, p)),
      None if requested.is_none() => which("tcpdump")
        .map(|p| (Tool::Tcpdump, p))
        .ok_or("neither dumpcap (Wireshark) nor tcpdump was found".into()),
      None => Err("dumpcap not found; install Wireshark or pass --tool tcpdump".into()),
    },
    Some(other) => Err(format!("unknown capture tool {other}; use dumpcap or tcpdump")),
  }
}

pub fn spawn_capture(tool: Tool, path: &PathBuf, iface: &str, filter: Option<&str>) -> std::io::Result<Child> {
  let mut cmd = Command::new(path);
  match tool {
    Tool::Dumpcap => {
      cmd.args(["-i", iface, "-q", "-w", "-"]);
      if let Some(f) = filter {
        cmd.args(["-f", f]);
      }
    }
    Tool::Tcpdump => {
      cmd.args(["-i", iface, "-U", "-n", "-w", "-"]);
      if let Some(f) = filter {
        cmd.args(f.split_whitespace());
      }
    }
  }
  cmd.stdout(Stdio::piped()).stderr(Stdio::inherit()).stdin(Stdio::null()).spawn()
}

pub fn list_interfaces(path: &PathBuf) -> std::io::Result<std::process::ExitStatus> {
  Command::new(path).arg("-D").status()
}
