//! Link layer → IP → TCP decoding for a single captured frame.

use etherparse::{NetSlice, SlicedPacket, TcpOptionElement, TransportSlice};
use std::net::IpAddr;

pub const FLAG_FIN: u8 = 0x01;
pub const FLAG_SYN: u8 = 0x02;
pub const FLAG_RST: u8 = 0x04;
pub const FLAG_PSH: u8 = 0x08;
pub const FLAG_ACK: u8 = 0x10;
pub const FLAG_URG: u8 = 0x20;
pub const FLAG_ECE: u8 = 0x40;
pub const FLAG_CWR: u8 = 0x80;

#[derive(Debug, Clone, Default)]
pub struct TcpOptions {
  pub mss: Option<u16>,
  pub wscale: Option<u8>,
  pub sack_perm: bool,
  pub sack_blocks: u8,
  pub timestamp: bool,
}

#[derive(Debug, Clone)]
pub struct Segment<'a> {
  pub ts: f64,
  pub src: IpAddr,
  pub dst: IpAddr,
  pub sport: u16,
  pub dport: u16,
  pub seq: u32,
  pub ack: u32,
  pub flags: u8,
  pub window: u16,
  pub options: TcpOptions,
  pub payload: &'a [u8],
  /// Length on the wire, which may exceed what was captured (snaplen).
  pub wire_len: u32,
}

pub enum Decoded<'a> {
  Tcp(Segment<'a>),
  Other,
}

// Linktype numbers from https://www.tcpdump.org/linktypes.html
const LINKTYPE_NULL: i32 = 0;
const LINKTYPE_ETHERNET: i32 = 1;
const LINKTYPE_RAW: i32 = 101;
const LINKTYPE_LOOP: i32 = 108;
const LINKTYPE_LINUX_SLL: i32 = 113;
const LINKTYPE_IPV4: i32 = 228;
const LINKTYPE_IPV6: i32 = 229;
const LINKTYPE_LINUX_SLL2: i32 = 276;

pub fn decode(linktype: i32, ts: f64, data: &[u8], wire_len: u32) -> Result<Decoded<'_>, String> {
  let sliced = match linktype {
    LINKTYPE_ETHERNET => SlicedPacket::from_ethernet(data),
    LINKTYPE_LINUX_SLL => SlicedPacket::from_linux_sll(data),
    LINKTYPE_RAW | LINKTYPE_IPV4 | LINKTYPE_IPV6 => SlicedPacket::from_ip(data),
    // BSD loopback (macOS lo0): 4 byte address family header, then IP.
    LINKTYPE_NULL | LINKTYPE_LOOP => {
      if data.len() < 4 {
        return Err("short loopback header".into());
      }
      SlicedPacket::from_ip(&data[4..])
    }
    // SLL2 has a fixed 20 byte header ending in the IP packet.
    LINKTYPE_LINUX_SLL2 => {
      if data.len() < 20 {
        return Err("short SLL2 header".into());
      }
      SlicedPacket::from_ip(&data[20..])
    }
    other => return Err(format!("unsupported link type {other}")),
  }
  .map_err(|e| e.to_string())?;

  let (src, dst) = match &sliced.net {
    Some(NetSlice::Ipv4(v4)) => (IpAddr::V4(v4.header().source_addr()), IpAddr::V4(v4.header().destination_addr())),
    Some(NetSlice::Ipv6(v6)) => (IpAddr::V6(v6.header().source_addr()), IpAddr::V6(v6.header().destination_addr())),
    _ => return Ok(Decoded::Other),
  };
  let tcp = match &sliced.transport {
    Some(TransportSlice::Tcp(tcp)) => tcp,
    _ => return Ok(Decoded::Other),
  };

  let mut flags = 0u8;
  for (on, bit) in [
    (tcp.fin(), FLAG_FIN),
    (tcp.syn(), FLAG_SYN),
    (tcp.rst(), FLAG_RST),
    (tcp.psh(), FLAG_PSH),
    (tcp.ack(), FLAG_ACK),
    (tcp.urg(), FLAG_URG),
    (tcp.ece(), FLAG_ECE),
    (tcp.cwr(), FLAG_CWR),
  ] {
    if on {
      flags |= bit;
    }
  }

  let mut options = TcpOptions::default();
  for opt in tcp.options_iterator().flatten() {
    match opt {
      TcpOptionElement::MaximumSegmentSize(v) => options.mss = Some(v),
      TcpOptionElement::WindowScale(v) => options.wscale = Some(v),
      TcpOptionElement::SelectiveAcknowledgementPermitted => options.sack_perm = true,
      TcpOptionElement::SelectiveAcknowledgement(_, rest) => {
        options.sack_blocks = 1 + rest.iter().filter(|b| b.is_some()).count() as u8;
      }
      TcpOptionElement::Timestamp(_, _) => options.timestamp = true,
      TcpOptionElement::Noop => {}
    }
  }

  Ok(Decoded::Tcp(Segment {
    ts,
    src,
    dst,
    sport: tcp.source_port(),
    dport: tcp.destination_port(),
    seq: tcp.sequence_number(),
    ack: tcp.acknowledgment_number(),
    flags,
    window: tcp.window_size(),
    options,
    payload: tcp.payload(),
    wire_len,
  }))
}
