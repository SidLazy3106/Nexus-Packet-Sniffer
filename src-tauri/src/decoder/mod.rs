//! Protocol decoder. Every access to packet bytes goes through bounds-checked helpers,
//! so malformed or truncated input yields anomalies instead of panics.

mod app;
mod link;
mod network;
mod transport;
mod util;

use crate::constants::*;
use serde::Serialize;
use std::net::IpAddr;

pub use app::rcode_name as dns_rcode_name;
pub use util::{hex_string, tcp_flags_string};

#[derive(Debug, Clone, Serialize, Default)]
pub struct Field {
    pub name: String,
    pub value: String,
    pub offset: usize,
    pub len: usize,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct Layer {
    pub name: String,
    pub offset: usize,
    pub len: usize,
    pub fields: Vec<Field>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum AnomalyKind {
    /// Frame ended before a header it claims to contain (not a capture snaplen cut).
    Truncated,
    InvalidHeaderLength,
    InvalidLength,
    Malformed,
}

impl AnomalyKind {
    pub fn label(self) -> &'static str {
        match self {
            AnomalyKind::Truncated => "Truncated header",
            AnomalyKind::InvalidHeaderLength => "Invalid header length",
            AnomalyKind::InvalidLength => "Inconsistent length field",
            AnomalyKind::Malformed => "Malformed content",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Anomaly {
    pub kind: AnomalyKind,
    pub layer: String,
    pub detail: String,
}

#[derive(Debug, Clone, Default)]
pub struct IpMeta {
    pub version: u8,
    pub src: Option<IpAddr>,
    pub dst: Option<IpAddr>,
    pub proto: u8,
    pub ttl: u8,
    pub id: u32,
    pub total_len: u32,
    pub header_len: usize,
    pub dont_fragment: bool,
    pub more_fragments: bool,
    /// Fragment offset in bytes.
    pub frag_offset: u32,
    pub is_fragment: bool,
}

#[derive(Debug, Clone, Default)]
pub struct TcpMeta {
    pub sport: u16,
    pub dport: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u16,
    pub window: u16,
    /// Payload length derived from the IP length fields (not from captured bytes).
    pub payload_len: u32,
}

#[derive(Debug, Clone, Default)]
pub struct UdpMeta {
    pub sport: u16,
    pub dport: u16,
    pub length: u16,
}

#[derive(Debug, Clone, Default)]
pub struct IcmpMeta {
    pub v6: bool,
    pub typ: u8,
    pub code: u8,
    pub id: Option<u16>,
    pub seq: Option<u16>,
    /// For error messages: destination/protocol/port of the packet that triggered the error.
    pub orig_dst: Option<IpAddr>,
    pub orig_proto: Option<u8>,
    pub orig_dport: Option<u16>,
}

#[derive(Debug, Clone, Default)]
pub struct DnsMeta {
    pub id: u16,
    pub response: bool,
    pub rcode: u8,
    pub qname: String,
    pub qtype: u16,
    pub qdcount: u16,
    pub ancount: u16,
}

#[derive(Debug, Clone, Default)]
pub struct ArpMeta {
    pub op: u16,
    pub sender_ip: Option<IpAddr>,
    pub target_ip: Option<IpAddr>,
    pub sender_mac: String,
}

#[derive(Debug, Clone, Default)]
pub struct Meta {
    pub src_mac: Option<String>,
    pub dst_mac: Option<String>,
    pub ip: Option<IpMeta>,
    pub tcp: Option<TcpMeta>,
    pub udp: Option<UdpMeta>,
    pub icmp: Option<IcmpMeta>,
    pub dns: Option<DnsMeta>,
    pub arp: Option<ArpMeta>,
    pub dhcp_msg_type: Option<u8>,
}

#[derive(Debug, Clone, Default)]
pub struct Decoded {
    pub layers: Vec<Layer>,
    pub meta: Meta,
    pub anomalies: Vec<Anomaly>,
    /// Highest-level protocol label (e.g. "TCP", "DNS", "ARP").
    pub protocol: String,
    pub info: String,
    pub src: String,
    pub dst: String,
    pub sport: Option<u16>,
    pub dport: Option<u16>,
    /// Offset of the first byte after all decoded headers (start of application payload).
    pub payload_offset: usize,
}

/// Decoding context shared by the per-layer decoders.
pub(crate) struct Ctx<'a> {
    pub data: &'a [u8],
    /// True when the captured bytes cover the whole on-wire frame (not cut by snaplen).
    pub complete: bool,
    pub out: Decoded,
}

impl<'a> Ctx<'a> {
    fn new(data: &'a [u8], complete: bool) -> Self {
        Ctx {
            data,
            complete,
            out: Decoded {
                protocol: "Other".into(),
                ..Default::default()
            },
        }
    }

    pub fn anomaly(&mut self, kind: AnomalyKind, layer: &str, detail: impl Into<String>) {
        self.out.anomalies.push(Anomaly {
            kind,
            layer: layer.into(),
            detail: detail.into(),
        });
    }

    /// A header ran past the end of the frame. Only an anomaly if the capture holds the full frame.
    pub fn truncated(&mut self, layer: &str, detail: impl Into<String>) {
        if self.complete {
            self.anomaly(AnomalyKind::Truncated, layer, detail);
        }
    }

    pub fn push_layer(&mut self, name: &str, offset: usize, len: usize, fields: Vec<Field>) {
        self.out.layers.push(Layer {
            name: name.into(),
            offset,
            len,
            fields,
        });
    }

    pub fn set_top(&mut self, protocol: &str, info: String) {
        self.out.protocol = protocol.into();
        self.out.info = info;
    }
}

pub(crate) fn field(name: &str, value: impl Into<String>, offset: usize, len: usize) -> Field {
    Field {
        name: name.into(),
        value: value.into(),
        offset,
        len,
    }
}

/// Decode a captured frame. `orig_len` is the on-wire length (>= data.len() when snaplen cut it).
pub fn decode(data: &[u8], dlt: u32, orig_len: usize) -> Decoded {
    let mut ctx = Ctx::new(data, data.len() >= orig_len);
    match dlt {
        DLT_EN10MB => link::ethernet(&mut ctx),
        DLT_NULL => link::bsd_loopback(&mut ctx),
        DLT_RAW => link::raw_ip(&mut ctx),
        other => {
            ctx.set_top("Other", format!("Unsupported link type (DLT {other})"));
            ctx.out.payload_offset = 0;
        }
    }
    ctx.out
}

#[cfg(test)]
mod tests;
