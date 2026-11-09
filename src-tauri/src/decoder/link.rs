//! Link-layer decoding: Ethernet II (with 802.1Q), BSD loopback and raw IP.

use super::util::*;
use super::{field, network, AnomalyKind, ArpMeta, Ctx};
use crate::constants::*;

pub(super) fn ethernet(ctx: &mut Ctx) {
    let d = ctx.data;
    if d.len() < 14 {
        ctx.truncated("Ethernet", format!("frame is {} bytes, Ethernet header needs 14", d.len()));
        ctx.set_top("Ethernet", format!("Truncated frame ({} bytes)", d.len()));
        ctx.out.payload_offset = d.len();
        return;
    }
    let dst = mac_at(d, 0).unwrap_or_default();
    let src = mac_at(d, 6).unwrap_or_default();
    let mut ethertype = be16(d, 12).unwrap_or(0);
    let mut off = 14;
    let mut fields = vec![
        field("Destination", dst.clone(), 0, 6),
        field("Source", src.clone(), 6, 6),
    ];
    // Up to two stacked VLAN tags (802.1Q / QinQ).
    let mut tags = 0;
    while ethertype == ETHERTYPE_VLAN && tags < 2 {
        let Some(tci) = be16(d, off) else { break };
        let Some(inner) = be16(d, off + 2) else { break };
        fields.push(field(
            "VLAN",
            format!("ID {} priority {}", tci & 0x0fff, tci >> 13),
            off,
            2,
        ));
        ethertype = inner;
        off += 4;
        tags += 1;
    }
    fields.push(field(
        "Type",
        format!("{} (0x{ethertype:04x})", ethertype_name(ethertype)),
        off - 2,
        2,
    ));
    ctx.out.meta.src_mac = Some(src.clone());
    ctx.out.meta.dst_mac = Some(dst.clone());
    ctx.out.src = src;
    ctx.out.dst = dst;
    ctx.push_layer("Ethernet II", 0, off, fields);
    ctx.out.payload_offset = off;
    dispatch(ctx, ethertype, off);
}

pub(super) fn bsd_loopback(ctx: &mut Ctx) {
    let d = ctx.data;
    let Some(fam_bytes) = d.get(0..4) else {
        ctx.set_top("Loopback", "Truncated loopback frame".into());
        return;
    };
    // The family is written in the capturing host's byte order (little-endian on Windows/x86).
    let fam_le = u32::from_le_bytes([fam_bytes[0], fam_bytes[1], fam_bytes[2], fam_bytes[3]]);
    let ethertype = match fam_le {
        2 => ETHERTYPE_IPV4,
        23 | 24 | 28 | 30 => ETHERTYPE_IPV6,
        _ => 0,
    };
    ctx.push_layer(
        "Null/Loopback",
        0,
        4,
        vec![field("Family", format!("{fam_le}"), 0, 4)],
    );
    ctx.out.payload_offset = 4;
    dispatch(ctx, ethertype, 4);
}

pub(super) fn raw_ip(ctx: &mut Ctx) {
    let ethertype = match ctx.data.first().map(|b| b >> 4) {
        Some(4) => ETHERTYPE_IPV4,
        Some(6) => ETHERTYPE_IPV6,
        _ => 0,
    };
    dispatch(ctx, ethertype, 0);
}

fn dispatch(ctx: &mut Ctx, ethertype: u16, off: usize) {
    match ethertype {
        ETHERTYPE_IPV4 => network::ipv4(ctx, off),
        ETHERTYPE_IPV6 => network::ipv6(ctx, off),
        ETHERTYPE_ARP => arp(ctx, off),
        other => {
            let proto = if ctx.out.layers.is_empty() { "Other" } else { "Ethernet" };
            ctx.set_top(proto, format!("{} (0x{other:04x})", ethertype_name(other)));
        }
    }
}

fn ethertype_name(t: u16) -> &'static str {
    match t {
        ETHERTYPE_IPV4 => "IPv4",
        ETHERTYPE_IPV6 => "IPv6",
        ETHERTYPE_ARP => "ARP",
        ETHERTYPE_VLAN => "VLAN",
        0x88CC => "LLDP",
        0x8863 | 0x8864 => "PPPoE",
        _ => "Unknown EtherType",
    }
}

fn arp(ctx: &mut Ctx, off: usize) {
    let d = ctx.data;
    if d.len() < off + 8 {
        ctx.truncated("ARP", "ARP header needs at least 8 bytes");
        ctx.set_top("ARP", "Truncated ARP packet".into());
        return;
    }
    let htype = be16(d, off).unwrap_or(0);
    let ptype = be16(d, off + 2).unwrap_or(0);
    let hlen = u8_at(d, off + 4).unwrap_or(0) as usize;
    let plen = u8_at(d, off + 5).unwrap_or(0) as usize;
    let op = be16(d, off + 6).unwrap_or(0);
    let op_name = match op {
        1 => "request",
        2 => "reply",
        _ => "unknown operation",
    };
    let mut fields = vec![
        field("Hardware type", htype.to_string(), off, 2),
        field("Protocol type", format!("0x{ptype:04x}"), off + 2, 2),
        field("Hardware size", hlen.to_string(), off + 4, 1),
        field("Protocol size", plen.to_string(), off + 5, 1),
        field("Operation", format!("{op} ({op_name})"), off + 6, 2),
    ];
    let mut meta = ArpMeta {
        op,
        ..Default::default()
    };
    let mut total = 8;
    let mut info = format!("ARP {op_name}");
    if hlen == 6 && plen == 4 {
        total = 8 + 2 * (hlen + plen);
        if d.len() < off + total {
            ctx.truncated("ARP", "ARP payload shorter than its declared address sizes");
        } else {
            let sha = mac_at(d, off + 8).unwrap_or_default();
            let spa = ipv4_at(d, off + 14);
            let tha = mac_at(d, off + 18).unwrap_or_default();
            let tpa = ipv4_at(d, off + 24);
            fields.push(field("Sender MAC", sha.clone(), off + 8, 6));
            fields.push(field("Sender IP", spa.map(|a| a.to_string()).unwrap_or_default(), off + 14, 4));
            fields.push(field("Target MAC", tha, off + 18, 6));
            fields.push(field("Target IP", tpa.map(|a| a.to_string()).unwrap_or_default(), off + 24, 4));
            meta.sender_mac = sha;
            meta.sender_ip = spa.map(Into::into);
            meta.target_ip = tpa.map(Into::into);
            if let (Some(s), Some(t)) = (spa, tpa) {
                info = match op {
                    1 if s == t => format!("Gratuitous ARP for {t}"),
                    1 => format!("Who has {t}? Tell {s}"),
                    2 => format!("{s} is at {}", meta.sender_mac),
                    _ => info,
                };
                ctx.out.src = s.to_string();
                ctx.out.dst = t.to_string();
            }
        }
    } else if hlen != 0 || plen != 0 {
        ctx.anomaly(
            AnomalyKind::Malformed,
            "ARP",
            format!("unexpected address sizes hlen={hlen} plen={plen} for Ethernet/IPv4 ARP"),
        );
    }
    ctx.out.meta.arp = Some(meta);
    ctx.push_layer("ARP", off, total.min(d.len().saturating_sub(off)), fields);
    ctx.out.payload_offset = (off + total).min(d.len());
    ctx.set_top("ARP", info);
}
