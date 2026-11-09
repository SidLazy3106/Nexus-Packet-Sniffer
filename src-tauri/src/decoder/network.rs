//! IPv4 and IPv6 decoding.

use super::util::*;
use super::{field, transport, AnomalyKind, Ctx, IpMeta};
use crate::constants::*;
use std::net::IpAddr;

pub(super) fn ipv4(ctx: &mut Ctx, off: usize) {
    let d = ctx.data;
    let Some(vihl) = u8_at(d, off) else {
        ctx.truncated("IPv4", "no bytes available for IPv4 header");
        ctx.set_top("IPv4", "Truncated IPv4 packet".into());
        return;
    };
    let version = vihl >> 4;
    let ihl = ((vihl & 0x0f) as usize) * 4;
    if version != 4 {
        ctx.anomaly(AnomalyKind::Malformed, "IPv4", format!("version field is {version}, expected 4"));
    }
    if ihl < 20 {
        ctx.anomaly(AnomalyKind::InvalidHeaderLength, "IPv4", format!("IHL {ihl} bytes is below the 20-byte minimum"));
        ctx.set_top("IPv4", format!("Invalid header length ({ihl} bytes)"));
        ctx.out.payload_offset = off;
        return;
    }
    if d.len() < off + ihl {
        ctx.truncated("IPv4", format!("header needs {ihl} bytes, only {} available", d.len() - off.min(d.len())));
        ctx.set_top("IPv4", "Truncated IPv4 header".into());
        ctx.out.payload_offset = d.len();
        return;
    }
    let tos = u8_at(d, off + 1).unwrap_or(0);
    let total_len = be16(d, off + 2).unwrap_or(0) as usize;
    let id = be16(d, off + 4).unwrap_or(0);
    let ff = be16(d, off + 6).unwrap_or(0);
    let ttl = u8_at(d, off + 8).unwrap_or(0);
    let proto = u8_at(d, off + 9).unwrap_or(0);
    let csum = be16(d, off + 10).unwrap_or(0);
    let src = ipv4_at(d, off + 12).map(IpAddr::from);
    let dst = ipv4_at(d, off + 16).map(IpAddr::from);

    let dont_fragment = ff & 0x4000 != 0;
    let more_fragments = ff & 0x2000 != 0;
    let frag_offset = ((ff & 0x1fff) as u32) * 8;
    let is_fragment = more_fragments || frag_offset > 0;

    // Claimed end of the IP datagram. Ethernet padding beyond total_len is ignored.
    let mut claimed_end = off + total_len;
    if total_len < ihl {
        ctx.anomaly(
            AnomalyKind::InvalidLength,
            "IPv4",
            format!("total length {total_len} is smaller than header length {ihl}"),
        );
        claimed_end = d.len();
    } else if claimed_end > d.len() && ctx.complete {
        ctx.anomaly(
            AnomalyKind::InvalidLength,
            "IPv4",
            format!("total length {total_len} exceeds the {} bytes present in the frame", d.len() - off),
        );
        claimed_end = d.len();
    }

    let src_s = src.map(ip_str).unwrap_or_default();
    let dst_s = dst.map(ip_str).unwrap_or_default();
    let mut fields = vec![
        field("Version", "4", off, 1),
        field("Header length", format!("{ihl} bytes"), off, 1),
        field("DSCP/ECN", format!("0x{tos:02x}"), off + 1, 1),
        field("Total length", total_len.to_string(), off + 2, 2),
        field("Identification", format!("0x{id:04x} ({id})"), off + 4, 2),
        field(
            "Flags",
            format!(
                "{}{}",
                if dont_fragment { "Don't Fragment " } else { "" },
                if more_fragments { "More Fragments" } else { "" }
            )
            .trim()
            .to_string()
            .pipe_empty("none"),
            off + 6,
            2,
        ),
        field("Fragment offset", format!("{frag_offset} bytes"), off + 6, 2),
        field("TTL", ttl.to_string(), off + 8, 1),
        field("Protocol", format!("{} ({proto})", proto_name(proto)), off + 9, 1),
        field("Header checksum", format!("0x{csum:04x} (not validated: NIC checksum offload)"), off + 10, 2),
        field("Source", src_s.clone(), off + 12, 4),
        field("Destination", dst_s.clone(), off + 16, 4),
    ];
    if ihl > 20 {
        fields.push(field("Options", format!("{} bytes", ihl - 20), off + 20, ihl - 20));
    }
    ctx.push_layer("IPv4", off, ihl, fields);
    ctx.out.src = src_s;
    ctx.out.dst = dst_s;
    ctx.out.meta.ip = Some(IpMeta {
        version: 4,
        src,
        dst,
        proto,
        ttl,
        id: id as u32,
        total_len: total_len as u32,
        header_len: ihl,
        dont_fragment,
        more_fragments,
        frag_offset,
        is_fragment,
    });
    ctx.out.payload_offset = off + ihl;
    let first = frag_offset == 0;
    ctx.set_top(
        "IPv4",
        format!("{} → {} {}", ctx.out.src, ctx.out.dst, proto_name(proto)),
    );
    if is_fragment {
        ctx.set_top(
            "IPv4",
            format!(
                "Fragmented IP packet ({}, offset={frag_offset}, id=0x{id:04x}, more={})",
                proto_name(proto),
                more_fragments
            ),
        );
    }
    if first {
        let (frag_proto, frag_info) = (ctx.out.protocol.clone(), ctx.out.info.clone());
        transport::decode(ctx, proto, off + ihl, claimed_end, is_fragment, false);
        if is_fragment {
            // The fragment description is more truthful than a transport summary of partial data.
            ctx.set_top(&frag_proto, frag_info);
        }
    }
}

pub(super) fn ipv6(ctx: &mut Ctx, off: usize) {
    let d = ctx.data;
    if d.len() < off + 40 {
        ctx.truncated("IPv6", "IPv6 header needs 40 bytes");
        ctx.set_top("IPv6", "Truncated IPv6 header".into());
        ctx.out.payload_offset = d.len();
        return;
    }
    let vtf = be32(d, off).unwrap_or(0);
    let version = (vtf >> 28) as u8;
    let tclass = ((vtf >> 20) & 0xff) as u8;
    let flow = vtf & 0x000f_ffff;
    let payload_len = be16(d, off + 4).unwrap_or(0) as usize;
    let mut next = u8_at(d, off + 6).unwrap_or(0);
    let hop = u8_at(d, off + 7).unwrap_or(0);
    let src = ipv6_at(d, off + 8).map(IpAddr::from);
    let dst = ipv6_at(d, off + 24).map(IpAddr::from);
    if version != 6 {
        ctx.anomaly(AnomalyKind::Malformed, "IPv6", format!("version field is {version}, expected 6"));
    }
    let src_s = src.map(ip_str).unwrap_or_default();
    let dst_s = dst.map(ip_str).unwrap_or_default();
    let mut claimed_end = off + 40 + payload_len;
    if payload_len > 0 && claimed_end > d.len() && ctx.complete {
        ctx.anomaly(
            AnomalyKind::InvalidLength,
            "IPv6",
            format!("payload length {payload_len} exceeds the {} bytes present", d.len() - off - 40),
        );
        claimed_end = d.len();
    }
    if payload_len == 0 {
        claimed_end = d.len();
    }
    ctx.push_layer(
        "IPv6",
        off,
        40,
        vec![
            field("Version", "6", off, 1),
            field("Traffic class", format!("0x{tclass:02x}"), off, 2),
            field("Flow label", format!("0x{flow:05x}"), off + 1, 3),
            field("Payload length", payload_len.to_string(), off + 4, 2),
            field("Next header", format!("{} ({next})", proto_name(next)), off + 6, 1),
            field("Hop limit", hop.to_string(), off + 7, 1),
            field("Source", src_s.clone(), off + 8, 16),
            field("Destination", dst_s.clone(), off + 24, 16),
        ],
    );
    ctx.out.src = src_s;
    ctx.out.dst = dst_s;

    // Walk extension headers (bounded).
    let mut cur = off + 40;
    let mut is_fragment = false;
    let mut more_fragments = false;
    let mut frag_offset = 0u32;
    let mut frag_id = 0u32;
    let mut first_fragment = true;
    for _ in 0..MAX_IPV6_EXT_HEADERS {
        match next {
            IPPROTO_HOPOPT | IPPROTO_ROUTING | IPPROTO_DSTOPTS => {
                let (Some(nh), Some(len)) = (u8_at(d, cur), u8_at(d, cur + 1)) else {
                    ctx.truncated("IPv6", "extension header cut off");
                    break;
                };
                let total = (len as usize + 1) * 8;
                ctx.push_layer(
                    &format!("IPv6 ext: {}", proto_name(next)),
                    cur,
                    total.min(d.len().saturating_sub(cur)),
                    vec![field("Next header", format!("{} ({nh})", proto_name(nh)), cur, 1)],
                );
                next = nh;
                cur += total;
            }
            IPPROTO_FRAGMENT => {
                let (Some(nh), Some(fo), Some(id)) = (u8_at(d, cur), be16(d, cur + 2), be32(d, cur + 4)) else {
                    ctx.truncated("IPv6", "fragment header cut off");
                    break;
                };
                is_fragment = true;
                more_fragments = fo & 1 != 0;
                frag_offset = ((fo >> 3) as u32) * 8;
                frag_id = id;
                first_fragment = frag_offset == 0;
                ctx.push_layer(
                    "IPv6 ext: Fragment",
                    cur,
                    8,
                    vec![
                        field("Next header", format!("{} ({nh})", proto_name(nh)), cur, 1),
                        field("Fragment offset", format!("{frag_offset} bytes"), cur + 2, 2),
                        field("More fragments", more_fragments.to_string(), cur + 3, 1),
                        field("Identification", format!("0x{id:08x}"), cur + 4, 4),
                    ],
                );
                next = nh;
                cur += 8;
            }
            _ => break,
        }
    }
    ctx.out.meta.ip = Some(IpMeta {
        version: 6,
        src,
        dst,
        proto: next,
        ttl: hop,
        id: frag_id,
        total_len: (40 + payload_len) as u32,
        header_len: cur - off,
        dont_fragment: false,
        more_fragments,
        frag_offset,
        is_fragment,
    });
    ctx.out.payload_offset = cur.min(d.len());
    ctx.set_top("IPv6", format!("{} → {} {}", ctx.out.src, ctx.out.dst, proto_name(next)));
    if is_fragment {
        ctx.set_top(
            "IPv6",
            format!(
                "Fragmented IPv6 packet ({}, offset={frag_offset}, id=0x{frag_id:08x}, more={more_fragments})",
                proto_name(next)
            ),
        );
    }
    if first_fragment && next != IPPROTO_NONE {
        let (frag_proto, frag_info) = (ctx.out.protocol.clone(), ctx.out.info.clone());
        transport::decode(ctx, next, cur, claimed_end, is_fragment, true);
        if is_fragment {
            ctx.set_top(&frag_proto, frag_info);
        }
    }
}

/// Small helper so empty strings can fall back to a label.
trait PipeEmpty {
    fn pipe_empty(self, fallback: &str) -> String;
}
impl PipeEmpty for String {
    fn pipe_empty(self, fallback: &str) -> String {
        if self.is_empty() {
            fallback.into()
        } else {
            self
        }
    }
}
