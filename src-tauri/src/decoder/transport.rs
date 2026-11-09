//! TCP, UDP, ICMP and ICMPv6 decoding.

use super::util::*;
use super::{app, field, AnomalyKind, Ctx, IcmpMeta, TcpMeta, UdpMeta};
use crate::constants::*;

/// `claimed_end` is where the IP header says the datagram ends; the captured data may end earlier.
pub(super) fn decode(ctx: &mut Ctx, proto: u8, off: usize, claimed_end: usize, fragment: bool, v6: bool) {
    match proto {
        IPPROTO_TCP => tcp(ctx, off, claimed_end, fragment),
        IPPROTO_UDP => udp(ctx, off, claimed_end, fragment),
        IPPROTO_ICMP => icmp(ctx, off, claimed_end, false),
        IPPROTO_ICMPV6 => icmp(ctx, off, claimed_end, true),
        _ => {
            let _ = v6;
        }
    }
}

fn tcp(ctx: &mut Ctx, off: usize, claimed_end: usize, fragment: bool) {
    let d = ctx.data;
    let avail_end = claimed_end.min(d.len());
    if avail_end < off + 20 {
        ctx.truncated("TCP", format!("TCP header needs 20 bytes, {} available", avail_end.saturating_sub(off)));
        ctx.set_top("TCP", "Truncated TCP header".into());
        ctx.out.payload_offset = avail_end.max(off);
        return;
    }
    let sport = be16(d, off).unwrap_or(0);
    let dport = be16(d, off + 2).unwrap_or(0);
    let seq = be32(d, off + 4).unwrap_or(0);
    let ack = be32(d, off + 8).unwrap_or(0);
    let b12 = u8_at(d, off + 12).unwrap_or(0);
    let doff = ((b12 >> 4) as usize) * 4;
    let flags = (((b12 & 1) as u16) << 8) | u8_at(d, off + 13).unwrap_or(0) as u16;
    let window = be16(d, off + 14).unwrap_or(0);
    let csum = be16(d, off + 16).unwrap_or(0);
    let urg = be16(d, off + 18).unwrap_or(0);

    ctx.out.sport = Some(sport);
    ctx.out.dport = Some(dport);
    if doff < 20 {
        ctx.anomaly(AnomalyKind::InvalidHeaderLength, "TCP", format!("data offset {doff} bytes is below the 20-byte minimum"));
        ctx.set_top("TCP", format!("{sport} → {dport} invalid header length"));
        ctx.out.payload_offset = off + 20;
        return;
    }
    if off + doff > avail_end {
        ctx.truncated("TCP", format!("data offset {doff} bytes extends past the end of the packet"));
    }
    let hdr_end = (off + doff).min(avail_end);
    let payload_len = claimed_end.saturating_sub(off + doff) as u32;

    let mut fields = vec![
        field("Source port", sport.to_string(), off, 2),
        field("Destination port", dport.to_string(), off + 2, 2),
        field("Sequence number", seq.to_string(), off + 4, 4),
        field("Acknowledgment number", ack.to_string(), off + 8, 4),
        field("Header length", format!("{doff} bytes"), off + 12, 1),
        field("Flags", format!("0x{flags:03x} [{}]", tcp_flags_string(flags)), off + 12, 2),
        field("Window", window.to_string(), off + 14, 2),
        field("Checksum", format!("0x{csum:04x} (not validated: NIC checksum offload)"), off + 16, 2),
        field("Urgent pointer", urg.to_string(), off + 18, 2),
    ];
    let mut opt_info = String::new();
    if doff > 20 {
        let (opts, summary) = parse_tcp_options(d, off + 20, hdr_end);
        fields.push(field("Options", format!("{} bytes", doff - 20), off + 20, doff - 20));
        fields.extend(opts);
        opt_info = summary;
    }
    ctx.push_layer("TCP", off, hdr_end - off, fields);
    ctx.out.meta.tcp = Some(TcpMeta {
        sport,
        dport,
        seq,
        ack,
        flags,
        window,
        payload_len,
    });
    ctx.out.payload_offset = hdr_end;
    let mut info = format!("{sport} → {dport} [{}] Seq={seq}", tcp_flags_string(flags));
    if flags & TCP_ACK != 0 {
        info.push_str(&format!(" Ack={ack}"));
    }
    info.push_str(&format!(" Win={window} Len={payload_len}{opt_info}"));
    ctx.set_top("TCP", info);
    let _ = fragment;
}

fn parse_tcp_options(d: &[u8], start: usize, end: usize) -> (Vec<super::Field>, String) {
    let mut out = Vec::new();
    let mut summary = String::new();
    let mut i = start;
    let mut count = 0;
    while i < end && count < MAX_TCP_OPTIONS {
        count += 1;
        let kind = d[i];
        match kind {
            0 => break,
            1 => {
                i += 1;
                continue;
            }
            _ => {}
        }
        let Some(&len) = d.get(i + 1) else { break };
        let len = len as usize;
        if len < 2 || i + len > end {
            break;
        }
        match kind {
            2 if len == 4 => {
                let mss = be16(d, i + 2).unwrap_or(0);
                out.push(field("Option: MSS", mss.to_string(), i, len));
                summary.push_str(&format!(" MSS={mss}"));
            }
            3 if len == 3 => {
                let sh = d[i + 2];
                out.push(field("Option: Window scale", format!("shift {sh}"), i, len));
                summary.push_str(&format!(" WS={}", 1u32.checked_shl(sh as u32).unwrap_or(0)));
            }
            4 => {
                out.push(field("Option: SACK permitted", "yes", i, len));
                summary.push_str(" SACK_PERM");
            }
            5 => out.push(field("Option: SACK", format!("{} block(s)", (len - 2) / 8), i, len)),
            8 if len == 10 => {
                let tsval = be32(d, i + 2).unwrap_or(0);
                let tsecr = be32(d, i + 6).unwrap_or(0);
                out.push(field("Option: Timestamps", format!("TSval={tsval} TSecr={tsecr}"), i, len));
            }
            other => out.push(field("Option", format!("kind {other}, {len} bytes"), i, len)),
        }
        i += len;
    }
    (out, summary)
}

fn udp(ctx: &mut Ctx, off: usize, claimed_end: usize, fragment: bool) {
    let d = ctx.data;
    let avail_end = claimed_end.min(d.len());
    if avail_end < off + 8 {
        ctx.truncated("UDP", "UDP header needs 8 bytes");
        ctx.set_top("UDP", "Truncated UDP header".into());
        ctx.out.payload_offset = avail_end.max(off);
        return;
    }
    let sport = be16(d, off).unwrap_or(0);
    let dport = be16(d, off + 2).unwrap_or(0);
    let length = be16(d, off + 4).unwrap_or(0);
    let csum = be16(d, off + 6).unwrap_or(0);
    ctx.out.sport = Some(sport);
    ctx.out.dport = Some(dport);
    if length < 8 {
        ctx.anomaly(AnomalyKind::InvalidLength, "UDP", format!("length {length} is below the 8-byte header"));
    } else if !fragment && off + length as usize != claimed_end {
        ctx.anomaly(
            AnomalyKind::InvalidLength,
            "UDP",
            format!(
                "UDP length {length} does not match the {} bytes carried by IP",
                claimed_end.saturating_sub(off)
            ),
        );
    }
    ctx.push_layer(
        "UDP",
        off,
        8,
        vec![
            field("Source port", sport.to_string(), off, 2),
            field("Destination port", dport.to_string(), off + 2, 2),
            field("Length", length.to_string(), off + 4, 2),
            field("Checksum", format!("0x{csum:04x} (not validated: NIC checksum offload)"), off + 6, 2),
        ],
    );
    ctx.out.meta.udp = Some(UdpMeta { sport, dport, length });
    ctx.out.payload_offset = off + 8;
    let payload_len = claimed_end.saturating_sub(off + 8);
    ctx.set_top("UDP", format!("{sport} → {dport} Len={payload_len}"));
    if !fragment {
        app::udp_payload(ctx, off + 8, avail_end, sport, dport);
    }
}

fn icmp(ctx: &mut Ctx, off: usize, claimed_end: usize, v6: bool) {
    let d = ctx.data;
    let avail_end = claimed_end.min(d.len());
    let name = if v6 { "ICMPv6" } else { "ICMP" };
    if avail_end < off + 4 {
        ctx.truncated(name, "ICMP header needs at least 4 bytes");
        ctx.set_top(name, format!("Truncated {name} message"));
        ctx.out.payload_offset = avail_end.max(off);
        return;
    }
    let typ = d[off];
    let code = d[off + 1];
    let csum = be16(d, off + 2).unwrap_or(0);
    let mut meta = IcmpMeta {
        v6,
        typ,
        code,
        ..Default::default()
    };
    let desc = if v6 { icmpv6_name(typ, code) } else { icmp_name(typ, code) };
    let mut fields = vec![
        field("Type", format!("{typ} ({})", type_label(v6, typ)), off, 1),
        field("Code", format!("{code} ({desc})"), off + 1, 1),
        field("Checksum", format!("0x{csum:04x} (not validated: NIC checksum offload)"), off + 2, 2),
    ];
    let is_echo = if v6 { typ == 128 || typ == 129 } else { typ == 0 || typ == 8 };
    let is_error = if v6 { typ < 128 } else { matches!(typ, 3 | 4 | 5 | 11 | 12) };
    let mut info = desc.clone();
    if is_echo {
        if let (Some(id), Some(seq)) = (be16(d, off + 4), be16(d, off + 6)) {
            fields.push(field("Identifier", id.to_string(), off + 4, 2));
            fields.push(field("Sequence", seq.to_string(), off + 6, 2));
            meta.id = Some(id);
            meta.seq = Some(seq);
            info = format!("{desc} id={id} seq={seq}");
        } else {
            ctx.truncated(name, "echo header cut off");
        }
    } else if is_error {
        parse_embedded(d, off + 8, avail_end, v6, &mut meta);
        if let Some(dst) = meta.orig_dst {
            info = format!("{desc} (original destination {dst})");
        }
    }
    ctx.out.meta.icmp = Some(meta);
    ctx.push_layer(name, off, avail_end - off, fields);
    ctx.out.payload_offset = (off + 8).min(avail_end);
    ctx.set_top(name, info);
}

/// Pull the destination of the packet that triggered an ICMP error out of its embedded header.
fn parse_embedded(d: &[u8], start: usize, end: usize, v6: bool, meta: &mut IcmpMeta) {
    let Some(inner) = d.get(start..end) else { return };
    if v6 {
        if inner.len() >= 40 && inner[0] >> 4 == 6 {
            meta.orig_dst = ipv6_at(inner, 24).map(Into::into);
            meta.orig_proto = Some(inner[6]);
            if matches!(inner[6], IPPROTO_TCP | IPPROTO_UDP) {
                meta.orig_dport = be16(inner, 42);
            }
        }
    } else if inner.len() >= 20 && inner[0] >> 4 == 4 {
        let ihl = ((inner[0] & 0x0f) as usize) * 4;
        meta.orig_dst = ipv4_at(inner, 16).map(Into::into);
        meta.orig_proto = Some(inner[9]);
        if matches!(inner[9], IPPROTO_TCP | IPPROTO_UDP) && ihl >= 20 {
            meta.orig_dport = be16(inner, ihl + 2);
        }
    }
}

fn type_label(v6: bool, t: u8) -> &'static str {
    if v6 {
        match t {
            1 => "Destination Unreachable",
            2 => "Packet Too Big",
            3 => "Time Exceeded",
            4 => "Parameter Problem",
            128 => "Echo Request",
            129 => "Echo Reply",
            133 => "Router Solicitation",
            134 => "Router Advertisement",
            135 => "Neighbor Solicitation",
            136 => "Neighbor Advertisement",
            137 => "Redirect",
            _ => "Other",
        }
    } else {
        match t {
            0 => "Echo Reply",
            3 => "Destination Unreachable",
            4 => "Source Quench",
            5 => "Redirect",
            8 => "Echo Request",
            11 => "Time Exceeded",
            12 => "Parameter Problem",
            13 => "Timestamp",
            14 => "Timestamp Reply",
            _ => "Other",
        }
    }
}

pub fn icmp_name(t: u8, c: u8) -> String {
    match (t, c) {
        (0, _) => "Echo (ping) reply".into(),
        (8, _) => "Echo (ping) request".into(),
        (3, 0) => "Destination unreachable (network unreachable)".into(),
        (3, 1) => "Destination unreachable (host unreachable)".into(),
        (3, 2) => "Destination unreachable (protocol unreachable)".into(),
        (3, 3) => "Destination unreachable (port unreachable)".into(),
        (3, 4) => "Destination unreachable (fragmentation needed, DF set)".into(),
        (3, 9) | (3, 10) | (3, 13) => "Destination unreachable (administratively prohibited)".into(),
        (3, c) => format!("Destination unreachable (code {c})"),
        (5, _) => "Redirect".into(),
        (11, 0) => "Time exceeded (TTL expired in transit)".into(),
        (11, 1) => "Time exceeded (fragment reassembly)".into(),
        (12, _) => "Parameter problem".into(),
        (t, c) => format!("ICMP type {t} code {c}"),
    }
}

pub fn icmpv6_name(t: u8, c: u8) -> String {
    match (t, c) {
        (1, 0) => "Destination unreachable (no route)".into(),
        (1, 1) => "Destination unreachable (administratively prohibited)".into(),
        (1, 3) => "Destination unreachable (address unreachable)".into(),
        (1, 4) => "Destination unreachable (port unreachable)".into(),
        (1, c) => format!("Destination unreachable (code {c})"),
        (2, _) => "Packet too big".into(),
        (3, 0) => "Time exceeded (hop limit)".into(),
        (3, _) => "Time exceeded (reassembly)".into(),
        (4, _) => "Parameter problem".into(),
        (128, _) => "Echo (ping) request".into(),
        (129, _) => "Echo (ping) reply".into(),
        (133, _) => "Router solicitation".into(),
        (134, _) => "Router advertisement".into(),
        (135, _) => "Neighbor solicitation".into(),
        (136, _) => "Neighbor advertisement".into(),
        (137, _) => "Redirect".into(),
        (t, c) => format!("ICMPv6 type {t} code {c}"),
    }
}
