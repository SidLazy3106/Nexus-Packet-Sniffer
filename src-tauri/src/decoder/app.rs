//! Application-layer decoding: DNS and DHCP metadata. No payload content beyond protocol headers
//! is interpreted, and nothing is decrypted.

use super::util::*;
use super::{field, AnomalyKind, Ctx, DnsMeta};
use crate::constants::*;

pub(super) fn udp_payload(ctx: &mut Ctx, off: usize, end: usize, sport: u16, dport: u16) {
    let is_dns = [sport, dport].iter().any(|p| *p == PORT_DNS || *p == PORT_MDNS);
    let is_dhcp = (sport == PORT_DHCP_SERVER && dport == PORT_DHCP_CLIENT)
        || (sport == PORT_DHCP_CLIENT && dport == PORT_DHCP_SERVER);
    if end <= off {
        return;
    }
    if is_dns {
        dns(ctx, off, end, sport == PORT_DNS || sport == PORT_MDNS && dport != PORT_DNS);
    } else if is_dhcp {
        dhcp(ctx, off, end);
    }
}

fn dns(ctx: &mut Ctx, off: usize, end: usize, _from_server: bool) {
    let Some(d) = ctx.data.get(off..end) else { return };
    if d.len() < 12 {
        ctx.truncated("DNS", format!("DNS header needs 12 bytes, {} present", d.len()));
        return;
    }
    let id = be16(d, 0).unwrap_or(0);
    let flags = be16(d, 2).unwrap_or(0);
    let qd = be16(d, 4).unwrap_or(0);
    let an = be16(d, 6).unwrap_or(0);
    let ns = be16(d, 8).unwrap_or(0);
    let ar = be16(d, 10).unwrap_or(0);
    let response = flags & 0x8000 != 0;
    let opcode = (flags >> 11) & 0xf;
    let rcode = (flags & 0xf) as u8;

    // Plausibility check: counts that cannot fit in the packet indicate a non-DNS payload.
    let min_needed = (qd as usize) * 5 + (an as usize) * 11;
    if min_needed > d.len() {
        // A capture cut short by snaplen/retention legitimately holds fewer bytes than the counts imply.
        if ctx.complete {
            ctx.anomaly(
                AnomalyKind::Malformed,
                "DNS",
                format!("record counts (qd={qd}, an={an}) cannot fit in {} bytes", d.len()),
            );
        }
        return;
    }

    let mut qname = String::new();
    let mut qtype = 0u16;
    let mut fields = vec![
        field("Transaction ID", format!("0x{id:04x}"), off, 2),
        field("Type", if response { "Response" } else { "Query" }, off + 2, 2),
        field("Opcode", opcode.to_string(), off + 2, 2),
        field("Response code", format!("{rcode} ({})", rcode_name(rcode)), off + 2, 2),
        field("Questions", qd.to_string(), off + 4, 2),
        field("Answer RRs", an.to_string(), off + 6, 2),
        field("Authority RRs", ns.to_string(), off + 8, 2),
        field("Additional RRs", ar.to_string(), off + 10, 2),
    ];
    if qd > 0 {
        match read_name(d, 12) {
            Some((name, next)) => {
                if let (Some(t), Some(c)) = (be16(d, next), be16(d, next + 2)) {
                    qtype = t;
                    fields.push(field(
                        "Question",
                        format!("{name} type {} class {c}", qtype_name(t)),
                        off + 12,
                        next + 4 - 12,
                    ));
                } else {
                    ctx.anomaly(AnomalyKind::Truncated, "DNS", "question type/class cut off");
                }
                qname = name;
            }
            None => ctx.anomaly(AnomalyKind::Malformed, "DNS", "question name is malformed"),
        }
    }
    let info = if response {
        format!(
            "Standard query response 0x{id:04x} {} {} {}",
            rcode_name(rcode),
            qtype_name(qtype),
            qname
        )
    } else {
        format!("Standard query 0x{id:04x} {} {}", qtype_name(qtype), qname)
    };
    ctx.push_layer("DNS", off, end - off, fields);
    ctx.out.meta.dns = Some(DnsMeta {
        id,
        response,
        rcode,
        qname,
        qtype,
        qdcount: qd,
        ancount: an,
    });
    ctx.out.payload_offset = end;
    ctx.set_top("DNS", info.trim().to_string());
}

/// Read a (possibly compressed) domain name. Returns the name and the offset just past it in the
/// original (non-jumped) position. Pointer jumps and length are bounded.
pub(super) fn read_name(d: &[u8], start: usize) -> Option<(String, usize)> {
    let mut pos = start;
    let mut name = String::new();
    let mut end_after: Option<usize> = None;
    let mut jumps = 0;
    loop {
        let len = *d.get(pos)? as usize;
        if len == 0 {
            let after = end_after.unwrap_or(pos + 1);
            if name.is_empty() {
                name.push('.');
            }
            return Some((name, after));
        }
        if len & 0xC0 == 0xC0 {
            let lo = *d.get(pos + 1)? as usize;
            let ptr = ((len & 0x3F) << 8) | lo;
            if end_after.is_none() {
                end_after = Some(pos + 2);
            }
            jumps += 1;
            if jumps > MAX_DNS_POINTER_JUMPS || ptr >= d.len() {
                return None;
            }
            pos = ptr;
            continue;
        }
        if len > 63 {
            return None;
        }
        let label = d.get(pos + 1..pos + 1 + len)?;
        if !name.is_empty() {
            name.push('.');
        }
        for &b in label {
            name.push(if b.is_ascii_graphic() { b as char } else { '?' });
        }
        if name.len() > MAX_DNS_NAME_LEN {
            return None;
        }
        pos += 1 + len;
    }
}

pub fn rcode_name(r: u8) -> &'static str {
    match r {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        _ => "OTHER",
    }
}

fn qtype_name(t: u16) -> String {
    match t {
        1 => "A".into(),
        2 => "NS".into(),
        5 => "CNAME".into(),
        6 => "SOA".into(),
        12 => "PTR".into(),
        15 => "MX".into(),
        16 => "TXT".into(),
        28 => "AAAA".into(),
        33 => "SRV".into(),
        65 => "HTTPS".into(),
        255 => "ANY".into(),
        0 => "?".into(),
        n => format!("TYPE{n}"),
    }
}

fn dhcp(ctx: &mut Ctx, off: usize, end: usize) {
    let Some(d) = ctx.data.get(off..end) else { return };
    if d.len() < 240 {
        ctx.truncated("DHCP", format!("BOOTP message needs 240 bytes, {} present", d.len()));
        return;
    }
    if d[236..240] != [0x63, 0x82, 0x53, 0x63] {
        ctx.anomaly(AnomalyKind::Malformed, "DHCP", "missing DHCP magic cookie");
        return;
    }
    let op = d[0];
    let xid = be32(d, 4).unwrap_or(0);
    let yiaddr = ipv4_at(d, 16).map(|a| a.to_string()).unwrap_or_default();
    let chaddr = mac_at(d, 28).unwrap_or_default();
    let mut msg_type = None;
    let mut i = 240;
    while i < d.len() {
        let code = d[i];
        if code == 255 {
            break;
        }
        if code == 0 {
            i += 1;
            continue;
        }
        let Some(&len) = d.get(i + 1) else { break };
        if code == 53 && len == 1 {
            msg_type = d.get(i + 2).copied();
        }
        i += 2 + len as usize;
    }
    let type_name = match msg_type {
        Some(1) => "Discover",
        Some(2) => "Offer",
        Some(3) => "Request",
        Some(4) => "Decline",
        Some(5) => "ACK",
        Some(6) => "NAK",
        Some(7) => "Release",
        Some(8) => "Inform",
        _ => "Unknown",
    };
    ctx.push_layer(
        "DHCP",
        off,
        end - off,
        vec![
            field("Message type", type_name, off, 1),
            field("Op", if op == 1 { "BOOTREQUEST" } else { "BOOTREPLY" }, off, 1),
            field("Transaction ID", format!("0x{xid:08x}"), off + 4, 4),
            field("Your IP", yiaddr, off + 16, 4),
            field("Client MAC", chaddr, off + 28, 6),
        ],
    );
    ctx.out.meta.dhcp_msg_type = msg_type;
    ctx.out.payload_offset = end;
    ctx.set_top("DHCP", format!("DHCP {type_name} - Transaction ID 0x{xid:08x}"));
}
