use crate::constants::*;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub fn u8_at(d: &[u8], o: usize) -> Option<u8> {
    d.get(o).copied()
}

pub fn be16(d: &[u8], o: usize) -> Option<u16> {
    let b = d.get(o..o.checked_add(2)?)?;
    Some(u16::from_be_bytes([b[0], b[1]]))
}

pub fn be32(d: &[u8], o: usize) -> Option<u32> {
    let b = d.get(o..o.checked_add(4)?)?;
    Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

pub fn ipv4_at(d: &[u8], o: usize) -> Option<Ipv4Addr> {
    let b = d.get(o..o.checked_add(4)?)?;
    Some(Ipv4Addr::new(b[0], b[1], b[2], b[3]))
}

pub fn ipv6_at(d: &[u8], o: usize) -> Option<Ipv6Addr> {
    let b: [u8; 16] = d.get(o..o.checked_add(16)?)?.try_into().ok()?;
    Some(Ipv6Addr::from(b))
}

pub fn mac_at(d: &[u8], o: usize) -> Option<String> {
    let b = d.get(o..o.checked_add(6)?)?;
    Some(
        b.iter()
            .map(|x| format!("{x:02x}"))
            .collect::<Vec<_>>()
            .join(":"),
    )
}

pub fn ip_str(ip: IpAddr) -> String {
    ip.to_string()
}

pub fn hex_string(d: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(d.len() * 2);
    for b in d {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// Wireshark-style flag list, e.g. "SYN, ACK".
pub fn tcp_flags_string(flags: u16) -> String {
    const NAMES: [(u16, &str); 8] = [
        (TCP_SYN, "SYN"),
        (TCP_FIN, "FIN"),
        (TCP_RST, "RST"),
        (TCP_PSH, "PSH"),
        (TCP_ACK, "ACK"),
        (TCP_URG, "URG"),
        (TCP_ECE, "ECE"),
        (TCP_CWR, "CWR"),
    ];
    let parts: Vec<&str> = NAMES
        .iter()
        .filter(|(bit, _)| flags & bit != 0)
        .map(|(_, n)| *n)
        .collect();
    if parts.is_empty() {
        "none".into()
    } else {
        parts.join(", ")
    }
}

pub fn proto_name(p: u8) -> String {
    match p {
        IPPROTO_ICMP => "ICMP".into(),
        IPPROTO_TCP => "TCP".into(),
        IPPROTO_UDP => "UDP".into(),
        IPPROTO_ICMPV6 => "ICMPv6".into(),
        IPPROTO_HOPOPT => "HOPOPT".into(),
        IPPROTO_ROUTING => "IPv6-Route".into(),
        IPPROTO_FRAGMENT => "IPv6-Frag".into(),
        IPPROTO_NONE => "IPv6-NoNxt".into(),
        IPPROTO_DSTOPTS => "IPv6-Opts".into(),
        other => format!("proto {other}"),
    }
}
