use super::*;
use crate::testutil::*;

const A: [u8; 4] = [10, 0, 0, 1];
const B: [u8; 4] = [10, 0, 0, 2];

fn dec(data: &[u8]) -> Decoded {
    decode(data, DLT_EN10MB, data.len())
}

#[test]
fn ipv4_tcp_syn_fields_decode_exactly() {
    let mut t = Tcp::new(51234, 443, 1000, 0, SYN, 0);
    t.options = vec![2, 4, 0x05, 0xb4, 4, 2, 3, 3, 7];
    let d = dec(&tcp_frame(A, B, &t));
    assert!(d.anomalies.is_empty(), "{:?}", d.anomalies);
    assert_eq!(d.protocol, "TCP");
    assert_eq!(d.src, "10.0.0.1");
    assert_eq!(d.dst, "10.0.0.2");
    assert_eq!((d.sport, d.dport), (Some(51234), Some(443)));
    let ip = d.meta.ip.as_ref().unwrap();
    assert_eq!((ip.version, ip.ttl, ip.id, ip.proto), (4, 64, 0x1234, 6));
    assert!(ip.dont_fragment && !ip.is_fragment);
    let tcp = d.meta.tcp.as_ref().unwrap();
    assert_eq!((tcp.seq, tcp.ack, tcp.window, tcp.payload_len), (1000, 0, 65535, 0));
    assert_eq!(tcp.flags, TCP_SYN);
    assert!(d.info.contains("[SYN]") && d.info.contains("MSS=1460") && d.info.contains("WS=128"), "{}", d.info);
    assert_eq!(d.layers.iter().map(|l| l.name.as_str()).collect::<Vec<_>>(), ["Ethernet II", "IPv4", "TCP"]);
}

#[test]
fn tcp_flags_interpretation() {
    assert_eq!(tcp_flags_string(TCP_SYN | TCP_ACK), "SYN, ACK");
    assert_eq!(tcp_flags_string(TCP_FIN | TCP_ACK | TCP_PSH), "FIN, PSH, ACK");
    assert_eq!(tcp_flags_string(TCP_RST), "RST");
    assert_eq!(tcp_flags_string(0), "none");
    let d = dec(&tcp_frame(A, B, &Tcp::new(1, 2, 0, 0, 0x3f, 0)));
    assert_eq!(d.meta.tcp.unwrap().flags, 0x3f);
}

#[test]
fn tcp_payload_length_comes_from_ip_length() {
    let d = dec(&tcp_frame(A, B, &Tcp::new(80, 5000, 1, 1, ACK | PSH, 100)));
    assert_eq!(d.meta.tcp.as_ref().unwrap().payload_len, 100);
    assert_eq!(d.payload_offset, 14 + 20 + 20);
}

#[test]
fn ethernet_padding_is_not_counted_as_payload() {
    let mut f = tcp_frame(A, B, &Tcp::new(80, 5000, 1, 1, ACK, 0));
    f.extend_from_slice(&[0; 6]); // trailer padding
    let d = dec(&f);
    assert_eq!(d.meta.tcp.unwrap().payload_len, 0);
    assert!(d.anomalies.is_empty());
}

#[test]
fn udp_decodes_and_validates_length() {
    let d = dec(&udp_payload_frame(A, B, 40000, 9999, b"hello"));
    assert_eq!(d.protocol, "UDP");
    assert!(d.anomalies.is_empty());
    assert_eq!(d.meta.udp.as_ref().unwrap().length, 13);

    // corrupt the UDP length field (frame offset 14+20+4)
    let mut f = udp_payload_frame(A, B, 40000, 9999, b"hello");
    f[14 + 20 + 4] = 0;
    f[14 + 20 + 5] = 200;
    let d = dec(&f);
    assert!(d.anomalies.iter().any(|a| a.kind == AnomalyKind::InvalidLength && a.layer == "UDP"));
}

#[test]
fn ipv6_tcp_decodes() {
    let d = dec(&tcp6_frame(&Tcp::new(1234, 80, 7, 0, SYN, 0)));
    assert!(d.anomalies.is_empty(), "{:?}", d.anomalies);
    assert_eq!(d.protocol, "TCP");
    assert_eq!(d.src, "2001::1");
    assert_eq!(d.dst, "2001::2");
    let ip = d.meta.ip.unwrap();
    assert_eq!((ip.version, ip.ttl), (6, 60));
}

#[test]
fn ipv6_extension_headers_and_fragment() {
    // hop-by-hop (8 bytes) then fragment header (offset 0, more=1) then TCP
    let tcp = Tcp::new(1, 2, 3, 0, SYN, 0).build();
    let mut payload = vec![44, 0, 1, 4, 0, 0, 0, 0]; // HBH -> next=44
    payload.extend_from_slice(&[6, 0, 0x00, 0x01, 0xde, 0xad, 0xbe, 0xef]); // frag hdr, M=1
    payload.extend_from_slice(&tcp);
    let d = dec(&eth(0x86DD, &ipv6_header(0, &payload, 64)));
    let ip = d.meta.ip.unwrap();
    assert!(ip.is_fragment && ip.more_fragments);
    assert_eq!(ip.id, 0xdeadbeef);
    assert!(d.meta.tcp.is_some());
}

#[test]
fn ipv4_fragments_are_flagged_and_non_first_not_parsed() {
    let mut ip = Ip4::new(A, B, 17);
    ip.frag = 0x2000; // MF, offset 0
    let udp = [0x30, 0x39, 0, 53, 0, 28, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20];
    let first = dec(&eth(0x0800, &ip.build(&udp[..16])));
    assert!(first.meta.ip.as_ref().unwrap().is_fragment);
    assert!(first.info.starts_with("Fragmented IP packet"));

    ip.frag = 0x00b9; // offset 185*8 = 1480, no MF
    let later = dec(&eth(0x0800, &ip.build(&[1, 2, 3, 4])));
    let m = later.meta.ip.unwrap();
    assert_eq!(m.frag_offset, 1480);
    assert!(m.is_fragment && !m.more_fragments);
    assert!(later.meta.udp.is_none());
}

#[test]
fn icmp_echo_and_unreachable() {
    let echo = dec(&icmp_frame(A, B, 8, 0, [0x12, 0x34, 0, 7], &[0; 8]));
    assert_eq!(echo.protocol, "ICMP");
    let m = echo.meta.icmp.unwrap();
    assert_eq!((m.typ, m.id, m.seq), (8, Some(0x1234), Some(7)));

    // port unreachable carrying the original IPv4+UDP header to 10.0.0.9:53
    let orig = Ip4::new(B, [10, 0, 0, 9], 17).build(&[0, 1, 0, 53, 0, 8, 0, 0]);
    let unreach = dec(&icmp_frame(A, B, 3, 3, [0; 4], &orig));
    let m = unreach.meta.icmp.unwrap();
    assert_eq!(m.orig_dst.unwrap().to_string(), "10.0.0.9");
    assert_eq!((m.orig_proto, m.orig_dport), (Some(17), Some(53)));
    assert!(unreach.info.contains("port unreachable"));
}

#[test]
fn icmpv6_echo() {
    let msg = [128u8, 0, 0, 0, 0, 1, 0, 2];
    let d = dec(&eth(0x86DD, &ipv6_header(58, &msg, 64)));
    assert_eq!(d.protocol, "ICMPv6");
    assert_eq!(d.meta.icmp.unwrap().seq, Some(2));
}

#[test]
fn arp_request_and_reply() {
    let d = dec(&arp_frame(1, A, B));
    assert_eq!(d.protocol, "ARP");
    assert_eq!(d.info, "Who has 10.0.0.2? Tell 10.0.0.1");
    let r = dec(&arp_frame(2, A, B));
    assert!(r.info.starts_with("10.0.0.1 is at"));
    let g = dec(&arp_frame(1, A, A));
    assert!(g.info.starts_with("Gratuitous ARP"));
}

#[test]
fn dns_query_and_response() {
    let q = dec(&udp_payload_frame(A, B, 50000, 53, &dns_message(0xabcd, false, 0, "example.com", 1, 0)));
    assert_eq!(q.protocol, "DNS");
    let m = q.meta.dns.unwrap();
    assert_eq!((m.id, m.response, m.qname.as_str(), m.qtype), (0xabcd, false, "example.com", 1));
    assert!(q.info.contains("Standard query 0xabcd A example.com"));

    let r = dec(&udp_payload_frame(B, A, 53, 50000, &dns_message(0xabcd, true, 3, "nope.example.com", 1, 0)));
    let m = r.meta.dns.unwrap();
    assert!(m.response);
    assert_eq!(m.rcode, 3);
    assert!(r.info.contains("NXDOMAIN"));
}

#[test]
fn dns_compression_loop_is_rejected_not_hung() {
    // name = pointer to itself
    let mut msg = vec![0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    msg.extend_from_slice(&[0xC0, 12, 0, 1, 0, 1]);
    let d = dec(&udp_payload_frame(A, B, 50000, 53, &msg));
    assert!(d.anomalies.iter().any(|a| a.kind == AnomalyKind::Malformed));
}

#[test]
fn dns_absurd_counts_are_rejected() {
    let mut msg = vec![0, 1, 0x81, 0x80, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0];
    msg.extend_from_slice(&[0; 4]);
    let d = dec(&udp_payload_frame(A, B, 53, 50000, &msg));
    assert!(d.meta.dns.is_none());
    assert!(!d.anomalies.is_empty());
}

#[test]
fn dhcp_discover() {
    let mut p = vec![0u8; 240];
    p[0] = 1;
    p[4..8].copy_from_slice(&0xdeadbeefu32.to_be_bytes());
    p[236..240].copy_from_slice(&[0x63, 0x82, 0x53, 0x63]);
    p.extend_from_slice(&[53, 1, 1, 255]);
    let d = dec(&udp_payload_frame([0, 0, 0, 0], [255, 255, 255, 255], 68, 67, &p));
    assert_eq!(d.protocol, "DHCP");
    assert_eq!(d.meta.dhcp_msg_type, Some(1));
}

// ---- malformed / truncated handling ----

#[test]
fn every_truncation_of_every_packet_is_safe() {
    let packets = vec![
        tcp_frame(A, B, &Tcp::new(1, 2, 3, 4, SYN | ACK, 10)),
        udp_payload_frame(A, B, 5, 53, &dns_message(1, false, 0, "a.b.c", 1, 0)),
        icmp_frame(A, B, 3, 3, [0; 4], &Ip4::new(B, A, 6).build(&[0; 8])),
        arp_frame(1, A, B),
        tcp6_frame(&Tcp::new(1, 2, 3, 4, ACK, 4)),
    ];
    for p in packets {
        for cut in 0..=p.len() {
            // Both "frame ended" and "snaplen cut" interpretations must never panic.
            let _ = decode(&p[..cut], DLT_EN10MB, cut);
            let _ = decode(&p[..cut], DLT_EN10MB, p.len());
        }
    }
}

#[test]
fn random_bytes_never_panic() {
    // Deterministic xorshift so failures are reproducible.
    let mut x: u64 = 0x9E3779B97F4A7C15;
    for len in 0..300usize {
        for _ in 0..40 {
            let buf: Vec<u8> = (0..len)
                .map(|_| {
                    x ^= x << 13;
                    x ^= x >> 7;
                    x ^= x << 17;
                    x as u8
                })
                .collect();
            for dlt in [DLT_EN10MB, DLT_NULL, DLT_RAW, 999] {
                let _ = decode(&buf, dlt, buf.len());
            }
        }
    }
}

#[test]
fn truncated_ethernet_is_anomaly_only_when_frame_is_complete() {
    let d = decode(&[1, 2, 3], DLT_EN10MB, 3);
    assert!(d.anomalies.iter().any(|a| a.kind == AnomalyKind::Truncated));
    // Snaplen-cut capture of a longer frame is not a protocol anomaly.
    let d = decode(&[1, 2, 3], DLT_EN10MB, 1500);
    assert!(d.anomalies.is_empty());
}

#[test]
fn invalid_ipv4_ihl_and_tcp_offset() {
    let mut f = tcp_frame(A, B, &Tcp::new(1, 2, 3, 4, ACK, 0));
    f[14] = 0x43; // IHL 3 words
    let d = dec(&f);
    assert!(d.anomalies.iter().any(|a| a.kind == AnomalyKind::InvalidHeaderLength && a.layer == "IPv4"));

    let mut f = tcp_frame(A, B, &Tcp::new(1, 2, 3, 4, ACK, 0));
    f[14 + 20 + 12] = 0x30; // TCP data offset 12 bytes
    let d = dec(&f);
    assert!(d.anomalies.iter().any(|a| a.kind == AnomalyKind::InvalidHeaderLength && a.layer == "TCP"));
}

#[test]
fn ipv4_total_length_beyond_frame_is_flagged() {
    let mut f = tcp_frame(A, B, &Tcp::new(1, 2, 3, 4, ACK, 0));
    f[16] = 0x05;
    f[17] = 0xdc; // claims 1500 bytes
    let d = dec(&f);
    assert!(d.anomalies.iter().any(|a| a.kind == AnomalyKind::InvalidLength));
}

#[test]
fn loopback_and_raw_ip_link_types() {
    let ip = Ip4::new(A, B, 6).build(&Tcp::new(1, 2, 3, 0, SYN, 0).build());
    let mut lo = vec![2, 0, 0, 0];
    lo.extend_from_slice(&ip);
    let d = decode(&lo, DLT_NULL, lo.len());
    assert_eq!(d.protocol, "TCP");
    let d = decode(&ip, DLT_RAW, ip.len());
    assert_eq!(d.protocol, "TCP");
}

#[test]
fn hex_string_formats_bytes() {
    assert_eq!(hex_string(&[0x00, 0xab, 0xff]), "00abff");
    assert_eq!(hex_string(&[]), "");
}

#[test]
fn vlan_tag_is_skipped() {
    let inner = Ip4::new(A, B, 6).build(&Tcp::new(1, 2, 3, 0, SYN, 0).build());
    let mut f = Vec::new();
    f.extend_from_slice(&ETH_DST);
    f.extend_from_slice(&ETH_SRC);
    f.extend_from_slice(&[0x81, 0x00, 0x00, 0x64, 0x08, 0x00]);
    f.extend_from_slice(&inner);
    let d = dec(&f);
    assert_eq!(d.protocol, "TCP");
}
