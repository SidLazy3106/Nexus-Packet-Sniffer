//! Scenario tests: hand-built packet sequences with known-correct diagnoses.

use super::*;
use crate::analytics::{Analytics, Family};
use crate::decoder::decode;
use crate::testutil::*;

const C: [u8; 4] = [10, 0, 0, 1];
const S: [u8; 4] = [10, 0, 0, 2];
const CP: u16 = 50000;
const SP: u16 = 80;

struct Feed {
    d: Diagnostics,
    a: Analytics,
    no: u64,
    last_ms: i64,
}

impl Feed {
    fn new() -> Self {
        Feed { d: Diagnostics::new(DiagConfig::default()), a: Analytics::new(), no: 0, last_ms: 0 }
    }

    fn push(&mut self, ms: i64, frame: Vec<u8>) -> u64 {
        self.no += 1;
        self.last_ms = self.last_ms.max(ms);
        let dec = decode(&frame, 1, frame.len());
        self.a.record(ms * 1000, frame.len() as u32, Family::Other, &dec.protocol, &dec.src, &dec.dst, None);
        self.d.observe(self.no, ms * 1000, &dec);
        self.no
    }

    fn c2s(&mut self, ms: i64, seq: u32, ack: u32, flags: u8, len: usize) -> u64 {
        self.push(ms, tcp_frame(C, S, &Tcp::new(CP, SP, seq, ack, flags, len)))
    }
    fn s2c(&mut self, ms: i64, seq: u32, ack: u32, flags: u8, len: usize) -> u64 {
        self.push(ms, tcp_frame(S, C, &Tcp::new(SP, CP, seq, ack, flags, len)))
    }

    /// Standard handshake: SYN @t, SYN-ACK @t+10, ACK @t+11. Client ISN 999, server ISN 4999.
    fn handshake(&mut self, t: i64) {
        self.c2s(t, 999, 0, SYN, 0);
        self.s2c(t + 10, 4999, 1000, SYN | ACK, 0);
        self.c2s(t + 11, 1000, 5000, ACK, 0);
    }

    fn snap(&mut self) -> DiagSnapshot {
        self.d.tick((self.last_ms + 20_000) * 1000, &self.a);
        self.d.snapshot()
    }
}

fn ids(s: &DiagSnapshot, prefix: &str) -> Vec<Finding> {
    s.findings.iter().filter(|f| f.id.starts_with(prefix)).cloned().collect()
}

#[test]
fn ordinary_connection_produces_no_findings_and_measures_handshake() {
    let mut f = Feed::new();
    f.handshake(0);
    f.c2s(20, 1000, 5000, ACK | PSH, 200);
    f.s2c(30, 5000, 1200, ACK, 0);
    f.s2c(40, 5000, 1200, ACK | PSH, 500);
    f.c2s(50, 1200, 5500, ACK, 0);
    f.c2s(60, 1200, 5500, FIN | ACK, 0);
    f.s2c(70, 5500, 1201, FIN | ACK, 0);
    f.c2s(80, 1201, 5501, ACK, 0);
    let s = f.snap();
    assert!(s.findings.is_empty(), "unexpected findings: {:?}", s.findings.iter().map(|x| &x.id).collect::<Vec<_>>());
    assert_eq!(s.counters.tcp_handshakes, 1);
    let hs = s.latency.iter().find(|l| l.kind == "TCP handshake").unwrap();
    assert!((hs.value_ms - 11.0).abs() < 1e-9, "{}", hs.value_ms);
    assert!(hs.measured);
}

#[test]
fn rtt_sample_requires_matching_ack() {
    let mut f = Feed::new();
    f.handshake(0);
    f.c2s(100, 1000, 5000, ACK | PSH, 100);
    f.s2c(125, 5000, 1100, ACK, 0);
    let s = f.snap();
    let l = s.latency.iter().find(|l| l.kind == "TCP data→ACK").unwrap();
    assert!((l.value_ms - 25.0).abs() < 1e-9);
}

#[test]
fn retransmission_is_detected_with_original_packet_as_evidence() {
    let mut f = Feed::new();
    f.handshake(0);
    let orig = f.c2s(100, 1000, 5000, ACK | PSH, 100);
    let re = f.c2s(400, 1000, 5000, ACK | PSH, 100);
    let s = f.snap();
    let r = ids(&s, "tcp-retrans:");
    assert_eq!(r.len(), 1);
    let r = &r[0];
    assert_eq!(r.count, 1);
    assert_eq!(r.confidence, Confidence::High);
    assert_eq!(r.evidence[0].packet_no, Some(re));
    assert!(r.evidence[0].note.contains(&format!("packet {orig}")), "{}", r.evidence[0].note);
    assert!(r.evidence[0].note.contains("300.000 ms"));
    assert!(r.description.contains("does not show where or why"));
    assert_eq!(s.counters.tcp_retransmissions, 1);
}

#[test]
fn syn_retransmission_is_flagged_as_syn() {
    let mut f = Feed::new();
    f.c2s(0, 999, 0, SYN, 0);
    f.c2s(1000, 999, 0, SYN, 0);
    let s = f.snap();
    let r = ids(&s, "tcp-retrans:");
    assert_eq!(r[0].title, "TCP SYN retransmitted");
}

#[test]
fn duplicate_acks_then_fast_retransmit_are_correlated() {
    let mut f = Feed::new();
    f.handshake(0);
    f.c2s(10, 1000, 5000, ACK | PSH, 100);
    f.c2s(11, 1100, 5000, ACK | PSH, 100); // segment A (lost downstream in this scenario)
    f.c2s(12, 1200, 5000, ACK | PSH, 100);
    f.c2s(13, 1300, 5000, ACK | PSH, 100);
    f.c2s(14, 1400, 5000, ACK | PSH, 100);
    f.s2c(20, 5000, 1100, ACK, 0);
    // three duplicate ACKs for 1100? first ack=1100 is the "original"; the following are duplicates.
    let mut last = 0;
    for i in 0..4 {
        last = f.s2c(21 + i, 5000, 1100, ACK, 0);
    }
    f.c2s(60, 1100, 5000, ACK | PSH, 100); // retransmit the segment the receiver keeps asking for
    let s = f.snap();
    let d = ids(&s, "tcp-dupack:");
    assert_eq!(d.len(), 1, "dup-ack finding");
    assert_eq!(s.counters.tcp_duplicate_acks, 4);
    assert!(d[0].evidence.iter().any(|e| e.packet_no == Some(last)));
    let r = ids(&s, "tcp-retrans:");
    assert!(r[0].evidence[0].note.contains("fast-retransmit"), "{}", r[0].evidence[0].note);
    let lr = ids(&s, "tcp-loss-recovery:");
    assert_eq!(lr.len(), 1);
    assert!(lr[0].possible_causes.iter().any(|c| c.contains("Packet loss")));
    // Hypothesis, not a claim.
    assert!(lr[0].description.contains("cannot show where"));
}

#[test]
fn two_duplicate_acks_are_below_the_threshold() {
    let mut f = Feed::new();
    f.handshake(0);
    f.c2s(10, 1000, 5000, ACK | PSH, 100);
    f.c2s(11, 1100, 5000, ACK | PSH, 100);
    f.s2c(20, 5000, 1100, ACK, 0);
    f.s2c(21, 5000, 1100, ACK, 0);
    f.s2c(22, 5000, 1100, ACK, 0);
    let s = f.snap();
    assert!(ids(&s, "tcp-dupack:").is_empty());
    assert_eq!(s.counters.tcp_duplicate_acks, 2);
}

#[test]
fn acks_with_no_outstanding_data_are_not_duplicates() {
    let mut f = Feed::new();
    f.handshake(0);
    for i in 0..6 {
        f.s2c(20 + i, 5000, 1000, ACK, 0); // keep-alive style ACKs, nothing outstanding
    }
    let s = f.snap();
    assert_eq!(s.counters.tcp_duplicate_acks, 0);
}

#[test]
fn quick_late_arrival_is_out_of_order_not_retransmission() {
    let mut f = Feed::new();
    f.handshake(0);
    f.c2s(10, 1000, 5000, ACK | PSH, 100);
    f.c2s(11, 1200, 5000, ACK | PSH, 100); // 1100..1200 missing
    let late = f.c2s(14, 1100, 5000, ACK | PSH, 100); // arrives 3 ms later
    let s = f.snap();
    let o = ids(&s, "tcp-ooo:");
    assert_eq!(o.len(), 1);
    assert_eq!(o[0].evidence[0].packet_no, Some(late));
    assert!(ids(&s, "tcp-retrans:").is_empty());
    assert_eq!(s.counters.tcp_out_of_order, 1);
}

#[test]
fn slow_gap_fill_is_retransmission_of_unobserved_original() {
    let mut f = Feed::new();
    f.handshake(0);
    f.c2s(10, 1000, 5000, ACK | PSH, 100);
    f.c2s(11, 1200, 5000, ACK | PSH, 100);
    f.c2s(900, 1100, 5000, ACK | PSH, 100); // 889 ms later
    let s = f.snap();
    let r = ids(&s, "tcp-retrans:");
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].confidence, Confidence::Medium);
    assert!(r[0].evidence[0].note.contains("original transmission was not observed"));
}

#[test]
fn sequence_gap_alone_is_not_reported_as_loss() {
    let mut f = Feed::new();
    f.handshake(0);
    f.c2s(10, 1000, 5000, ACK | PSH, 100);
    f.c2s(11, 1500, 5000, ACK | PSH, 100); // 400 bytes never seen
    let s = f.snap();
    let g = ids(&s, "tcp-gap:");
    assert_eq!(g.len(), 1);
    assert!(g[0].severity <= Severity::Informational);
    assert_eq!(g[0].confidence, Confidence::Low);
    assert!(g[0].description.contains("does not by itself prove"));
    assert!(g[0].possible_causes[0].contains("local capture"));
    assert!(ids(&s, "tcp-retrans:").is_empty());
}

#[test]
fn keepalive_is_not_a_retransmission() {
    let mut f = Feed::new();
    f.handshake(0);
    f.c2s(10, 1000, 5000, ACK | PSH, 100);
    f.c2s(60_000, 1099, 5000, ACK, 1); // keep-alive probe: seq = next-1, 1 byte
    let s = f.snap();
    assert!(ids(&s, "tcp-retrans:").is_empty());
}

#[test]
fn sequence_wraparound_is_handled() {
    let mut f = Feed::new();
    f.c2s(0, u32::MAX - 49, 0, SYN, 0);
    f.s2c(5, 100, u32::MAX - 48, SYN | ACK, 0);
    f.c2s(6, u32::MAX - 48, 101, ACK, 0);
    f.c2s(10, u32::MAX - 48, 101, ACK | PSH, 100); // crosses the 2^32 boundary
    f.c2s(11, 51, 101, ACK | PSH, 100); // continues after wrap -> in order
    let s = f.snap();
    assert!(ids(&s, "tcp-gap:").is_empty(), "wrap must not look like a gap");
    assert!(ids(&s, "tcp-retrans:").is_empty());
}

#[test]
fn refused_connections_raise_a_high_confidence_failure_finding() {
    let mut f = Feed::new();
    for i in 0..3 {
        let t = i * 1000;
        f.push(t, tcp_frame(C, S, &Tcp::new(40000 + i as u16, 8080, 1, 0, SYN, 0)));
        f.push(t + 2, tcp_frame(S, C, &Tcp::new(8080, 40000 + i as u16, 0, 2, RST | ACK, 0)));
    }
    let s = f.snap();
    let c = ids(&s, "conn-fail:");
    assert_eq!(c.len(), 1);
    assert_eq!(c[0].confidence, Confidence::High);
    assert!(c[0].description.contains("3 refused"), "{}", c[0].description);
    assert_eq!(s.counters.tcp_refused, 3);
    // Refused SYN replies are not also reported as mid-stream resets.
    assert!(ids(&s, "tcp-reset:").is_empty());
}

#[test]
fn unanswered_syns_are_low_confidence_when_destination_never_seen() {
    let mut f = Feed::new();
    for i in 0..3 {
        f.push(i * 100, tcp_frame(C, S, &Tcp::new(40000 + i as u16, 9, 1, 0, SYN, 0)));
    }
    let s = f.snap();
    let c = ids(&s, "conn-fail:");
    assert_eq!(c.len(), 1);
    assert_eq!(c[0].confidence, Confidence::Low);
    assert!(c[0].limitations[0].contains("lack of observation"));
}

#[test]
fn syns_within_timeout_of_capture_end_are_not_judged() {
    let mut f = Feed::new();
    for i in 0..3 {
        f.push(i, tcp_frame(C, S, &Tcp::new(40000 + i as u16, 9, 1, 0, SYN, 0)));
    }
    f.d.tick(1_000_000, &f.a); // 1 s after the SYNs, timeout is 3 s
    assert!(ids(&f.d.snapshot(), "conn-fail:").is_empty());
}

#[test]
fn midstream_reset_is_low_severity_and_hedged() {
    let mut f = Feed::new();
    f.handshake(0);
    f.c2s(10, 1000, 5000, ACK | PSH, 50);
    f.s2c(20, 5000, 1050, RST | ACK, 0);
    let s = f.snap();
    let r = ids(&s, "tcp-reset:");
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].severity, Severity::Low);
    assert!(r[0].limitations[0].contains("frequently normal"));
}

#[test]
fn slow_handshake_reports_measured_legs() {
    let mut f = Feed::new();
    f.c2s(0, 999, 0, SYN, 0);
    f.s2c(500, 4999, 1000, SYN | ACK, 0);
    f.c2s(502, 1000, 5000, ACK, 0);
    let s = f.snap();
    let h = ids(&s, "tcp-slow-handshake:");
    assert_eq!(h.len(), 1);
    assert!(h[0].measurements.iter().all(|m| m.kind == "measured"));
    assert!(h[0].measurements.iter().any(|m| m.value == "502.000 ms"));
}

#[test]
fn latency_variation_requires_enough_samples_and_a_big_outlier() {
    let mut f = Feed::new();
    f.handshake(0);
    let mut seq = 1000u32;
    let mut t = 100;
    for _ in 0..10 {
        f.c2s(t, seq, 5000, ACK | PSH, 100);
        seq += 100;
        f.s2c(t + 20, 5000, seq, ACK, 0);
        t += 100;
    }
    f.c2s(t, seq, 5000, ACK | PSH, 100);
    seq += 100;
    f.s2c(t + 400, 5000, seq, ACK, 0); // 400 ms vs ~20 ms median
    let s = f.snap();
    let v = ids(&s, "latency-var:");
    assert_eq!(v.len(), 1);
    assert!(v[0].limitations[0].contains("not pure network RTT"));
}

#[test]
fn slow_dns_response_is_measured_from_matched_packets() {
    let mut f = Feed::new();
    let q = f.push(0, udp_payload_frame(C, S, 51000, 53, &dns_message(7, false, 0, "slow.example", 1, 0)));
    let r = f.push(800, udp_payload_frame(S, C, 53, 51000, &dns_message(7, true, 0, "slow.example", 1, 1)));
    let s = f.snap();
    let d = ids(&s, "dns-slow:");
    assert_eq!(d.len(), 1);
    assert!(d[0].evidence[0].note.contains(&format!("query packet {q}")));
    let l = s.latency.iter().find(|l| l.kind == "DNS").unwrap();
    assert_eq!(l.value_ms, 800.0);
    assert_eq!(l.packet_no, r);
}

#[test]
fn fast_dns_is_clean_and_mismatched_id_does_not_match() {
    let mut f = Feed::new();
    f.push(0, udp_payload_frame(C, S, 51000, 53, &dns_message(7, false, 0, "a.example", 1, 0)));
    f.push(20, udp_payload_frame(S, C, 53, 51000, &dns_message(7, true, 0, "a.example", 1, 1)));
    f.push(30, udp_payload_frame(C, S, 51001, 53, &dns_message(8, false, 0, "b.example", 1, 0)));
    f.push(40, udp_payload_frame(S, C, 53, 51001, &dns_message(99, true, 0, "b.example", 1, 1)));
    let s = f.snap();
    assert_eq!(s.latency.iter().filter(|l| l.kind == "DNS").count(), 1);
}

#[test]
fn repeated_dns_failures_and_unanswered_queries_are_reported() {
    let mut f = Feed::new();
    for i in 0..5u16 {
        f.push(i as i64 * 10, udp_payload_frame(C, S, 51000 + i, 53, &dns_message(i, false, 0, "nx.example", 1, 0)));
        f.push(i as i64 * 10 + 1, udp_payload_frame(S, C, 53, 51000 + i, &dns_message(i, true, 3, "nx.example", 1, 0)));
    }
    for i in 10..13u16 {
        f.push(1000 + i as i64, udp_payload_frame(C, [10, 0, 0, 9], 52000 + i, 53, &dns_message(i, false, 0, "gone.example", 1, 0)));
    }
    let s = f.snap();
    assert_eq!(ids(&s, "dns-rcode:").len(), 1);
    let u = ids(&s, "dns-unanswered:");
    assert_eq!(u.len(), 1);
    assert!(u[0].description.contains("not proof"));
}

#[test]
fn icmp_unreachable_and_echo_rtt() {
    let mut f = Feed::new();
    f.push(0, icmp_frame(C, S, 8, 0, [0, 1, 0, 1], &[0; 8]));
    f.push(12, icmp_frame(S, C, 0, 0, [0, 1, 0, 1], &[0; 8]));
    let orig = Ip4::new(C, [10, 0, 0, 9], 17).build(&[0, 1, 0, 53, 0, 8, 0, 0]);
    f.push(100, icmp_frame(S, C, 3, 1, [0; 4], &orig));
    let s = f.snap();
    let l = s.latency.iter().find(|l| l.kind == "ICMP echo").unwrap();
    assert_eq!(l.value_ms, 12.0);
    let u = ids(&s, "icmp:");
    assert_eq!(u.len(), 1);
    assert!(u[0].description.contains("10.0.0.9"));
    assert_eq!(u[0].severity, Severity::Medium);
    assert_eq!(s.counters.icmp_errors, 1);
}

#[test]
fn malformed_packets_are_reported_without_claiming_malice() {
    let mut f = Feed::new();
    let mut bad = tcp_frame(C, S, &Tcp::new(1, 2, 3, 4, ACK, 0));
    bad[14] = 0x43;
    f.push(0, bad);
    let s = f.snap();
    let m = ids(&s, "malformed:");
    assert_eq!(m.len(), 1);
    assert!(m[0].possible_causes.iter().any(|c| c.contains("offload")));
    assert!(m[0].possible_causes.iter().any(|c| c.contains("does not show intent")));
    assert_eq!(s.counters.malformed, 1);
}

#[test]
fn capture_drops_are_reported_as_local_and_taint_tcp_findings() {
    let mut f = Feed::new();
    f.handshake(0);
    f.c2s(10, 1000, 5000, ACK | PSH, 100);
    f.c2s(300, 1000, 5000, ACK | PSH, 100);
    f.d.set_capture_stats(CaptureDrops { received: 1000, kernel_dropped: 50, interface_dropped: 0, pipeline_dropped: 0 });
    let s = f.snap();
    let c = ids(&s, "capture-drops-kernel");
    assert_eq!(c.len(), 1);
    assert!(c[0].title.contains("not network packet loss"));
    assert_eq!(c[0].category, "capture");
    let r = &ids(&s, "tcp-retrans:")[0];
    assert!(r.limitations.iter().any(|l| l.contains("50 packet(s) were dropped by the local capture")));
    assert_eq!(s.health.capture_integrity, "degraded");
}

#[test]
fn health_needs_enough_data_and_excludes_capture_findings() {
    let mut f = Feed::new();
    f.handshake(0);
    assert!(f.snap().health.score.is_none());
    for i in 0..60 {
        f.c2s(100 + i, 1000 + (i as u32) * 10, 5000, ACK | PSH, 10);
    }
    f.d.set_capture_stats(CaptureDrops { received: 100, kernel_dropped: 5, ..Default::default() });
    let s = f.snap();
    assert_eq!(s.health.score, Some(100));
    assert_eq!(s.health.label, "Healthy");
    assert_eq!(s.health.capture_integrity, "degraded");
}

#[test]
fn traffic_spike_uses_baseline_and_minimum_volume() {
    let mut d = Diagnostics::new(DiagConfig::default());
    let mut a = Analytics::new();
    for sec in 0..40i64 {
        a.record(sec * 1_000_000, 1000, Family::Udp, "UDP", "a", "b", None);
    }
    a.record(40 * 1_000_000, 8_000_000, Family::Udp, "UDP", "a", "b", None);
    for sec in 41..45i64 {
        a.record(sec * 1_000_000, 1000, Family::Udp, "UDP", "a", "b", None);
    }
    d.tick(46 * 1_000_000, &a);
    let s = d.snapshot();
    let sp = ids(&s, "traffic-spike");
    assert_eq!(sp.len(), 1);
    assert_eq!(sp[0].count, 1);
    assert_eq!(sp[0].evidence[0].packet_no, None);
    // Ticking again must not double count.
    d.tick(47 * 1_000_000, &a);
    assert_eq!(ids(&d.snapshot(), "traffic-spike")[0].count, 1);
}

#[test]
fn small_variations_are_not_spikes() {
    let mut d = Diagnostics::new(DiagConfig::default());
    let mut a = Analytics::new();
    for sec in 0..60i64 {
        a.record(sec * 1_000_000, 1000 + (sec as u32 % 5) * 100, Family::Udp, "UDP", "a", "b", None);
    }
    d.tick(61 * 1_000_000, &a);
    assert!(ids(&d.snapshot(), "traffic-spike").is_empty());
}

#[test]
fn icmp_dominated_capture_flags_protocol_mix_once() {
    let mut d = Diagnostics::new(DiagConfig::default());
    let mut a = Analytics::new();
    for i in 0..300i64 {
        a.record(i * 1000, 100, Family::Icmp, "ICMP", "a", "b", None);
    }
    d.tick(10_000_000, &a);
    d.tick(11_000_000, &a);
    let m = ids(&d.snapshot(), "mix-icmp");
    assert_eq!(m.len(), 1);
    assert_eq!(m[0].count, 1);
}

#[test]
fn analysis_is_deterministic_and_reproducible() {
    fn run() -> String {
        let mut f = Feed::new();
        f.handshake(0);
        f.c2s(100, 1000, 5000, ACK | PSH, 100);
        f.c2s(500, 1000, 5000, ACK | PSH, 100);
        f.s2c(520, 5000, 1100, ACK, 0);
        serde_json::to_string(&f.snap()).unwrap()
    }
    assert_eq!(run(), run());
}

#[test]
fn every_finding_has_evidence_causes_and_recommendations() {
    let mut f = Feed::new();
    f.handshake(0);
    f.c2s(10, 1000, 5000, ACK | PSH, 100);
    f.c2s(300, 1000, 5000, ACK | PSH, 100);
    f.c2s(400, 1600, 5000, ACK | PSH, 100);
    f.s2c(410, 5000, 1000, RST | ACK, 0);
    let mut bad = tcp_frame(C, S, &Tcp::new(1, 2, 3, 4, ACK, 0));
    bad[14] = 0x43;
    f.push(500, bad);
    let s = f.snap();
    assert!(!s.findings.is_empty());
    for x in &s.findings {
        assert!(!x.evidence.is_empty(), "{} has no evidence", x.id);
        assert!(!x.possible_causes.is_empty(), "{} has no causes", x.id);
        assert!(!x.recommendations.is_empty(), "{} has no recommendations", x.id);
        assert!(!x.limitations.is_empty(), "{} has no limitations", x.id);
    }
}

#[test]
fn evidence_is_capped_keeping_first_and_latest() {
    let mut f = Feed::new();
    f.handshake(0);
    f.c2s(10, 1000, 5000, ACK | PSH, 10);
    let mut last = 0;
    for i in 0..60 {
        last = f.c2s(100 + i * 10, 1000, 5000, ACK | PSH, 10);
    }
    let s = f.snap();
    let r = &ids(&s, "tcp-retrans:")[0];
    assert_eq!(r.evidence.len(), MAX_EVIDENCE_PER_FINDING);
    assert_eq!(r.evidence.last().unwrap().packet_no, Some(last));
    assert_eq!(r.count, 60);
}

#[test]
fn flow_table_is_bounded() {
    let mut f = Feed::new();
    for i in 0..(MAX_DIAG_FLOWS as u32 + 500) {
        let sp = 1024 + (i % 60000) as u16;
        let src = [10, (i >> 16) as u8, (i >> 8) as u8, i as u8];
        f.push(i as i64, tcp_frame(src, S, &Tcp::new(sp, 80, 1, 0, SYN, 0)));
    }
    assert!(f.d.flows.len() <= MAX_DIAG_FLOWS);
}

#[test]
fn health_decays_gently_and_repeats_of_one_condition_do_not_sink_it() {
    // Distinct flows with the same retransmission condition form one group.
    let mut one = Feed::new();
    one.handshake(0);
    one.c2s(10, 1000, 5000, ACK | PSH, 10);
    one.c2s(300, 1000, 5000, ACK | PSH, 10);
    for i in 0..60 {
        one.c2s(400 + i, 2000 + (i as u32) * 10, 5000, ACK | PSH, 10);
    }
    let single = one.snap().health.score.unwrap();
    assert!(single >= 90, "a single low-severity finding should leave the network Healthy, got {single}");

    let mut many = Feed::new();
    for k in 0..12u16 {
        let (cp, base) = (40000 + k, 1000u32);
        many.push(k as i64 * 50, tcp_frame(C, S, &Tcp::new(cp, SP, base - 1, 0, SYN, 0)));
        many.push(k as i64 * 50 + 5, tcp_frame(S, C, &Tcp::new(SP, cp, 4999, base, SYN | ACK, 0)));
        many.push(k as i64 * 50 + 6, tcp_frame(C, S, &Tcp::new(cp, SP, base, 5000, ACK, 0)));
        many.push(k as i64 * 50 + 7, tcp_frame(C, S, &Tcp::new(cp, SP, base, 5000, ACK | PSH, 10)));
        many.push(k as i64 * 50 + 30, tcp_frame(C, S, &Tcp::new(cp, SP, base, 5000, ACK | PSH, 10)));
    }
    let s = many.snap();
    assert_eq!(ids(&s, "tcp-retrans:").len(), 12);
    let score = s.health.score.unwrap();
    assert!(score >= 75, "12 flows with the same Low finding must not read as Poor, got {score}");
    assert!(score <= single);
}
