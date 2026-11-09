//! Evidence-based diagnostics. Every finding carries the packet numbers that support it, the
//! limits of the conclusion, and a confidence level. Nothing here infers loss from absence alone.

mod services;
mod tcp;
#[cfg(test)]
mod tests;

use crate::analytics::Analytics;
use crate::config::DiagConfig;
use crate::constants::*;
use crate::decoder::{AnomalyKind, Decoded};
use serde::Serialize;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum Severity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum Confidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Serialize)]
pub struct Evidence {
    /// None for aggregate observations that are not tied to one packet.
    pub packet_no: Option<u64>,
    pub ts_us: i64,
    pub note: String,
}

impl Evidence {
    /// Evidence tied to one packet.
    pub(crate) fn pkt(no: u64, ts_us: i64, note: impl Into<String>) -> Self {
        Evidence { packet_no: Some(no), ts_us, note: note.into() }
    }
    /// Evidence that is an aggregate observation rather than a single packet.
    pub(crate) fn agg(ts_us: i64, note: impl Into<String>) -> Self {
        Evidence { packet_no: None, ts_us, note: note.into() }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Measurement {
    pub label: String,
    pub value: String,
    /// "measured" values come directly from timestamps of matched packets;
    /// "estimated" values are derived and carry stated assumptions.
    pub kind: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub id: String,
    pub title: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub category: &'static str,
    pub protocol: &'static str,
    pub first_ts_us: i64,
    pub last_ts_us: i64,
    pub count: u64,
    /// What was observed (confirmed facts only).
    pub description: String,
    pub evidence: Vec<Evidence>,
    pub measurements: Vec<Measurement>,
    /// Hypotheses, never stated as fact.
    pub possible_causes: Vec<String>,
    pub recommendations: Vec<String>,
    pub limitations: Vec<String>,
    pub flow: Option<String>,
}

pub(crate) struct Spec {
    pub key: String,
    pub title: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub category: &'static str,
    pub protocol: &'static str,
    pub description: String,
    pub causes: Vec<String>,
    pub recommendations: Vec<String>,
    pub limitations: Vec<String>,
    pub flow: Option<String>,
    pub measurements: Vec<Measurement>,
}

fn strings(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| (*s).to_string()).collect()
}

impl Spec {
    pub(crate) fn new(key: impl Into<String>, title: impl Into<String>, category: &'static str, protocol: &'static str) -> Self {
        Spec {
            key: key.into(),
            title: title.into(),
            severity: Severity::Informational,
            confidence: Confidence::Medium,
            category,
            protocol,
            description: String::new(),
            causes: vec![],
            recommendations: vec![],
            limitations: vec![],
            flow: None,
            measurements: vec![],
        }
    }
    pub(crate) fn severity(mut self, s: Severity) -> Self {
        self.severity = s;
        self
    }
    pub(crate) fn confidence(mut self, c: Confidence) -> Self {
        self.confidence = c;
        self
    }
    /// What was observed (confirmed facts only).
    pub(crate) fn about(mut self, d: impl Into<String>) -> Self {
        self.description = d.into();
        self
    }
    pub(crate) fn causes(mut self, c: &[&str]) -> Self {
        self.causes = strings(c);
        self
    }
    pub(crate) fn advice(mut self, r: &[&str]) -> Self {
        self.recommendations = strings(r);
        self
    }
    pub(crate) fn limits(mut self, l: &[&str]) -> Self {
        self.limitations = strings(l);
        self
    }
    pub(crate) fn in_flow(mut self, f: &str) -> Self {
        self.flow = Some(f.to_string());
        self
    }
    pub(crate) fn measured(mut self, label: impl Into<String>, value: impl Into<String>) -> Self {
        self.measurements.push(Measurement { label: label.into(), value: value.into(), kind: "measured" });
        self
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct LatencyObservation {
    pub kind: &'static str,
    pub label: String,
    pub ts_us: i64,
    pub value_ms: f64,
    pub packet_no: u64,
    /// Always a measurement between two matched packets seen at the capture point.
    pub measured: bool,
    pub note: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Counters {
    pub tcp_retransmissions: u64,
    pub tcp_duplicate_acks: u64,
    pub tcp_out_of_order: u64,
    pub tcp_sequence_gaps: u64,
    pub tcp_resets: u64,
    pub tcp_handshakes: u64,
    pub tcp_refused: u64,
    pub dns_queries: u64,
    pub dns_responses: u64,
    pub icmp_errors: u64,
    pub fragments: u64,
    pub malformed: u64,
}

#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct CaptureDrops {
    pub received: u64,
    /// Dropped by the kernel/driver buffer because the application did not read fast enough.
    pub kernel_dropped: u64,
    pub interface_dropped: u64,
    /// Dropped by NEXUS' own bounded queue.
    pub pipeline_dropped: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Health {
    pub score: Option<u8>,
    pub label: &'static str,
    pub basis: String,
    pub capture_integrity: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct TimelineEvent {
    pub ts_us: i64,
    pub finding_id: String,
    pub title: String,
    pub severity: Severity,
    pub packet_no: Option<u64>,
    pub note: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DiagSnapshot {
    pub findings: Vec<Finding>,
    pub timeline: Vec<TimelineEvent>,
    pub health: Health,
    pub counters: Counters,
    pub latency: Vec<LatencyObservation>,
    pub capture: CaptureDrops,
    pub dropped_findings: u64,
}

pub struct Diagnostics {
    pub(crate) cfg: DiagConfig,
    findings: Vec<Finding>,
    index: HashMap<String, usize>,
    dropped_findings: u64,
    pub(crate) counters: Counters,
    pub(crate) latency: VecDeque<LatencyObservation>,
    pub(crate) capture: CaptureDrops,
    total_packets: u64,
    pub(crate) last_ts: i64,
    // TCP
    pub(crate) flows: HashMap<tcp::FlowKey, tcp::Flow>,
    pub(crate) syn_pending: HashMap<tcp::FlowKey, tcp::SynPending>,
    pub(crate) fail: HashMap<(IpAddr, u16), tcp::FailStats>,
    pub(crate) rst_by_src: HashMap<IpAddr, u32>,
    pub(crate) seen_src: HashSet<IpAddr>,
    // services
    pub(crate) dns_pending: HashMap<services::DnsKey, services::DnsPending>,
    pub(crate) dns_unanswered: HashMap<IpAddr, (u32, Vec<Evidence>)>,
    pub(crate) dns_codes: HashMap<(IpAddr, u8), u32>,
    pub(crate) pings: HashMap<services::PingKey, (i64, u64)>,
    pub(crate) malformed: HashMap<(AnomalyKind, String), u32>,
    pub(crate) last_spike_sec: i64,
}

impl Diagnostics {
    pub fn new(cfg: DiagConfig) -> Self {
        Diagnostics {
            cfg,
            findings: Vec::new(),
            index: HashMap::new(),
            dropped_findings: 0,
            counters: Counters::default(),
            latency: VecDeque::new(),
            capture: CaptureDrops::default(),
            total_packets: 0,
            last_ts: 0,
            flows: HashMap::new(),
            syn_pending: HashMap::new(),
            fail: HashMap::new(),
            rst_by_src: HashMap::new(),
            seen_src: HashSet::new(),
            dns_pending: HashMap::new(),
            dns_unanswered: HashMap::new(),
            dns_codes: HashMap::new(),
            pings: HashMap::new(),
            malformed: HashMap::new(),
            last_spike_sec: i64::MIN,
        }
    }

    /// Feed one decoded packet. `no` is the packet's 1-based number in the capture.
    pub fn observe(&mut self, no: u64, ts_us: i64, d: &Decoded) {
        self.total_packets += 1;
        self.last_ts = self.last_ts.max(ts_us);
        if let Some(src) = d.meta.ip.as_ref().and_then(|i| i.src) {
            if self.seen_src.len() < MAX_TRACKED_ENDPOINTS {
                self.seen_src.insert(src);
            }
        }
        self.malformed_check(no, ts_us, d);
        self.fragment_check(no, ts_us, d);
        if d.meta.tcp.is_some() {
            self.tcp_packet(no, ts_us, d);
        }
        if d.meta.dns.is_some() {
            self.dns_packet(no, ts_us, d);
        }
        if d.meta.icmp.is_some() {
            self.icmp_packet(no, ts_us, d);
        }
    }

    pub fn set_capture_stats(&mut self, c: CaptureDrops) {
        self.capture = c;
    }

    /// Periodic work: timeouts, traffic anomalies and capture integrity. `now_us` is wall-clock
    /// for live captures and the final packet time for offline analysis.
    pub fn tick(&mut self, now_us: i64, analytics: &Analytics) {
        self.expire_syns(now_us);
        self.expire_dns(now_us);
        self.traffic_checks(now_us, analytics);
        self.capture_checks(now_us);
    }

    pub(crate) fn raise(&mut self, spec: Spec, ts_us: i64, ev: Evidence) {
        if let Some(&i) = self.index.get(&spec.key) {
            let f = &mut self.findings[i];
            f.count += 1;
            f.last_ts_us = f.last_ts_us.max(ts_us);
            f.first_ts_us = f.first_ts_us.min(ts_us);
            f.severity = f.severity.max(spec.severity);
            f.confidence = f.confidence.max(spec.confidence);
            f.description = spec.description;
            f.measurements = spec.measurements;
            push_evidence(&mut f.evidence, ev);
            return;
        }
        if self.findings.len() >= MAX_FINDINGS {
            self.dropped_findings += 1;
            return;
        }
        self.index.insert(spec.key.clone(), self.findings.len());
        self.findings.push(Finding {
            id: spec.key,
            title: spec.title,
            severity: spec.severity,
            confidence: spec.confidence,
            category: spec.category,
            protocol: spec.protocol,
            first_ts_us: ts_us,
            last_ts_us: ts_us,
            count: 1,
            description: spec.description,
            evidence: vec![ev],
            measurements: spec.measurements,
            possible_causes: spec.causes,
            recommendations: spec.recommendations,
            limitations: spec.limitations,
            flow: spec.flow,
        });
    }

    pub(crate) fn has_finding(&self, key: &str) -> bool {
        self.index.contains_key(key)
    }

    /// Replace the aggregate count of an existing finding (used for rate-based findings).
    pub(crate) fn set_count(&mut self, key: &str, count: u64) {
        if let Some(&i) = self.index.get(key) {
            self.findings[i].count = count;
        }
    }

    pub(crate) fn add_latency(&mut self, l: LatencyObservation) {
        if self.latency.len() >= MAX_LATENCY_OBSERVATIONS {
            self.latency.pop_front();
        }
        self.latency.push_back(l);
    }

    fn malformed_check(&mut self, no: u64, ts: i64, d: &Decoded) {
        for a in &d.anomalies {
            self.counters.malformed += 1;
            let n = self.malformed.entry((a.kind, a.layer.clone())).or_insert(0);
            *n += 1;
            let n = *n;
            if n < self.cfg.malformed_min {
                continue;
            }
            let key = format!("malformed:{}:{:?}", a.layer, a.kind);
            let spec = Spec::new(key.clone(), format!("{} in {} headers", a.kind.label(), a.layer), "protocol", "Multiple")
                .severity(if n >= self.cfg.malformed_medium_count { Severity::Medium } else { Severity::Low })
                .confidence(Confidence::High)
                .about(format!("{n} packet(s) had a {} problem in the {} layer. Latest: {}.", a.kind.label().to_lowercase(), a.layer, a.detail))
                .causes(&[
                    "Capturing on the sending host with segmentation/checksum offload enabled can show zero or oversized length fields in outbound frames.",
                    "A faulty NIC, driver or middlebox corrupting or rewriting packets.",
                    "Packets truncated by the capture snap length or a retention limit (not a network fault).",
                    "Software producing non-conformant packets; deliberately crafted packets are possible but this observation alone does not show intent.",
                ])
                .advice(&[
                    "Capture on a mirror port or a second host to see whether the same frames appear malformed on the wire.",
                    "Temporarily disable large-send offload and checksum offload on the capturing NIC and re-capture.",
                    "Check whether the affected packets come from one source address or device.",
                ])
                .limits(&["Checksums are intentionally not validated because NIC offload commonly produces invalid checksums in local captures."]);
            self.raise(spec, ts, Evidence::pkt(no, ts, format!("{}: {}", a.layer, a.detail)));
            self.set_count(&key, u64::from(n));
        }
    }

    fn fragment_check(&mut self, no: u64, ts: i64, d: &Decoded) {
        let Some(ip) = d.meta.ip.as_ref() else { return };
        if !ip.is_fragment {
            return;
        }
        self.counters.fragments += 1;
        let c = self.counters.fragments;
        if c < FRAGMENT_REPORT_MIN {
            return;
        }
        let spec = Spec::new("ip-fragmentation", "IP fragmentation observed", "ip", "IP")
            .confidence(Confidence::High)
            .about(format!("{c} IP fragments were captured. Fragments are not reassembled, so upper-layer content of non-first fragments is not decoded."))
            .causes(&[
                "Datagrams larger than the path MTU (common with large UDP/DNS responses, tunnels or VPNs).",
                "A misconfigured MTU or blocked ICMP 'fragmentation needed' messages.",
            ])
            .advice(&[
                "Check interface/tunnel MTU settings and path MTU discovery behaviour.",
                "Look for ICMP 'fragmentation needed' or 'packet too big' findings in the same capture.",
            ])
            .limits(&["Fragmentation is normal for some traffic; this is an observation, not a fault."]);
        self.raise(spec, ts, Evidence::pkt(no, ts, d.info.clone()));
        self.set_count("ip-fragmentation", c);
    }

    fn capture_checks(&mut self, now: i64) {
        let c = self.capture;
        if c.kernel_dropped > 0 || c.interface_dropped > 0 {
            let total = c.kernel_dropped + c.interface_dropped;
            let ratio = total as f64 / (c.received + total).max(1) as f64;
            let spec = Spec::new("capture-drops-kernel", "Local capture buffer drops (not network packet loss)", "capture", "Capture")
                .severity(if ratio > CAPTURE_DROP_HIGH_RATIO { Severity::High } else { Severity::Medium })
                .confidence(Confidence::High)
                .about(format!("The capture driver reported {total} packet(s) dropped before NEXUS could read them ({:.2}% of packets seen). These packets crossed the interface but are missing from this capture.", ratio * 100.0))
                .causes(&[
                    "Traffic rate exceeded the rate the capture pipeline could read.",
                    "Kernel capture buffer too small for bursts.",
                    "CPU contention on the capturing machine.",
                ])
                .advice(&[
                    "Use a tighter capture (BPF) filter so fewer packets are captured.",
                    "Close other CPU-heavy applications during capture.",
                    "Treat TCP retransmission, duplicate-ACK, gap and out-of-order findings as less reliable for this capture.",
                ])
                .limits(&["This is a property of the local capture, not evidence of loss on the network."])
                .measured("Driver-reported drops", total.to_string());
            let note = format!("capture driver statistics: received={}, dropped by kernel={}, dropped by interface={}", c.received, c.kernel_dropped, c.interface_dropped);
            self.raise(spec, now, Evidence::agg(now, note));
        }
        if c.pipeline_dropped > 0 {
            let spec = Spec::new("capture-drops-pipeline", "NEXUS processing queue overflow (local, not network loss)", "capture", "Capture")
                .severity(Severity::Medium)
                .confidence(Confidence::High)
                .about(format!("{} packet(s) were discarded because the bounded processing queue was full.", c.pipeline_dropped))
                .causes(&["Packet rate exceeded decode/analysis throughput."])
                .advice(&["Increase the queue capacity in Settings or apply a narrower capture filter."])
                .limits(&["Analysis results for this capture are based on an incomplete packet sequence."]);
            self.raise(spec, now, Evidence::agg(now, format!("pipeline_dropped={}", c.pipeline_dropped)));
        }
    }

    pub fn snapshot(&self) -> DiagSnapshot {
        let drops = self.capture.kernel_dropped + self.capture.interface_dropped + self.capture.pipeline_dropped;
        let mut findings = self.findings.clone();
        for f in &mut findings {
            if f.category == "tcp" || f.category == "latency" {
                f.limitations.push("Capture point matters: packets sent or received by this host may differ from what is on the wire because of NIC offloads (LSO/GRO) and asymmetric routing.".into());
                if drops > 0 {
                    f.limitations.push(format!("{drops} packet(s) were dropped by the local capture mechanism during this capture, which can create apparent gaps, retransmissions or reordering."));
                }
            }
        }
        findings.sort_by(|a, b| b.severity.cmp(&a.severity).then(b.last_ts_us.cmp(&a.last_ts_us)));
        let mut timeline: Vec<TimelineEvent> = findings
            .iter()
            .flat_map(|f| {
                f.evidence.iter().map(|e| TimelineEvent {
                    ts_us: e.ts_us,
                    finding_id: f.id.clone(),
                    title: f.title.clone(),
                    severity: f.severity,
                    packet_no: e.packet_no,
                    note: e.note.clone(),
                })
            })
            .collect();
        timeline.sort_by_key(|e| e.ts_us);
        if timeline.len() > MAX_TIMELINE_EVENTS {
            timeline.drain(..timeline.len() - MAX_TIMELINE_EVENTS);
        }
        DiagSnapshot {
            health: self.health(),
            findings,
            timeline,
            counters: self.counters.clone(),
            latency: self.latency.iter().cloned().collect(),
            capture: self.capture,
            dropped_findings: self.dropped_findings,
        }
    }

    /// Health = 100 minus weighted severity of network findings (capture findings excluded),
    /// scaled by confidence. The formula is returned so the UI can show its basis.
    fn health(&self) -> Health {
        let integrity = if self.capture.kernel_dropped + self.capture.interface_dropped + self.capture.pipeline_dropped > 0 {
            "degraded"
        } else {
            "ok"
        };
        if self.total_packets < self.cfg.health_min_packets {
            return Health {
                score: None,
                label: "Insufficient data",
                basis: format!("Fewer than {} packets analysed; a health score would not be meaningful.", self.cfg.health_min_packets),
                capture_integrity: integrity,
            };
        }
        // Related findings (same title across flows/hosts) form one group: the worst member sets the
        // weight and repeats add only a logarithmic amount, so one recurring condition cannot sink the score.
        let mut groups: HashMap<&str, (f64, usize)> = HashMap::new();
        for f in self.findings.iter().filter(|f| f.category != "capture") {
            let w = match f.severity {
                Severity::Informational => 0.0,
                Severity::Low => HEALTH_WEIGHT_LOW,
                Severity::Medium => HEALTH_WEIGHT_MEDIUM,
                Severity::High => HEALTH_WEIGHT_HIGH,
                Severity::Critical => HEALTH_WEIGHT_CRITICAL,
            } * match f.confidence {
                Confidence::High => HEALTH_CONF_HIGH,
                Confidence::Medium => HEALTH_CONF_MEDIUM,
                Confidence::Low => HEALTH_CONF_LOW,
            };
            let e = groups.entry(f.title.as_str()).or_insert((0.0, 0));
            e.0 = e.0.max(w);
            e.1 += 1;
        }
        let penalty: f64 = groups.values().map(|(w, n)| w * (1.0 + HEALTH_REPEAT_FACTOR * (*n as f64).ln())).sum();
        let score = (100.0 * (-penalty / HEALTH_DECAY).exp()).clamp(0.0, 100.0).round() as u8;
        let label = match score {
            90..=100 => "Healthy",
            70..=89 => "Fair",
            40..=69 => "Degraded",
            _ => "Poor",
        };
        Health {
            score: Some(score),
            label,
            basis: format!("Each group of related findings costs its worst severity weight (Low {HEALTH_WEIGHT_LOW}, Medium {HEALTH_WEIGHT_MEDIUM}, High {HEALTH_WEIGHT_HIGH}, Critical {HEALTH_WEIGHT_CRITICAL}) x confidence (High {HEALTH_CONF_HIGH}, Medium {HEALTH_CONF_MEDIUM}, Low {HEALTH_CONF_LOW}), plus a small logarithmic amount for repeats; the score is 100 x e^(-total/{HEALTH_DECAY}). Capture-integrity findings are reported separately."),
            capture_integrity: integrity,
        }
    }

    pub fn findings_len(&self) -> usize {
        self.findings.len()
    }

    pub fn counters(&self) -> &Counters {
        &self.counters
    }
}

/// Keep the first and last evidence items when the cap is exceeded (drop from the middle).
fn push_evidence(list: &mut Vec<Evidence>, ev: Evidence) {
    if list.len() >= MAX_EVIDENCE_PER_FINDING {
        list.remove(MAX_EVIDENCE_PER_FINDING / 2);
    }
    list.push(ev);
}

pub(crate) fn ms(us: i64) -> f64 {
    us as f64 / 1000.0
}
