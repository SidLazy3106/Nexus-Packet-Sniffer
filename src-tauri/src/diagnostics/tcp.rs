//! TCP flow tracking: handshake timing, retransmissions, duplicate ACKs, reordering, resets
//! and ACK-derived RTT samples, all correlated by connection tuple and sequence numbers.

use super::*;
use crate::decoder::TcpMeta;
use std::collections::BTreeMap;
use std::fmt;

const MAX_HOLES: usize = 16;
const MAX_PENDING_RTT: usize = 128;

fn seq_lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}
fn seq_gt(a: u32, b: u32) -> bool {
    seq_lt(b, a)
}
fn seq_le(a: u32, b: u32) -> bool {
    !seq_gt(a, b)
}
fn seq_ge(a: u32, b: u32) -> bool {
    !seq_lt(a, b)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct FlowKey {
    a: (IpAddr, u16),
    b: (IpAddr, u16),
}

impl FlowKey {
    /// Canonical (direction-independent) key plus the direction index of this packet.
    pub fn new(src: IpAddr, sp: u16, dst: IpAddr, dp: u16) -> (Self, usize) {
        if (src, sp) <= (dst, dp) {
            (FlowKey { a: (src, sp), b: (dst, dp) }, 0)
        } else {
            (FlowKey { a: (dst, dp), b: (src, sp) }, 1)
        }
    }
}

fn ep(ip: IpAddr, port: u16) -> String {
    match ip {
        IpAddr::V4(_) => format!("{ip}:{port}"),
        IpAddr::V6(_) => format!("[{ip}]:{port}"),
    }
}

impl fmt::Display for FlowKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ⇄ {}", ep(self.a.0, self.a.1), ep(self.b.0, self.b.1))
    }
}

pub(crate) struct SynPending {
    pub ts: i64,
    pub no: u64,
    pub server: IpAddr,
    pub server_port: u16,
}

#[derive(Default)]
pub(crate) struct FailStats {
    pub refused: u32,
    pub unanswered: u32,
    pub evidence: Vec<Evidence>,
}

#[derive(Clone)]
struct Hole {
    start: u32,
    end: u32,
    ts: i64,
    no: u64,
}

#[derive(Default)]
struct Dir {
    next: Option<u32>,
    seen: BTreeMap<u32, (u32, i64, u64)>,
    holes: Vec<Hole>,
    last_ack: Option<u32>,
    last_win: u16,
    dup_count: u32,
    segs: u64,
    retrans: u64,
    ooo: u64,
    dupacks: u64,
}

enum Seg {
    InOrder,
    Keepalive,
    Gap { missing: u32 },
    Retrans { original: Option<(u64, i64)>, hole_no: Option<u64> },
    Ooo { hole_no: u64 },
}

impl Dir {
    fn remember(&mut self, seq: u32, end: u32, ts: i64, no: u64) {
        self.seen.insert(seq, (end, ts, no));
        if self.seen.len() > MAX_SEEN_SEGMENTS_PER_DIR {
            // Drop the entry with the oldest timestamp; sequence order is not time order under wrap.
            if let Some((&k, _)) = self.seen.iter().min_by_key(|(_, v)| v.1) {
                self.seen.remove(&k);
            }
        }
    }

    fn classify(&mut self, seq: u32, len: u32, ts: i64, no: u64, reorder_us: i64, pure_data: bool) -> Seg {
        let end = seq.wrapping_add(len);
        let Some(next) = self.next else {
            self.next = Some(end);
            self.remember(seq, end, ts, no);
            return Seg::InOrder;
        };
        if seq == next {
            self.next = Some(end);
            self.remember(seq, end, ts, no);
            return Seg::InOrder;
        }
        if seq_gt(seq, next) {
            self.holes.push(Hole { start: next, end: seq, ts, no });
            if self.holes.len() > MAX_HOLES {
                self.holes.remove(0);
            }
            self.next = Some(end);
            self.remember(seq, end, ts, no);
            return Seg::Gap { missing: seq.wrapping_sub(next) };
        }
        // seq < next: something at or before already-seen sequence space.
        if pure_data && len == 1 && seq == next.wrapping_sub(1) {
            return Seg::Keepalive;
        }
        if let Some(&(_, t0, n0)) = self.seen.get(&seq) {
            return Seg::Retrans { original: Some((n0, t0)), hole_no: None };
        }
        if let Some(i) = self.holes.iter().position(|h| seq_ge(seq, h.start) && seq_lt(seq, h.end)) {
            let h = self.holes[i].clone();
            if seq_ge(end, h.end) {
                self.holes.remove(i);
            } else {
                self.holes[i].start = end;
            }
            self.remember(seq, end, ts, no);
            return if ts - h.ts <= reorder_us {
                Seg::Ooo { hole_no: h.no }
            } else {
                // The original transmission was never observed here: the retransmission fills a gap.
                Seg::Retrans { original: None, hole_no: Some(h.no) }
            };
        }
        Seg::Retrans { original: None, hole_no: None }
    }
}

pub(crate) struct Flow {
    dirs: [Dir; 2],
    syn: Option<(i64, u64, usize)>,
    synack: Option<(i64, u64, usize)>,
    established: bool,
    fin: [bool; 2],
    pending: [std::collections::VecDeque<(u32, i64, u64)>; 2],
    rtt: Vec<f64>,
    pub last_ts: i64,
}

impl Flow {
    fn new(ts: i64) -> Self {
        Flow {
            dirs: Default::default(),
            syn: None,
            synack: None,
            established: false,
            fin: [false; 2],
            pending: Default::default(),
            rtt: Vec::new(),
            last_ts: ts,
        }
    }
}

struct Params {
    reorder_us: i64,
    dup_thr: u32,
}

struct RetransInfo {
    seq: u32,
    len: u32,
    original: Option<(u64, i64)>,
    hole_no: Option<u64>,
    fast: bool,
    is_syn: bool,
    retrans: u64,
    segs: u64,
    dupacks_seen: u64,
}

struct RttInfo {
    ms: f64,
    data_no: u64,
    median_before: Option<f64>,
    samples: usize,
    first: bool,
}

enum Event {
    Syn,
    SynAck,
    Established { s2sa: Option<f64>, sa2a: f64, total: Option<f64>, syn_no: Option<u64> },
    Reset { refused: bool, established: bool, had_data: bool },
    Retrans(RetransInfo),
    Ooo { seq: u32, len: u32, hole_no: u64, ooo: u64, segs: u64 },
    DupAck { ack: u32, n: u32, total: u64, outstanding_to: u32 },
    Gap { seq: u32, missing: u32 },
    Rtt(RttInfo),
}

impl Flow {
    #[allow(clippy::too_many_lines)]
    fn step(&mut self, di: usize, t: &TcpMeta, no: u64, ts: i64, p: &Params, out: &mut Vec<Event>) {
        self.last_ts = ts;
        let oi = 1 - di;
        let f = t.flags;
        let syn = f & TCP_SYN != 0;
        let fin = f & TCP_FIN != 0;
        let rst = f & TCP_RST != 0;
        let ack = f & TCP_ACK != 0;

        if syn && !ack {
            if self.syn.is_none() {
                self.syn = Some((ts, no, di));
                out.push(Event::Syn);
            }
        } else if syn && ack {
            if self.synack.is_none() {
                self.synack = Some((ts, no, di));
                out.push(Event::SynAck);
            }
        } else if ack && !self.established {
            if let Some((sat, _, sad)) = self.synack {
                if di != sad {
                    self.established = true;
                    out.push(Event::Established {
                        s2sa: self.syn.map(|(st, _, _)| ms(sat - st)),
                        sa2a: ms(ts - sat),
                        total: self.syn.map(|(st, _, _)| ms(ts - st)),
                        syn_no: self.syn.map(|(_, n, _)| n),
                    });
                }
            }
        }
        if rst {
            let refused = matches!(self.syn, Some((_, _, sd)) if sd != di) && self.synack.is_none();
            let had_data = self.dirs[0].segs + self.dirs[1].segs > 0;
            out.push(Event::Reset { refused, established: self.established, had_data });
        }
        if fin {
            self.fin[di] = true;
        }

        let plen = t.payload_len;
        let seg_len = plen + syn as u32 + fin as u32;
        if seg_len > 0 && !rst {
            let pure_data = plen > 0 && !syn && !fin;
            let class = self.dirs[di].classify(t.seq, seg_len, ts, no, p.reorder_us, pure_data);
            if !matches!(class, Seg::Keepalive) {
                self.dirs[di].segs += 1;
            }
            let end = t.seq.wrapping_add(seg_len);
            match class {
                Seg::InOrder => {
                    if plen > 0 {
                        self.push_pending(di, end, ts, no);
                    }
                }
                Seg::Keepalive => {}
                Seg::Gap { missing } => {
                    if plen > 0 {
                        self.push_pending(di, end, ts, no);
                    }
                    out.push(Event::Gap { seq: t.seq, missing });
                }
                Seg::Retrans { original, hole_no } => {
                    self.dirs[di].retrans += 1;
                    // Karn's algorithm: ACKs after a retransmission are ambiguous, so drop pending samples.
                    self.pending[di].clear();
                    let fast = self.dirs[oi].dup_count >= p.dup_thr && self.dirs[oi].last_ack == Some(t.seq);
                    out.push(Event::Retrans(RetransInfo {
                        seq: t.seq,
                        len: seg_len,
                        original,
                        hole_no,
                        fast,
                        is_syn: syn,
                        retrans: self.dirs[di].retrans,
                        segs: self.dirs[di].segs,
                        dupacks_seen: self.dirs[oi].dupacks,
                    }));
                }
                Seg::Ooo { hole_no } => {
                    self.dirs[di].ooo += 1;
                    out.push(Event::Ooo { seq: t.seq, len: seg_len, hole_no, ooo: self.dirs[di].ooo, segs: self.dirs[di].segs });
                }
            }
        }

        if ack && !syn {
            while let Some(&(end, sent, data_no)) = self.pending[oi].front() {
                if seq_le(end, t.ack) {
                    self.pending[oi].pop_front();
                    if end == t.ack {
                        let ms_v = ms(ts - sent);
                        let median = median(&self.rtt);
                        let first = self.rtt.is_empty();
                        if self.rtt.len() < MAX_RTT_SAMPLES_PER_FLOW {
                            self.rtt.push(ms_v);
                        }
                        out.push(Event::Rtt(RttInfo { ms: ms_v, data_no, median_before: median, samples: self.rtt.len(), first }));
                    }
                } else {
                    break;
                }
            }
            let other_next = self.dirs[oi].next;
            let d = &mut self.dirs[di];
            if plen == 0 && !fin && !rst {
                let outstanding = other_next.is_some_and(|n| seq_gt(n, t.ack));
                if d.last_ack == Some(t.ack) && d.last_win == t.window && outstanding {
                    d.dup_count += 1;
                    d.dupacks += 1;
                    out.push(Event::DupAck { ack: t.ack, n: d.dup_count, total: d.dupacks, outstanding_to: other_next.unwrap_or(0) });
                } else {
                    d.last_ack = Some(t.ack);
                    d.last_win = t.window;
                    d.dup_count = 0;
                }
            } else if d.last_ack != Some(t.ack) {
                d.last_ack = Some(t.ack);
                d.last_win = t.window;
                d.dup_count = 0;
            }
        }
    }

    fn push_pending(&mut self, di: usize, end: u32, ts: i64, no: u64) {
        let q = &mut self.pending[di];
        if q.len() >= MAX_PENDING_RTT {
            q.pop_front();
        }
        q.push_back((end, ts, no));
    }
}

fn median(v: &[f64]) -> Option<f64> {
    if v.is_empty() {
        return None;
    }
    let mut s = v.to_vec();
    s.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    Some(s[s.len() / 2])
}

/// Where an event happened: the flow, who sent the packet, and the packet itself.
struct EventCtx<'a> {
    key: FlowKey,
    fd: &'a str,
    src: (IpAddr, u16),
    dst: (IpAddr, u16),
    no: u64,
    ts: i64,
}

const LIMIT_CAPTURE_POINT: &str = "Classification is based only on packets visible at the capture point.";

impl Diagnostics {
    pub(super) fn tcp_packet(&mut self, no: u64, ts: i64, d: &Decoded) {
        let (Some(ip), Some(t)) = (d.meta.ip.as_ref(), d.meta.tcp.as_ref()) else { return };
        let (Some(src), Some(dst)) = (ip.src, ip.dst) else { return };
        let (key, di) = FlowKey::new(src, t.sport, dst, t.dport);
        if !self.flows.contains_key(&key) {
            if self.flows.len() >= MAX_DIAG_FLOWS {
                self.evict_flows();
            }
            self.flows.insert(key, Flow::new(ts));
        }
        let params = Params {
            reorder_us: (self.cfg.reorder_window_ms * 1000.0) as i64,
            dup_thr: self.cfg.dupack_threshold,
        };
        let mut events = Vec::new();
        if let Some(flow) = self.flows.get_mut(&key) {
            flow.step(di, t, no, ts, &params, &mut events);
        }
        if events.is_empty() {
            return;
        }
        let fd = key.to_string();
        let ctx = EventCtx { key, fd: &fd, src: (src, t.sport), dst: (dst, t.dport), no, ts };
        for e in events {
            self.tcp_event(e, &ctx);
        }
    }

    fn evict_flows(&mut self) {
        let mut v: Vec<(i64, FlowKey)> = self.flows.iter().map(|(k, f)| (f.last_ts, *k)).collect();
        v.sort_by_key(|x| x.0);
        for (_, k) in v.into_iter().take(MAX_DIAG_FLOWS / 10 + 1) {
            self.flows.remove(&k);
            self.syn_pending.remove(&k);
        }
    }

    fn tcp_event(&mut self, e: Event, c: &EventCtx) {
        match e {
            Event::Syn => {
                self.syn_pending.entry(c.key).or_insert(SynPending { ts: c.ts, no: c.no, server: c.dst.0, server_port: c.dst.1 });
            }
            Event::SynAck => {
                self.syn_pending.remove(&c.key);
            }
            Event::Established { s2sa, sa2a, total, syn_no } => self.on_established(c, s2sa, sa2a, total, syn_no),
            Event::Reset { refused, established, had_data } => self.on_reset(c, refused, established, had_data),
            Event::Retrans(r) => self.on_retransmission(c, &r),
            Event::Ooo { seq, len, hole_no, ooo, segs } => self.on_out_of_order(c, seq, len, hole_no, ooo, segs),
            Event::DupAck { ack, n, total, outstanding_to } => self.on_dup_ack(c, ack, n, total, outstanding_to),
            Event::Gap { seq, missing } => self.on_gap(c, seq, missing),
            Event::Rtt(r) => self.on_rtt(c, &r),
        }
    }

    fn on_established(&mut self, c: &EventCtx, s2sa: Option<f64>, sa2a: f64, total: Option<f64>, syn_no: Option<u64>) {
        self.syn_pending.remove(&c.key);
        self.counters.tcp_handshakes += 1;
        let Some(total) = total else { return };
        let s2sa_text = s2sa.map_or("n/a".to_string(), |v| format!("{v:.3} ms"));
        let syn_text = syn_no.map_or("?".to_string(), |n| n.to_string());
        self.add_latency(LatencyObservation {
            kind: "TCP handshake",
            label: c.fd.to_string(),
            ts_us: c.ts,
            value_ms: total,
            packet_no: c.no,
            measured: true,
            note: format!("SYN→SYN-ACK {s2sa_text}, SYN-ACK→ACK {sa2a:.3} ms (packets {syn_text}–{})", c.no),
        });
        let slow = self.cfg.handshake_slow_ms;
        if total <= slow {
            return;
        }
        let spec = Spec::new(format!("tcp-slow-handshake:{}", c.fd), "Slow TCP handshake", "latency", "TCP")
            .severity(if total > slow * 3.0 { Severity::Medium } else { Severity::Low })
            .confidence(Confidence::High)
            .about(format!("The three-way handshake on {} took {total:.1} ms between the SYN and the final ACK as seen at the capture point (threshold {slow:.0} ms).", c.fd))
            .causes(&[
                "High network round-trip time between the endpoints.",
                "A busy server or firewall delaying the SYN-ACK.",
                "Congestion or queuing on the path.",
            ])
            .advice(&[
                "Compare with ICMP echo RTT to the same host to separate network delay from server delay.",
                "Capture at both ends to see which leg of the handshake is slow.",
            ])
            .limits(&["SYN→SYN-ACK approximates the RTT to the server only if captured near the client; SYN-ACK→ACK approximates the RTT to the client only if captured near the server. The capture location is not known to NEXUS."])
            .in_flow(c.fd)
            .measured("Total handshake", format!("{total:.3} ms"))
            .measured("SYN → SYN-ACK", s2sa_text)
            .measured("SYN-ACK → ACK", format!("{sa2a:.3} ms"));
        self.raise(spec, c.ts, Evidence::pkt(c.no, c.ts, format!("handshake completed after {total:.1} ms (SYN packet {syn_text})")));
    }

    fn on_reset(&mut self, c: &EventCtx, refused: bool, established: bool, had_data: bool) {
        self.counters.tcp_resets += 1;
        let sent = self.rst_by_src.entry(c.src.0).or_insert(0);
        *sent += 1;
        let sent = *sent;
        if refused {
            self.counters.tcp_refused += 1;
            self.syn_pending.remove(&c.key);
            let server = ep(c.src.0, c.src.1);
            let fs = self.fail.entry(c.src).or_default();
            fs.refused += 1;
            push_evidence(&mut fs.evidence, Evidence::pkt(c.no, c.ts, format!("RST from {server} in reply to SYN (connection refused)")));
            self.eval_fail(c.src, c.ts);
        } else {
            let (sev, conf, what) = if established && had_data {
                (Severity::Low, Confidence::High, "A TCP reset ended an established connection that had carried data")
            } else if established {
                (Severity::Low, Confidence::High, "A TCP reset ended an established connection before any data was seen")
            } else {
                (Severity::Informational, Confidence::Medium, "A TCP reset was seen on a connection whose handshake was not observed")
            };
            let sender = ep(c.src.0, c.src.1);
            let spec = Spec::new(format!("tcp-reset:{}", c.fd), "TCP connection reset", "tcp", "TCP")
                .severity(sev)
                .confidence(conf)
                .about(format!("{what} ({}); RST sent by {sender}.", c.fd))
                .causes(&[
                    "The application closed the socket abruptly (common for browsers and some clients).",
                    "The host received data for a connection it no longer knows (timeout, restart, or NAT/firewall state expiry).",
                    "A firewall or middlebox actively rejecting or tearing down the session.",
                ])
                .advice(&[
                    "Check whether the resets align with idle timeouts on firewalls/NAT devices.",
                    "Inspect the application logs on the endpoint that sent the RST.",
                ])
                .limits(&["A single RST is frequently normal. NEXUS cannot tell who initiated the reset logically, only which side sent it."])
                .in_flow(c.fd);
            self.raise(spec, c.ts, Evidence::pkt(c.no, c.ts, format!("RST from {sender}")));
        }
        if sent >= self.cfg.rst_burst_min {
            let key = format!("tcp-rst-burst:{}", c.src.0);
            let spec = Spec::new(key.clone(), "Many TCP resets from one host", "tcp", "TCP")
                .severity(Severity::Medium)
                .about(format!("{} sent {sent} RST segments in this capture.", c.src.0))
                .causes(&[
                    "A service that is down or restarting, or a firewall rejecting traffic with resets.",
                    "A client retrying connections to ports that are closed.",
                ])
                .advice(&[
                    "Check whether the host is running the expected service and listening on the contacted ports.",
                    "Review firewall reject rules on that host.",
                ])
                .limits(&["Resets alone do not indicate malicious activity."]);
            self.raise(spec, c.ts, Evidence::pkt(c.no, c.ts, format!("RST #{sent} from {}", c.src.0)));
            self.set_count(&key, u64::from(sent));
        }
    }

    fn on_retransmission(&mut self, c: &EventCtx, r: &RetransInfo) {
        self.counters.tcp_retransmissions += 1;
        let ratio = r.retrans as f64 / r.segs.max(1) as f64;
        let sev = if r.segs >= self.cfg.ratio_min_segments && ratio >= self.cfg.retrans_ratio_high {
            Severity::High
        } else if r.segs >= self.cfg.ratio_min_segments && ratio >= self.cfg.retrans_ratio_medium {
            Severity::Medium
        } else {
            Severity::Low
        };
        let (seq, len) = (r.seq, r.len);
        let note = match (r.original, r.hole_no) {
            (Some((n0, t0)), _) => format!(
                "{} seq {seq} (len {len}) seen again; first seen in packet {n0} {:.3} ms earlier{}",
                if r.is_syn { "SYN" } else { "segment" },
                ms(c.ts - t0),
                if r.fast { "; preceded by duplicate ACKs (fast-retransmit pattern)" } else { "; no preceding duplicate-ACK run (timeout-like pattern)" }
            ),
            (None, Some(h)) => format!("segment seq {seq} (len {len}) fills a gap first noticed at packet {h}; the original transmission was not observed in this capture"),
            (None, None) => format!("segment seq {seq} (len {len}) overlaps already-acknowledged sequence space; original not in recent history"),
        };
        let key = format!("tcp-retrans:{}", c.fd);
        let spec = Spec::new(key.clone(), if r.is_syn { "TCP SYN retransmitted" } else { "TCP retransmissions" }, "tcp", "TCP")
            .severity(sev)
            .confidence(if r.original.is_some() { Confidence::High } else { Confidence::Medium })
            .about(format!(
                "{} retransmitted segment(s) among {} segments in one direction of {} ({:.2}%). A retransmission means the same sequence range was sent again; it does not show where or why the earlier copy was lost.",
                r.retrans, r.segs, c.fd, ratio * 100.0
            ))
            .causes(&[
                "Segment or ACK lost between the endpoints (congestion, faulty link, wireless interference).",
                "Receiver slow or unreachable, causing a retransmission timeout.",
                "Excess queuing delay causing a spurious timeout (the original may still have arrived).",
            ])
            .advice(&[
                "Run ICMP or application-level tests along the path to look for packet loss or high delay.",
                "Check interface error and discard counters on switches/routers along the path.",
                "Capture at the other endpoint to see whether the original segment arrived.",
            ])
            .limits(&[LIMIT_CAPTURE_POINT])
            .in_flow(c.fd)
            .measured("Retransmission ratio", format!("{:.2}% ({}/{})", ratio * 100.0, r.retrans, r.segs));
        self.raise(spec, c.ts, Evidence::pkt(c.no, c.ts, note));
        self.set_count(&key, r.retrans);
        if r.dupacks_seen > 0 {
            let spec = Spec::new(format!("tcp-loss-recovery:{}", c.fd), "TCP loss-recovery activity (retransmits with duplicate ACKs)", "tcp", "TCP")
                .severity(if sev >= Severity::Medium { Severity::High } else { Severity::Medium })
                .about(format!("On {}, retransmissions occurred together with duplicate ACKs from the receiver ({} seen). This combination is the usual signature of segments being lost or reordered on the path, but it cannot show where.", c.fd, r.dupacks_seen))
                .causes(&[
                    "Packet loss on the path between sender and receiver (congestion or link errors).",
                    "Heavy reordering that the receiver interprets as loss.",
                    "Loss before the capture point, if the capture was taken near the receiver.",
                ])
                .advice(&[
                    "Locate the lossy segment by capturing at several points or testing hop by hop.",
                    "Check for duplex mismatches, saturated links or failing cabling/optics.",
                ])
                .limits(&[LIMIT_CAPTURE_POINT])
                .in_flow(c.fd);
            self.raise(spec, c.ts, Evidence::pkt(c.no, c.ts, "retransmission on a flow that also shows duplicate ACKs"));
        }
    }

    fn on_out_of_order(&mut self, c: &EventCtx, seq: u32, len: u32, hole_no: u64, ooo: u64, segs: u64) {
        self.counters.tcp_out_of_order += 1;
        let ratio = ooo as f64 / segs.max(1) as f64;
        let sev = if segs >= self.cfg.ratio_min_segments && ratio >= self.cfg.retrans_ratio_medium { Severity::Low } else { Severity::Informational };
        let key = format!("tcp-ooo:{}", c.fd);
        let spec = Spec::new(key.clone(), "TCP segments arrived out of order", "tcp", "TCP")
            .severity(sev)
            .about(format!("{ooo} segment(s) on {} arrived after later sequence numbers and shortly after the gap appeared (within {:.0} ms), so they are classified as reordered rather than retransmitted.", c.fd, self.cfg.reorder_window_ms))
            .causes(&[
                "Multipath routing or link aggregation delivering packets over different paths.",
                "Packet scheduling or QoS behaviour in a router or NIC.",
            ])
            .advice(&[
                "Check for ECMP/LAG hashing that splits one flow across links.",
                "If throughput is poor, compare with retransmission counts for the same flow.",
            ])
            .limits(&["Reordering and loss recovery cannot always be told apart: a late arrival after the configured window is counted as a retransmission instead."])
            .in_flow(c.fd);
        self.raise(spec, c.ts, Evidence::pkt(c.no, c.ts, format!("segment seq {seq} (len {len}) arrived after a gap noticed at packet {hole_no}")));
        self.set_count(&key, ooo);
    }

    fn on_dup_ack(&mut self, c: &EventCtx, ack: u32, n: u32, total: u64, outstanding_to: u32) {
        self.counters.tcp_duplicate_acks += 1;
        if n < self.cfg.dupack_threshold {
            return;
        }
        let spec = Spec::new(format!("tcp-dupack:{}", c.fd), "Duplicate TCP acknowledgments", "tcp", "TCP")
            .severity(if n >= self.cfg.dupack_medium_run { Severity::Medium } else { Severity::Low })
            .confidence(Confidence::High)
            .about(format!("The receiver on {} repeated acknowledgment {ack} {n} times in a row while later data was outstanding ({total} duplicate ACKs in this direction). Duplicate ACKs signal that the receiver is missing a segment.", c.fd))
            .causes(&["A segment was lost or delayed and later segments keep arriving (loss or reordering)."])
            .advice(&[
                "Look for a matching retransmission in the other direction of this flow.",
                "Inspect the path for loss with hop-by-hop tests.",
            ])
            .limits(&[LIMIT_CAPTURE_POINT])
            .in_flow(c.fd)
            .measured("Longest observed run", n.to_string());
        self.raise(spec, c.ts, Evidence::pkt(c.no, c.ts, format!("duplicate ACK #{n} for ack={ack}; data outstanding up to seq {outstanding_to}")));
    }

    fn on_gap(&mut self, c: &EventCtx, seq: u32, missing: u32) {
        self.counters.tcp_sequence_gaps += 1;
        let sev = if self.counters.tcp_sequence_gaps >= self.cfg.gap_low_count { Severity::Low } else { Severity::Informational };
        let spec = Spec::new(format!("tcp-gap:{}", c.fd), "TCP sequence gap (data not present in capture)", "tcp", "TCP")
            .severity(sev)
            .confidence(Confidence::Low)
            .about(format!("A segment on {} started {missing} bytes beyond the previous in-order data, so that range is absent from this capture. Absence from a local capture does not by itself prove the data was lost on the network.", c.fd))
            .causes(&[
                "Packets dropped by the local capture mechanism (see capture integrity).",
                "Loss on the path before the capture point.",
                "Asymmetric routing, where part of the stream takes a path the capture cannot see.",
                "Capture started mid-connection.",
            ])
            .advice(&[
                "Check whether capture-buffer drops were reported for this capture.",
                "If the missing range is later retransmitted, see the retransmission finding for this flow.",
            ])
            .limits(&["Never treat a gap alone as network packet loss."])
            .in_flow(c.fd);
        self.raise(spec, c.ts, Evidence::pkt(c.no, c.ts, format!("segment seq {seq} follows an unseen range of {missing} bytes")));
    }

    fn on_rtt(&mut self, c: &EventCtx, r: &RttInfo) {
        let v = r.ms;
        if r.first {
            self.add_latency(LatencyObservation {
                kind: "TCP data→ACK",
                label: c.fd.to_string(),
                ts_us: c.ts,
                value_ms: v,
                packet_no: c.no,
                measured: true,
                note: format!("data packet {} acknowledged by packet {}; delayed ACKs inflate this value", r.data_no, c.no),
            });
        }
        let Some(m) = r.median_before else { return };
        if r.samples < self.cfg.rtt_min_samples || v <= self.cfg.rtt_variation_factor * m || v <= self.cfg.rtt_min_ms {
            return;
        }
        self.add_latency(LatencyObservation {
            kind: "TCP data→ACK (outlier)",
            label: c.fd.to_string(),
            ts_us: c.ts,
            value_ms: v,
            packet_no: c.no,
            measured: true,
            note: format!("{v:.1} ms vs flow median {m:.1} ms"),
        });
        let spec = Spec::new(format!("latency-var:{}", c.fd), "Large latency variation on a TCP flow", "latency", "TCP")
            .severity(if v > self.cfg.rtt_medium_ms { Severity::Medium } else { Severity::Low })
            .about(format!("On {}, the time from a data segment to its matching ACK reached {v:.1} ms, more than {:.0}x the flow's median of {m:.1} ms (over {} samples).", c.fd, self.cfg.rtt_variation_factor, r.samples))
            .causes(&[
                "Queuing delay (bufferbloat) or transient congestion on the path.",
                "Receiver-side delayed ACKs or application stalls.",
                "Wireless retransmissions or route changes.",
            ])
            .advice(&[
                "Correlate the timestamp with bandwidth peaks in Traffic Analytics.",
                "Run a ping to the peer during load to check for queuing delay.",
            ])
            .limits(&["Samples are measured between a data packet and its ACK at the capture point; they include receiver ACK delay and are not pure network RTT."])
            .in_flow(c.fd)
            .measured("Outlier sample", format!("{v:.1} ms"))
            .measured("Flow median", format!("{m:.1} ms"));
        self.raise(spec, c.ts, Evidence::pkt(c.no, c.ts, format!("ACK {v:.1} ms after data packet {} (median {m:.1} ms)", r.data_no)));
    }

    fn eval_fail(&mut self, k: (IpAddr, u16), ts: i64) {
        let Some(fs) = self.fail.get(&k) else { return };
        let total = fs.refused + fs.unanswered;
        if total < self.cfg.conn_fail_min {
            return;
        }
        let (refused, unanswered) = (fs.refused, fs.unanswered);
        let evidence = fs.evidence.last().cloned().unwrap_or(Evidence::agg(ts, "connection failure"));
        let never_seen = !self.seen_src.contains(&k.0);
        let (conf, extra) = if refused >= unanswered && refused > 0 {
            (Confidence::High, "The destination actively answered with TCP resets, so it was reachable but not accepting connections on that port.")
        } else if never_seen {
            (Confidence::Low, "No packet from this address appears anywhere in the capture, which fits a down host, a drop-policy firewall, or a return path the capture cannot see.")
        } else {
            (Confidence::Medium, "The destination was seen sending other traffic, so a service-specific block or backlog is more likely than an unreachable host.")
        };
        let key = format!("conn-fail:{}:{}", k.0, k.1);
        let spec = Spec::new(key.clone(), "Repeated connection failures", "tcp", "TCP")
            .severity(if total >= self.cfg.conn_fail_high { Severity::High } else { Severity::Medium })
            .confidence(conf)
            .about(format!("{total} connection attempt(s) to {} failed: {refused} refused with RST and {unanswered} received no SYN-ACK or RST within {:.0} s. {extra}", ep(k.0, k.1), self.cfg.syn_timeout_s))
            .causes(&[
                "The service is not running or not listening on that port.",
                "A firewall is rejecting (RST) or silently dropping (no reply) the connections.",
                "The destination host or route is down.",
                "Replies take a different path than the one being captured (asymmetric routing).",
            ])
            .advice(&[
                "Verify the service is running and listening (e.g. netstat / ss on the server).",
                "Test reachability from another host and check firewall/security-group rules.",
                "If only unanswered SYNs are seen, capture on the server side to see whether SYNs arrive.",
            ])
            .limits(&["An unanswered SYN is a lack of observation; it is not proof that the packet was dropped by the network."])
            .measured("Refused (RST)", refused.to_string())
            .measured("No reply", unanswered.to_string());
        self.raise(spec, ts, evidence);
        self.set_count(&key, u64::from(total));
    }

    pub(super) fn expire_syns(&mut self, now: i64) {
        let timeout = (self.cfg.syn_timeout_s * 1_000_000.0) as i64;
        let expired: Vec<FlowKey> = self.syn_pending.iter().filter(|(_, s)| now - s.ts >= timeout).map(|(k, _)| *k).collect();
        for k in expired {
            let Some(s) = self.syn_pending.remove(&k) else { continue };
            let note = format!("SYN to {} had no SYN-ACK or RST within {:.1} s", ep(s.server, s.server_port), self.cfg.syn_timeout_s);
            let fs = self.fail.entry((s.server, s.server_port)).or_default();
            fs.unanswered += 1;
            push_evidence(&mut fs.evidence, Evidence::pkt(s.no, s.ts, note));
            self.eval_fail((s.server, s.server_port), s.ts);
        }
    }
}
