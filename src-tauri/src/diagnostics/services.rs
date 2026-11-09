//! DNS, ICMP and traffic-level checks.

use super::*;
use crate::decoder::dns_rcode_name;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct DnsKey {
    client: IpAddr,
    server: IpAddr,
    id: u16,
}

pub(crate) struct DnsPending {
    ts: i64,
    no: u64,
    qname: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct PingKey {
    src: IpAddr,
    dst: IpAddr,
    id: u16,
    seq: u16,
}

/// DNS response codes: NXDOMAIN is common at low volume, so it needs more repeats than server failures.
const RCODE_NXDOMAIN: u8 = 3;
const NXDOMAIN_REPORT_MIN: u32 = 5;
const SERVER_ERROR_REPORT_MIN: u32 = 2;
/// Seconds of per-second history used as the traffic baseline.
const SPIKE_BASELINE_S: usize = 60;

impl Diagnostics {
    pub(super) fn dns_packet(&mut self, no: u64, ts: i64, d: &Decoded) {
        let (Some(ip), Some(dns)) = (d.meta.ip.as_ref(), d.meta.dns.as_ref()) else { return };
        let (Some(src), Some(dst)) = (ip.src, ip.dst) else { return };
        if !dns.response {
            self.counters.dns_queries += 1;
            if self.dns_pending.len() >= MAX_TRACKED_DNS {
                let cutoff = ts - (self.cfg.dns_timeout_s * 1_000_000.0) as i64;
                self.dns_pending.retain(|_, p| p.ts >= cutoff);
            }
            if self.dns_pending.len() < MAX_TRACKED_DNS {
                self.dns_pending
                    .entry(DnsKey { client: src, server: dst, id: dns.id })
                    .or_insert(DnsPending { ts, no, qname: dns.qname.to_lowercase() });
            }
            return;
        }
        self.counters.dns_responses += 1;
        let key = DnsKey { client: dst, server: src, id: dns.id };
        let matched = match self.dns_pending.get(&key) {
            Some(p) if p.qname == dns.qname.to_lowercase() => self.dns_pending.remove(&key),
            _ => None,
        };
        if let Some(q) = matched {
            self.dns_response_time(no, ts, src, &dns.qname, &q);
        }
        if dns.rcode != 0 {
            self.dns_error_code(no, ts, src, dns.rcode, &dns.qname);
        }
    }

    fn dns_response_time(&mut self, no: u64, ts: i64, server: IpAddr, qname: &str, q: &DnsPending) {
        let delta = ms(ts - q.ts);
        self.add_latency(LatencyObservation {
            kind: "DNS",
            label: format!("{qname} via {server}"),
            ts_us: ts,
            value_ms: delta,
            packet_no: no,
            measured: true,
            note: format!("query packet {} → response packet {no}", q.no),
        });
        let slow = self.cfg.dns_slow_ms;
        if delta <= slow {
            return;
        }
        let spec = Spec::new(format!("dns-slow:{server}"), "Slow DNS responses", "dns", "DNS")
            .severity(if delta > slow * 4.0 { Severity::Medium } else { Severity::Low })
            .confidence(Confidence::High)
            .about(format!("DNS server {server} answered {qname} after {delta:.1} ms (threshold {slow:.0} ms), measured between the matched query and response packets."))
            .causes(&[
                "The resolver had to query upstream servers (uncached name).",
                "Network latency or loss between client and resolver.",
                "An overloaded or distant resolver.",
            ])
            .advice(&[
                "Repeat the lookup to see whether the cached answer is faster.",
                "Try an alternative or closer resolver and compare response times.",
            ])
            .limits(&["The interval includes any delay before the query reached the capture point if captured away from the client."])
            .measured("Latest response time", format!("{delta:.1} ms"));
        self.raise(spec, ts, Evidence::pkt(no, ts, format!("{qname} answered in {delta:.1} ms (query packet {})", q.no)));
    }

    fn dns_error_code(&mut self, no: u64, ts: i64, server: IpAddr, rcode: u8, qname: &str) {
        let n = self.dns_codes.entry((server, rcode)).or_insert(0);
        *n += 1;
        let n = *n;
        let name = dns_rcode_name(rcode);
        let (min, sev) = if rcode == RCODE_NXDOMAIN { (NXDOMAIN_REPORT_MIN, Severity::Low) } else { (SERVER_ERROR_REPORT_MIN, Severity::Medium) };
        if n < min {
            return;
        }
        let causes: &[&str] = match rcode {
            RCODE_NXDOMAIN => &[
                "Clients querying names that do not exist (typos, stale configuration, search-suffix expansion).",
                "Service discovery or software probing for optional hostnames.",
            ],
            2 => &[
                "The resolver failed to reach upstream servers or validate DNSSEC.",
                "The authoritative server for the zone is down or misconfigured.",
            ],
            5 => &["The server refuses recursion or queries from this client by policy."],
            _ => &["The server rejected or could not process the query."],
        };
        let key = format!("dns-rcode:{server}:{name}");
        let spec = Spec::new(key.clone(), format!("Repeated DNS {name} responses"), "dns", "DNS")
            .severity(sev)
            .confidence(Confidence::High)
            .about(format!("DNS server {server} returned {name} {n} times. Latest query: {qname}."))
            .causes(causes)
            .advice(&[
                "Check resolver health and upstream connectivity.",
                "Review which names are failing and whether the client configuration references them intentionally.",
            ])
            .limits(&["Error responses are normal at low volume; thresholds are configurable."]);
        self.raise(spec, ts, Evidence::pkt(no, ts, format!("{name} for {qname}")));
        self.set_count(&key, u64::from(n));
    }

    pub(super) fn expire_dns(&mut self, now: i64) {
        let timeout = (self.cfg.dns_timeout_s * 1_000_000.0) as i64;
        let expired: Vec<DnsKey> = self.dns_pending.iter().filter(|(_, p)| now - p.ts >= timeout).map(|(k, _)| *k).collect();
        for k in expired {
            let Some(p) = self.dns_pending.remove(&k) else { continue };
            let entry = self.dns_unanswered.entry(k.server).or_insert((0, Vec::new()));
            entry.0 += 1;
            let n = entry.0;
            let ev = Evidence::pkt(p.no, p.ts, format!("query for {} had no matching response within {:.0} s", p.qname, self.cfg.dns_timeout_s));
            push_evidence(&mut entry.1, ev.clone());
            if n < self.cfg.dns_unanswered_min {
                continue;
            }
            let key = format!("dns-unanswered:{}", k.server);
            let spec = Spec::new(key.clone(), "DNS queries without responses", "dns", "DNS")
                .severity(Severity::Medium)
                .confidence(if self.seen_src.contains(&k.server) { Confidence::Medium } else { Confidence::Low })
                .about(format!("{n} DNS queries sent to {} received no matching response in the capture within {:.0} s. A missing response in a capture is not proof the server never answered.", k.server, self.cfg.dns_timeout_s))
                .causes(&[
                    "The DNS server is unreachable, overloaded or filtering queries.",
                    "Queries or replies were lost on the path.",
                    "Responses return on a path the capture cannot see (asymmetric routing), or the capture dropped them locally.",
                ])
                .advice(&[
                    "Test the resolver directly (e.g. nslookup against that server) from this host.",
                    "Check for a firewall blocking UDP/TCP 53 to or from the resolver.",
                ])
                .limits(&["Responses that arrived after the timeout are not matched to their query."]);
            self.raise(spec, p.ts, ev);
            self.set_count(&key, u64::from(n));
        }
    }

    pub(super) fn icmp_packet(&mut self, no: u64, ts: i64, d: &Decoded) {
        let (Some(ip), Some(m)) = (d.meta.ip.as_ref(), d.meta.icmp.as_ref()) else { return };
        let (Some(src), Some(dst)) = (ip.src, ip.dst) else { return };
        let (req, rep) = if m.v6 { (128, 129) } else { (8, 0) };
        if m.typ == req {
            if let (Some(id), Some(seq)) = (m.id, m.seq) {
                if self.pings.len() >= MAX_TRACKED_PINGS {
                    let cutoff = ts - STALE_ENTRY_US;
                    self.pings.retain(|_, v| v.0 >= cutoff);
                }
                if self.pings.len() < MAX_TRACKED_PINGS {
                    self.pings.insert(PingKey { src, dst, id, seq }, (ts, no));
                }
            }
            return;
        }
        if m.typ == rep {
            if let (Some(id), Some(seq)) = (m.id, m.seq) {
                if let Some((t0, n0)) = self.pings.remove(&PingKey { src: dst, dst: src, id, seq }) {
                    self.add_latency(LatencyObservation {
                        kind: "ICMP echo",
                        label: format!("{dst} → {src}"),
                        ts_us: ts,
                        value_ms: ms(ts - t0),
                        packet_no: no,
                        measured: true,
                        note: format!("request packet {n0} → reply packet {no} (id {id}, seq {seq})"),
                    });
                }
            }
            return;
        }
        let Some((title, sev, causes, recs)) = icmp_error_info(m.v6, m.typ, m.code) else { return };
        self.counters.icmp_errors += 1;
        let target = m.orig_dst.map_or("unknown destination".to_string(), |a| match m.orig_dport {
            Some(p) => format!("{a}:{p}"),
            None => a.to_string(),
        });
        let key = format!("icmp:{}:{}:{}:{}", m.v6, m.typ, m.code, m.orig_dst.map_or(String::new(), |a| a.to_string()));
        let spec = Spec::new(key, title, "icmp", if m.v6 { "ICMPv6" } else { "ICMP" })
            .severity(sev)
            .confidence(Confidence::High)
            .about(format!("{src} sent an ICMP error ({}) concerning traffic to {target}. The sender is the device that detected the problem (a router or the destination host).", d.info))
            .causes(&causes)
            .advice(&recs)
            .limits(&["The ICMP message reports what the sender observed; NEXUS cannot verify the underlying condition."]);
        self.raise(spec, ts, Evidence::pkt(no, ts, format!("{} from {src} about {target}", d.info)));
    }

    pub(super) fn traffic_checks(&mut self, now: i64, an: &Analytics) {
        let Some(first) = an.first_ts() else { return };
        let first_sec = first.div_euclid(1_000_000);
        let last_complete = now.div_euclid(1_000_000) - 1;
        let start = if self.last_spike_sec == i64::MIN { first_sec } else { self.last_spike_sec + 1 };
        if last_complete >= start {
            self.spike_scan(an, first_sec, start, last_complete);
            self.last_spike_sec = last_complete;
        }
        self.protocol_mix_check(now, an);
    }

    fn spike_scan(&mut self, an: &Analytics, first_sec: i64, start: i64, last_complete: i64) {
        let span = ((last_complete - start + 1) as usize).min(MAX_TIMESERIES_SECONDS - SPIKE_BASELINE_S);
        let series = an.recent_byte_series(last_complete, span + SPIKE_BASELINE_S);
        for i in SPIKE_BASELINE_S..series.len() {
            let (sec, bytes) = series[i];
            if (sec - first_sec) < self.cfg.spike_min_history_s as i64 || bytes < self.cfg.spike_min_bytes {
                continue;
            }
            let base = &series[i - SPIKE_BASELINE_S..i];
            let n = SPIKE_BASELINE_S as f64;
            let mean = base.iter().map(|x| x.1 as f64).sum::<f64>() / n;
            let sd = (base.iter().map(|x| (x.1 as f64 - mean).powi(2)).sum::<f64>() / n).sqrt();
            let b = bytes as f64;
            if b <= mean + self.cfg.spike_sigma * sd {
                continue;
            }
            let ts = sec * 1_000_000;
            let large = b > mean + self.cfg.spike_high_sigma * sd.max(1.0) && b > self.cfg.spike_high_ratio * mean.max(1.0);
            let spec = Spec::new("traffic-spike", "Traffic volume spike", "traffic", "Multiple")
                .severity(if large { Severity::Low } else { Severity::Informational })
                .about(format!("Per-second traffic exceeded the trailing {SPIKE_BASELINE_S} s baseline by more than {:.0} standard deviations. Latest: {bytes} bytes in one second vs mean {mean:.0} ± {sd:.0}.", self.cfg.spike_sigma))
                .causes(&[
                    "Large transfers such as downloads, backups, updates or streaming starting.",
                    "A burst caused by retransmissions or a misbehaving application.",
                    "A scan or flood; this requires additional evidence and is not implied by volume alone.",
                ])
                .advice(&[
                    "Use Traffic Analytics top talkers for that time window to see which hosts and protocols contributed.",
                    "Check whether the spike coincides with scheduled jobs or user activity.",
                ])
                .limits(&["A spike is a statistical observation; most spikes are legitimate bulk transfers."])
                .measured("Spike second", format!("{bytes} bytes"))
                .measured("Baseline mean", format!("{mean:.0} bytes/s"));
            self.raise(spec, ts, Evidence::agg(ts, format!("{bytes} bytes in second {sec} vs baseline {mean:.0} ± {sd:.0}")));
        }
    }

    fn protocol_mix_check(&mut self, now: i64, an: &Analytics) {
        let total = an.total_packets();
        if total < self.cfg.mix_min_packets {
            return;
        }
        let shares: [(&str, &str, u64); 3] = [
            ("mix-icmp", "ICMP", an.protocol_packets("ICMP") + an.protocol_packets("ICMPv6")),
            ("mix-arp", "ARP", an.protocol_packets("ARP")),
            ("mix-dns", "DNS", an.protocol_packets("DNS")),
        ];
        for (key, name, n) in shares {
            let share = n as f64 / total as f64;
            if share <= self.cfg.mix_share || self.has_finding(key) {
                continue;
            }
            let causes: &[&str] = match name {
                "ICMP" => &["Active ping or traceroute testing, or monitoring probes.", "ICMP errors caused by an unreachable service."],
                "ARP" => &["A capture dominated by local-segment discovery.", "Address resolution storms from a misbehaving device or address conflict."],
                _ => &["Heavy name-resolution activity, possibly a retry loop or resolver problem."],
            };
            let spec = Spec::new(key, format!("Unusual protocol mix: {name} dominates"), "traffic", "Multiple")
                .severity(Severity::Low)
                .about(format!("{name} accounts for {:.0}% of {total} captured packets ({n}), above the {:.0}% threshold. In most networks this share is far lower.", share * 100.0, self.cfg.mix_share * 100.0))
                .causes(causes)
                .advice(&["Inspect the packets of that protocol in Packet Explorer to identify the senders."])
                .limits(&["A short or filtered capture can have any protocol mix; this does not by itself indicate a fault."])
                .measured(format!("{name} share"), format!("{:.1}%", share * 100.0));
            self.raise(spec, now, Evidence::agg(now, format!("{n} of {total} packets are {name}")));
        }
    }
}

type IcmpInfo = (&'static str, Severity, Vec<&'static str>, Vec<&'static str>);

fn icmp_error_info(v6: bool, typ: u8, code: u8) -> Option<IcmpInfo> {
    let unreachable_net = (
        "ICMP destination unreachable (network/host)",
        Severity::Medium,
        vec!["No route to the destination from the reporting router.", "The destination host is down or its link is disconnected.", "A routing misconfiguration or withdrawn route."],
        vec!["Check routing tables on the reporting device.", "Confirm the destination host is online and reachable on its subnet."],
    );
    let port = (
        "ICMP port unreachable",
        Severity::Low,
        vec!["No service is listening on the contacted UDP port.", "A host firewall rejecting the traffic with ICMP."],
        vec!["Verify the service is running and bound to the expected port.", "Check host firewall reject rules."],
    );
    let admin = (
        "ICMP administratively prohibited",
        Severity::Low,
        vec!["A firewall or ACL policy is rejecting the traffic."],
        vec!["Review firewall/ACL rules on the reporting device."],
    );
    let frag = (
        "Path MTU problem (fragmentation needed / packet too big)",
        Severity::Medium,
        vec!["A packet larger than the path MTU was sent with Don't-Fragment set.", "A tunnel or VPN with a smaller MTU than the endpoints assume."],
        vec!["Check MTU on the reporting link and enable path MTU discovery or clamp TCP MSS.", "Look for stalls on large transfers that follow this message."],
    );
    let ttl = (
        "ICMP time exceeded",
        Severity::Low,
        vec!["Traceroute or similar diagnostics (expected).", "A routing loop causing TTL/hop limit to expire."],
        vec!["If not running traceroute, check for routing loops along the path."],
    );
    if !v6 {
        match (typ, code) {
            (3, 0) | (3, 1) => Some(unreachable_net),
            (3, 3) => Some(port),
            (3, 4) => Some(frag),
            (3, 9) | (3, 10) | (3, 13) => Some(admin),
            (3, _) => Some((
                "ICMP destination unreachable",
                Severity::Low,
                vec!["The destination or an intermediate device could not deliver the packet."],
                vec!["Inspect the ICMP code and the reporting device."],
            )),
            (11, _) => Some(ttl),
            _ => None,
        }
    } else {
        match (typ, code) {
            (1, 0) | (1, 3) => Some(unreachable_net),
            (1, 4) => Some(port),
            (1, 1) => Some(admin),
            (1, _) => Some((
                "ICMPv6 destination unreachable",
                Severity::Low,
                vec!["The destination or an intermediate device could not deliver the packet."],
                vec!["Inspect the ICMPv6 code and the reporting device."],
            )),
            (2, _) => Some(frag),
            (3, _) => Some(ttl),
            _ => None,
        }
    }
}
