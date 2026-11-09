//! Real-time traffic statistics derived exclusively from decoded packets.
//! All rates are computed from packet timestamps (offline) or wall clock (live), never invented.

use crate::constants::*;
use serde::Serialize;
use std::collections::{HashMap, VecDeque};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    Tcp,
    Udp,
    Icmp,
    Other,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Bucket {
    pub sec: i64,
    pub packets: u64,
    pub bytes: u64,
    pub tcp: u64,
    pub udp: u64,
    pub icmp: u64,
    pub other: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Count {
    pub name: String,
    pub packets: u64,
    pub bytes: u64,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct AnalyticsSnapshot {
    pub total_packets: u64,
    pub total_bytes: u64,
    pub packets_per_sec: f64,
    pub bytes_per_sec: f64,
    pub tcp_packets: u64,
    pub udp_packets: u64,
    pub icmp_packets: u64,
    pub other_packets: u64,
    pub protocols: Vec<Count>,
    pub top_sources: Vec<Count>,
    pub top_destinations: Vec<Count>,
    pub total_connections: usize,
    pub active_connections: usize,
    /// Packets not attributed to a top-talker/connection entry because tracking tables were full.
    pub untracked_packets: u64,
    pub series: Vec<Bucket>,
    pub window_s: usize,
    pub first_ts_us: Option<i64>,
    pub last_ts_us: Option<i64>,
}

#[derive(Default)]
pub struct Analytics {
    total_packets: u64,
    total_bytes: u64,
    families: [u64; 4],
    protocols: HashMap<String, (u64, u64)>,
    sources: HashMap<String, (u64, u64)>,
    destinations: HashMap<String, (u64, u64)>,
    flows: HashMap<String, i64>,
    untracked: u64,
    series: VecDeque<Bucket>,
    first_ts: Option<i64>,
    last_ts: Option<i64>,
}

fn bump(map: &mut HashMap<String, (u64, u64)>, key: &str, bytes: u64, untracked: &mut u64) {
    if let Some(v) = map.get_mut(key) {
        v.0 += 1;
        v.1 += bytes;
    } else if map.len() < MAX_TRACKED_ENDPOINTS {
        map.insert(key.to_string(), (1, bytes));
    } else {
        *untracked += 1;
    }
}

impl Analytics {
    pub fn new() -> Self {
        Self::default()
    }

    #[allow(clippy::too_many_arguments)] // one flat call per packet keeps the hot path allocation-free
    pub fn record(&mut self, ts_us: i64, len: u32, family: Family, label: &str, src: &str, dst: &str, flow: Option<&str>) {
        let bytes = len as u64;
        self.total_packets += 1;
        self.total_bytes += bytes;
        self.first_ts = Some(self.first_ts.map_or(ts_us, |f| f.min(ts_us)));
        self.last_ts = Some(self.last_ts.map_or(ts_us, |l| l.max(ts_us)));
        let fi = match family {
            Family::Tcp => 0,
            Family::Udp => 1,
            Family::Icmp => 2,
            Family::Other => 3,
        };
        self.families[fi] += 1;

        let mut untracked = 0;
        bump(&mut self.protocols, label, bytes, &mut untracked);
        if !src.is_empty() {
            bump(&mut self.sources, src, bytes, &mut untracked);
        }
        if !dst.is_empty() {
            bump(&mut self.destinations, dst, bytes, &mut untracked);
        }
        if let Some(f) = flow {
            if let Some(t) = self.flows.get_mut(f) {
                *t = (*t).max(ts_us);
            } else {
                if self.flows.len() >= MAX_TRACKED_FLOWS {
                    let cutoff = ts_us - STALE_ENTRY_US;
                    self.flows.retain(|_, t| *t >= cutoff);
                }
                if self.flows.len() < MAX_TRACKED_FLOWS {
                    self.flows.insert(f.to_string(), ts_us);
                } else {
                    untracked += 1;
                }
            }
        }
        self.untracked += untracked.min(1);

        let sec = ts_us.div_euclid(1_000_000);
        // Packets arrive almost in order; search backwards for the bucket.
        let idx = self.series.iter().rposition(|b| b.sec <= sec);
        let b = match idx {
            Some(i) if self.series[i].sec == sec => &mut self.series[i],
            Some(i) => {
                self.series.insert(i + 1, Bucket { sec, ..Default::default() });
                &mut self.series[i + 1]
            }
            None => {
                self.series.push_front(Bucket { sec, ..Default::default() });
                &mut self.series[0]
            }
        };
        b.packets += 1;
        b.bytes += bytes;
        match family {
            Family::Tcp => b.tcp += 1,
            Family::Udp => b.udp += 1,
            Family::Icmp => b.icmp += 1,
            Family::Other => b.other += 1,
        }
        while self.series.len() > MAX_TIMESERIES_SECONDS {
            self.series.pop_front();
        }
    }

    pub fn total_packets(&self) -> u64 {
        self.total_packets
    }

    pub fn protocol_packets(&self, label: &str) -> u64 {
        self.protocols.get(label).map_or(0, |v| v.0)
    }

    /// Per-second byte counts for the most recent complete seconds, oldest first.
    pub fn recent_byte_series(&self, end_sec: i64, n: usize) -> Vec<(i64, u64)> {
        let start = end_sec - n as i64 + 1;
        let map: HashMap<i64, u64> = self.series.iter().map(|b| (b.sec, b.bytes)).collect();
        (start..=end_sec).map(|s| (s, map.get(&s).copied().unwrap_or(0))).collect()
    }

    pub fn last_ts(&self) -> Option<i64> {
        self.last_ts
    }

    pub fn first_ts(&self) -> Option<i64> {
        self.first_ts
    }

    pub fn snapshot(&self, window_s: usize, now_us: Option<i64>) -> AnalyticsSnapshot {
        let live = now_us.is_some();
        let ref_us = now_us.or(self.last_ts);
        let mut series = Vec::new();
        let (mut pps, mut bps) = (0.0, 0.0);
        if let Some(r) = ref_us {
            let end_sec = r.div_euclid(1_000_000);
            let last_complete = if live { end_sec - 1 } else { end_sec };
            let start = last_complete - window_s as i64 + 1;
            let map: HashMap<i64, &Bucket> = self.series.iter().map(|b| (b.sec, b)).collect();
            for s in start..=last_complete {
                series.push(map.get(&s).map(|b| (*b).clone()).unwrap_or(Bucket { sec: s, ..Default::default() }));
            }
            let tail = series.len().min(3);
            if tail > 0 {
                let t = &series[series.len() - tail..];
                pps = t.iter().map(|b| b.packets).sum::<u64>() as f64 / tail as f64;
                bps = t.iter().map(|b| b.bytes).sum::<u64>() as f64 / tail as f64;
            }
        }
        let active_cutoff = ref_us.map_or(i64::MIN, |r| r - ACTIVE_FLOW_WINDOW_US);
        AnalyticsSnapshot {
            total_packets: self.total_packets,
            total_bytes: self.total_bytes,
            packets_per_sec: pps,
            bytes_per_sec: bps,
            tcp_packets: self.families[0],
            udp_packets: self.families[1],
            icmp_packets: self.families[2],
            other_packets: self.families[3],
            protocols: top(&self.protocols, 16),
            top_sources: top(&self.sources, 10),
            top_destinations: top(&self.destinations, 10),
            total_connections: self.flows.len(),
            active_connections: self.flows.values().filter(|t| **t >= active_cutoff).count(),
            untracked_packets: self.untracked,
            series,
            window_s,
            first_ts_us: self.first_ts,
            last_ts_us: self.last_ts,
        }
    }
}

fn top(map: &HashMap<String, (u64, u64)>, n: usize) -> Vec<Count> {
    let mut v: Vec<Count> = map
        .iter()
        .map(|(k, (p, b))| Count { name: k.clone(), packets: *p, bytes: *b })
        .collect();
    v.sort_by(|a, b| b.bytes.cmp(&a.bytes).then(b.packets.cmp(&a.packets)).then(a.name.cmp(&b.name)));
    v.truncate(n);
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(a: &mut Analytics, sec: i64, len: u32, fam: Family, label: &str, src: &str, flow: Option<&str>) {
        a.record(sec * 1_000_000 + 500, len, fam, label, src, "9.9.9.9", flow);
    }

    #[test]
    fn totals_and_distribution_reflect_recorded_packets() {
        let mut a = Analytics::new();
        rec(&mut a, 10, 100, Family::Tcp, "TCP", "1.1.1.1", Some("a"));
        rec(&mut a, 10, 200, Family::Tcp, "TCP", "1.1.1.1", Some("a"));
        rec(&mut a, 11, 50, Family::Udp, "DNS", "2.2.2.2", Some("b"));
        rec(&mut a, 12, 60, Family::Other, "ARP", "3.3.3.3", None);
        let s = a.snapshot(60, None);
        assert_eq!((s.total_packets, s.total_bytes), (4, 410));
        assert_eq!((s.tcp_packets, s.udp_packets, s.icmp_packets, s.other_packets), (2, 1, 0, 1));
        assert_eq!(s.total_connections, 2);
        let tcp = s.protocols.iter().find(|c| c.name == "TCP").unwrap();
        assert_eq!((tcp.packets, tcp.bytes), (2, 300));
        assert_eq!(s.top_sources[0].name, "1.1.1.1");
        assert_eq!(s.top_destinations[0].packets, 4);
    }

    #[test]
    fn offline_rate_uses_packet_time_over_last_three_seconds() {
        let mut a = Analytics::new();
        for sec in 10..=12 {
            for _ in 0..10 {
                rec(&mut a, sec, 100, Family::Tcp, "TCP", "1.1.1.1", None);
            }
        }
        let s = a.snapshot(60, None);
        assert_eq!(s.packets_per_sec, 10.0);
        assert_eq!(s.bytes_per_sec, 1000.0);
        assert_eq!(s.series.len(), 60);
        assert_eq!(s.series.last().unwrap().sec, 12);
    }

    #[test]
    fn live_rate_decays_to_zero_when_traffic_stops() {
        let mut a = Analytics::new();
        for _ in 0..30 {
            rec(&mut a, 100, 100, Family::Tcp, "TCP", "1.1.1.1", None);
        }
        let now = 200 * 1_000_000;
        let s = a.snapshot(30, Some(now));
        assert_eq!(s.packets_per_sec, 0.0);
        assert_eq!(s.series.last().unwrap().sec, 199);
    }

    #[test]
    fn active_connections_are_those_seen_recently() {
        let mut a = Analytics::new();
        rec(&mut a, 0, 10, Family::Tcp, "TCP", "1.1.1.1", Some("old"));
        rec(&mut a, 100, 10, Family::Tcp, "TCP", "1.1.1.1", Some("new"));
        let s = a.snapshot(60, None);
        assert_eq!((s.total_connections, s.active_connections), (2, 1));
    }

    #[test]
    fn out_of_order_timestamps_keep_series_sorted() {
        let mut a = Analytics::new();
        rec(&mut a, 12, 10, Family::Tcp, "TCP", "a", None);
        rec(&mut a, 10, 10, Family::Tcp, "TCP", "a", None);
        rec(&mut a, 11, 10, Family::Tcp, "TCP", "a", None);
        let secs: Vec<i64> = a.series.iter().map(|b| b.sec).collect();
        assert_eq!(secs, vec![10, 11, 12]);
    }

    #[test]
    fn empty_snapshot_is_zeroed() {
        let s = Analytics::new().snapshot(60, None);
        assert_eq!(s.total_packets, 0);
        assert!(s.series.is_empty());
        assert_eq!(s.packets_per_sec, 0.0);
    }
}
