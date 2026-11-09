//! The processing engine: owns the bounded packet store and feeds decoded packets to the
//! analytics and diagnostics components. All mutation happens under one lock, taken per batch.

use crate::analytics::{Analytics, AnalyticsSnapshot, Family};
use crate::config::Settings;
use crate::constants::*;
use crate::decoder::{self, hex_string, tcp_flags_string, Anomaly, Layer};
use crate::diagnostics::{CaptureDrops, DiagSnapshot, Diagnostics};
use crate::error::{NexusError, Result};
use crate::pcap_io::{make_writer, PacketSink, RawPacket};
use serde::Serialize;
use std::collections::VecDeque;
use std::fs::File;
use std::io::BufWriter;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize)]
pub struct PacketRow {
    pub no: u64,
    pub ts_us: i64,
    pub src: String,
    pub dst: String,
    pub sport: Option<u16>,
    pub dport: Option<u16>,
    pub protocol: String,
    pub length: u32,
    pub info: String,
    pub anomaly: bool,
    pub flags: Option<String>,
}

struct StoredPacket {
    row: PacketRow,
    data: Box<[u8]>,
    orig_len: u32,
    dlt: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct PacketDetail {
    pub row: PacketRow,
    pub layers: Vec<Layer>,
    pub anomalies: Vec<Anomaly>,
    /// Hex of the retained bytes; payload bytes are "**" when display redaction is on.
    pub hex: String,
    pub payload_offset: usize,
    pub captured_len: usize,
    pub original_len: u32,
    pub redacted: bool,
    pub payload_preview: String,
    pub cut_by_retention: bool,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct SourceInfo {
    /// "none", "live" or "file"
    pub kind: &'static str,
    pub name: String,
    pub interface: Option<String>,
    pub filter: String,
    pub started_ms: i64,
    pub ended_ms: Option<i64>,
}

struct Spool {
    sink: Box<dyn PacketSink + Send>,
    written: u64,
    cap: u64,
    capped: bool,
}

pub struct Engine {
    pub settings: Settings,
    packets: VecDeque<StoredPacket>,
    next_no: u64,
    dlt: u32,
    pub analytics: Analytics,
    pub diag: Diagnostics,
    pub source: SourceInfo,
    pub live: bool,
    spool: Option<Spool>,
    pub spool_path: Option<PathBuf>,
    pub spool_note: Option<String>,
    pub view_window_s: usize,
    pub evicted: u64,
}

pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as i64)
}

impl Engine {
    pub fn new(settings: Settings) -> Self {
        let settings = settings.sanitized();
        Engine {
            diag: Diagnostics::new(settings.diag.clone()),
            view_window_s: settings.analytics_window_s,
            settings,
            packets: VecDeque::new(),
            next_no: 0,
            dlt: DLT_EN10MB,
            analytics: Analytics::new(),
            source: SourceInfo { kind: "none", ..Default::default() },
            live: false,
            spool: None,
            spool_path: None,
            spool_note: None,
            evicted: 0,
        }
    }

    /// Discard the current capture and prepare for a new one.
    pub fn reset(&mut self, settings: Settings, source: SourceInfo, live: bool) {
        let settings = settings.sanitized();
        self.diag = Diagnostics::new(settings.diag.clone());
        self.view_window_s = settings.analytics_window_s;
        self.settings = settings;
        self.packets.clear();
        self.next_no = 0;
        self.analytics = Analytics::new();
        self.source = source;
        self.live = live;
        self.spool = None;
        self.spool_path = None;
        self.spool_note = None;
        self.evicted = 0;
    }

    /// Start spooling retained packets to a capture file (live sessions).
    pub fn start_spool(&mut self, path: &Path, dlt: u32) -> Result<()> {
        let file = File::create(path)?;
        let sink = make_writer(BufWriter::new(file), &self.settings.default_export_format, dlt)?;
        self.spool = Some(Spool { sink, written: 0, cap: self.settings.max_session_file_mb * 1024 * 1024, capped: false });
        self.spool_path = Some(path.to_path_buf());
        self.dlt = dlt;
        Ok(())
    }

    pub fn packet_count(&self) -> u64 {
        self.next_no
    }

    pub fn retained(&self) -> usize {
        self.packets.len()
    }

    pub fn dlt(&self) -> u32 {
        self.dlt
    }

    pub fn ingest(&mut self, raw: RawPacket, dlt: u32) -> PacketRow {
        if self.next_no == 0 {
            self.dlt = dlt;
        }
        let dec = decoder::decode(&raw.data, dlt, raw.orig_len as usize);
        self.next_no += 1;
        let no = self.next_no;

        let (family, flow) = match (&dec.meta.tcp, &dec.meta.udp, &dec.meta.icmp, &dec.meta.ip) {
            (Some(t), _, _, Some(ip)) => (Family::Tcp, flow_key("tcp", ip.src, t.sport, ip.dst, t.dport)),
            (_, Some(u), _, Some(ip)) => (Family::Udp, flow_key("udp", ip.src, u.sport, ip.dst, u.dport)),
            (_, _, Some(_), _) => (Family::Icmp, None),
            _ => (Family::Other, None),
        };
        self.analytics.record(raw.ts_us, raw.orig_len, family, &dec.protocol, &dec.src, &dec.dst, flow.as_deref());
        self.diag.observe(no, raw.ts_us, &dec);

        // Retention: keep headers plus a bounded amount of payload.
        let keep = (dec.payload_offset + self.settings.payload_retention_bytes).min(raw.data.len());
        let mut data = raw.data;
        data.truncate(keep);

        let row = PacketRow {
            no,
            ts_us: raw.ts_us,
            src: dec.src,
            dst: dec.dst,
            sport: dec.sport,
            dport: dec.dport,
            protocol: dec.protocol,
            length: raw.orig_len,
            info: dec.info,
            anomaly: !dec.anomalies.is_empty(),
            flags: dec.meta.tcp.as_ref().map(|t| tcp_flags_string(t.flags)),
        };

        if let Some(sp) = self.spool.as_mut() {
            if sp.capped {
                // already at the size cap; keep capturing without recording
            } else if sp.written >= sp.cap {
                sp.capped = true;
                self.spool_note = Some(format!(
                    "Session recording stopped at the {} MB file-size limit after packet {}; capture and analysis continue in memory.",
                    self.settings.max_session_file_mb, no - 1
                ));
            } else {
                let rp = RawPacket { ts_us: row.ts_us, orig_len: row.length, data: data.clone() };
                match sp.sink.write_packet(&rp) {
                    Ok(()) => sp.written += 32 + data.len() as u64,
                    Err(e) => {
                        sp.capped = true;
                        self.spool_note = Some(format!("Session recording stopped: {e}"));
                    }
                }
            }
        }

        self.packets.push_back(StoredPacket { row: row.clone(), data: data.into_boxed_slice(), orig_len: raw.orig_len, dlt });
        while self.packets.len() > self.settings.max_packets_in_memory {
            self.packets.pop_front();
            self.evicted += 1;
        }
        row
    }

    fn get(&self, no: u64) -> Option<&StoredPacket> {
        let first = self.packets.front()?.row.no;
        if no < first {
            return None;
        }
        let p = self.packets.get((no - first) as usize)?;
        (p.row.no == no).then_some(p)
    }

    pub fn get_packet(&self, no: u64) -> Option<PacketDetail> {
        let p = self.get(no)?;
        let dec = decoder::decode(&p.data, p.dlt, p.orig_len as usize);
        let redacted = self.settings.redact_payload_display;
        let split = dec.payload_offset.min(p.data.len());
        let hex = if redacted {
            let mut h = hex_string(&p.data[..split]);
            h.push_str(&"**".repeat(p.data.len() - split));
            h
        } else {
            hex_string(&p.data)
        };
        let payload = &p.data[split..];
        let payload_preview = if payload.is_empty() {
            "(no payload)".to_string()
        } else if redacted {
            "(hidden by privacy setting)".to_string()
        } else {
            hex_string(&payload[..payload.len().min(HEX_PREVIEW_BYTES)])
        };
        Some(PacketDetail {
            row: p.row.clone(),
            layers: dec.layers,
            anomalies: dec.anomalies,
            hex,
            payload_offset: split,
            captured_len: p.data.len(),
            original_len: p.orig_len,
            redacted,
            payload_preview,
            cut_by_retention: (p.data.len() as u32) < p.orig_len,
        })
    }

    /// Rows with number greater than `after`, up to `limit` (used to resynchronise the UI).
    pub fn rows_after(&self, after: u64, limit: usize) -> Vec<PacketRow> {
        let Some(first) = self.packets.front().map(|p| p.row.no) else { return vec![] };
        let start = (after + 1).max(first) - first;
        self.packets.iter().skip(start as usize).take(limit).map(|p| p.row.clone()).collect()
    }

    /// Write retained packets (all, or the selected numbers) to a capture file.
    /// Returns (written, skipped_other_link_type).
    pub fn export(&self, path: &Path, format: &str, selection: Option<&[u64]>) -> Result<(u64, u64)> {
        if self.packets.is_empty() {
            return Err(NexusError::Invalid("There are no packets to export.".into()));
        }
        let file = File::create(path)?;
        let mut sink = make_writer(BufWriter::new(file), format, self.dlt)?;
        let wanted: Option<std::collections::HashSet<u64>> = selection.map(|s| s.iter().copied().collect());
        let (mut written, mut skipped) = (0u64, 0u64);
        for p in &self.packets {
            if wanted.as_ref().is_some_and(|w| !w.contains(&p.row.no)) {
                continue;
            }
            if p.dlt != self.dlt {
                skipped += 1;
                continue;
            }
            sink.write_packet(&RawPacket { ts_us: p.row.ts_us, orig_len: p.orig_len, data: p.data.to_vec() })?;
            written += 1;
        }
        sink.finish()?;
        if written == 0 {
            let _ = std::fs::remove_file(path);
            return Err(NexusError::Invalid("None of the selected packets are available (they may have been evicted by the retention limit).".into()));
        }
        Ok((written, skipped))
    }

    /// Periodic live maintenance: capture statistics and time-based diagnostics.
    pub fn tick(&mut self, wall_now_us: i64, drops: CaptureDrops) {
        if self.live {
            self.diag.set_capture_stats(drops);
            self.diag.tick(wall_now_us, &self.analytics);
        }
    }

    /// Stop recording and run final time-based checks. Offline captures are evaluated up to the
    /// last packet's timestamp, so items near the end that are still within a timeout are not judged.
    pub fn finalize(&mut self, drops: CaptureDrops) {
        if let Some(mut sp) = self.spool.take() {
            let _ = sp.sink.finish();
        }
        let now = if self.live {
            self.diag.set_capture_stats(drops);
            now_ms() * 1000
        } else {
            self.analytics.last_ts().unwrap_or(0) + 1_000_000
        };
        self.diag.tick(now, &self.analytics);
        self.live = false;
        self.source.ended_ms = Some(now_ms());
    }

    pub fn analytics_snapshot(&self) -> AnalyticsSnapshot {
        let now = self.live.then(|| now_ms() * 1000);
        self.analytics.snapshot(self.view_window_s, now)
    }

    pub fn diag_snapshot(&self) -> DiagSnapshot {
        self.diag.snapshot()
    }
}

fn flow_key(proto: &str, src: Option<std::net::IpAddr>, sp: u16, dst: Option<std::net::IpAddr>, dp: u16) -> Option<String> {
    let (s, d) = (src?, dst?);
    let a = (s, sp);
    let b = (d, dp);
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
    Some(format!("{proto}|{}:{}|{}:{}", lo.0, lo.1, hi.0, hi.1))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcap_io::read_capture;
    use crate::testutil::*;

    fn raw(ts_ms: i64, frame: Vec<u8>) -> RawPacket {
        RawPacket { ts_us: ts_ms * 1000, orig_len: frame.len() as u32, data: frame }
    }

    fn engine(max: usize, retention: usize) -> Engine {
        Engine::new(Settings { max_packets_in_memory: max, payload_retention_bytes: retention, ..Settings::default() })
    }

    fn syn(i: u32) -> Vec<u8> {
        tcp_frame([10, 0, 0, 1], [10, 0, 0, 2], &Tcp::new(1000 + i as u16, 80, i, 0, SYN, 0))
    }

    #[test]
    fn ring_buffer_evicts_oldest_and_lookup_stays_correct() {
        let mut e = engine(1_000, 0);
        e.settings.max_packets_in_memory = 1_000; // already clamped to the minimum
        for i in 0..1_500u32 {
            e.ingest(raw(i as i64, syn(i)), DLT_EN10MB);
        }
        assert_eq!(e.retained(), 1_000);
        assert_eq!(e.packet_count(), 1_500);
        assert!(e.get_packet(100).is_none());
        assert_eq!(e.get_packet(501).unwrap().row.no, 501);
        assert_eq!(e.get_packet(1_500).unwrap().row.no, 1_500);
        assert_eq!(e.evicted, 500);
        assert_eq!(e.rows_after(1_495, 100).len(), 5);
    }

    #[test]
    fn payload_retention_truncates_stored_bytes_but_keeps_wire_length() {
        let mut e = engine(1_000, 10);
        let f = tcp_frame([10, 0, 0, 1], [10, 0, 0, 2], &Tcp::new(1, 2, 3, 4, ACK | PSH, 100));
        let full = f.len();
        e.ingest(raw(0, f), DLT_EN10MB);
        let d = e.get_packet(1).unwrap();
        assert_eq!(d.captured_len, 14 + 20 + 20 + 10);
        assert_eq!(d.original_len as usize, full);
        assert!(d.cut_by_retention);
        assert!(d.anomalies.is_empty(), "retention cut must not look like a malformed packet");
        assert_eq!(d.row.length as usize, full);
    }

    #[test]
    fn redaction_masks_only_payload_bytes() {
        let mut e = engine(1_000, 64);
        e.settings.redact_payload_display = true;
        e.ingest(raw(0, tcp_frame([10, 0, 0, 1], [10, 0, 0, 2], &Tcp::new(1, 2, 3, 4, ACK, 4))), DLT_EN10MB);
        let d = e.get_packet(1).unwrap();
        assert!(d.redacted);
        assert!(d.hex.ends_with("********"), "{}", d.hex);
        assert!(!d.hex.starts_with("**"));
        assert_eq!(d.payload_preview, "(hidden by privacy setting)");
    }

    #[test]
    fn analytics_and_diagnostics_are_fed_from_ingested_packets() {
        let mut e = engine(1_000, 0);
        e.reset(e.settings.clone(), SourceInfo { kind: "file", ..Default::default() }, false);
        e.ingest(raw(0, udp_payload_frame([10, 0, 0, 1], [10, 0, 0, 2], 5, 6, b"x")), DLT_EN10MB);
        e.ingest(raw(10, syn(1)), DLT_EN10MB);
        let a = e.analytics_snapshot();
        assert_eq!((a.total_packets, a.udp_packets, a.tcp_packets), (2, 1, 1));
        assert_eq!(a.total_connections, 2);
    }

    #[test]
    fn export_roundtrips_through_the_reader_and_honours_selection() {
        let mut e = engine(1_000, 256);
        for i in 0..5u32 {
            e.ingest(raw(i as i64, syn(i)), DLT_EN10MB);
        }
        let dir = std::env::temp_dir().join(format!("nexus-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        for fmt in ["pcap", "pcapng"] {
            let p = dir.join(format!("out.{fmt}"));
            let (w, s) = e.export(&p, fmt, Some(&[2, 4])).unwrap();
            assert_eq!((w, s), (2, 0));
            let mut got = vec![];
            let sum = read_capture(File::open(&p).unwrap(), |_, r| got.push(r)).unwrap();
            assert_eq!(sum.format, fmt);
            assert_eq!(got.len(), 2);
            assert_eq!(got[0].ts_us, 1_000);
            assert_eq!(got[1].ts_us, 3_000);
        }
        assert!(e.export(&dir.join("none.pcap"), "pcap", Some(&[99])).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn spool_stops_at_cap_without_stopping_capture() {
        let mut e = engine(1_000, 0);
        e.settings.max_session_file_mb = 1;
        let dir = std::env::temp_dir().join(format!("nexus-spool-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("s.pcap");
        e.start_spool(&path, DLT_EN10MB).unwrap();
        let big = tcp_frame([10, 0, 0, 1], [10, 0, 0, 2], &Tcp::new(1, 2, 3, 4, ACK, 1400));
        e.settings.payload_retention_bytes = 65_535;
        for i in 0..1_000 {
            e.ingest(raw(i, big.clone()), DLT_EN10MB);
        }
        assert_eq!(e.packet_count(), 1_000);
        assert!(e.spool_note.as_deref().unwrap_or("").contains("file-size limit"));
        e.finalize(CaptureDrops::default());
        let mut n = 0;
        read_capture(File::open(&path).unwrap(), |_, _| n += 1).unwrap();
        assert!(n > 100 && n < 1_000, "recorded {n}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn offline_finalize_does_not_judge_trailing_syns() {
        let mut e = engine(1_000, 0);
        e.reset(e.settings.clone(), SourceInfo { kind: "file", ..Default::default() }, false);
        for i in 0..3 {
            e.ingest(raw(i, syn(i as u32)), DLT_EN10MB);
        }
        e.finalize(CaptureDrops::default());
        assert!(e.diag_snapshot().findings.iter().all(|f| !f.id.starts_with("conn-fail")));
    }
}
