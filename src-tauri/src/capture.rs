//! Live capture: interface discovery, the capture thread and the bounded processing pipeline.
//!
//! capture thread --(bounded sync_channel)--> processor thread --> Engine (decode/analytics/diagnostics)
//! A full channel increments `pipeline_dropped`; it never blocks the capture thread or grows memory.

use crate::config::Settings;
use crate::constants::*;
use crate::diagnostics::CaptureDrops;
use crate::engine::{Engine, PacketRow};
use crate::error::{NexusError, Result};
use crate::npcap;
use crate::pcap_io::RawPacket;
use parking_lot::Mutex;
use serde::Serialize;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::mpsc::{sync_channel, RecvTimeoutError, TrySendError};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

pub const STATUS_IDLE: u8 = 0;
pub const STATUS_CAPTURING: u8 = 1;
pub const STATUS_PAUSED: u8 = 2;
pub const STATUS_STOPPED: u8 = 3;
pub const STATUS_ERROR: u8 = 4;

#[derive(Default)]
pub struct SharedStats {
    pub status: AtomicU8,
    /// Packets that passed the BPF filter (driver counter).
    pub received: AtomicU64,
    pub kernel_dropped: AtomicU64,
    pub interface_dropped: AtomicU64,
    pub pipeline_dropped: AtomicU64,
    pub paused_discarded: AtomicU64,
    pub queued: AtomicU64,
    pub last_error: Mutex<Option<String>>,
}

impl SharedStats {
    pub fn reset(&self) {
        for a in [&self.received, &self.kernel_dropped, &self.interface_dropped, &self.pipeline_dropped, &self.paused_discarded, &self.queued] {
            a.store(0, Ordering::Relaxed);
        }
        *self.last_error.lock() = None;
    }

    pub fn drops(&self) -> CaptureDrops {
        CaptureDrops {
            received: self.received.load(Ordering::Relaxed),
            kernel_dropped: self.kernel_dropped.load(Ordering::Relaxed),
            interface_dropped: self.interface_dropped.load(Ordering::Relaxed),
            pipeline_dropped: self.pipeline_dropped.load(Ordering::Relaxed),
        }
    }

    pub fn view(&self) -> CaptureStatsView {
        let d = self.drops();
        CaptureStatsView {
            status: match self.status.load(Ordering::Relaxed) {
                STATUS_CAPTURING => "capturing",
                STATUS_PAUSED => "paused",
                STATUS_STOPPED => "stopped",
                STATUS_ERROR => "error",
                _ => "idle",
            },
            received: d.received,
            kernel_dropped: d.kernel_dropped,
            interface_dropped: d.interface_dropped,
            pipeline_dropped: d.pipeline_dropped,
            paused_discarded: self.paused_discarded.load(Ordering::Relaxed),
            queued_total: self.queued.load(Ordering::Relaxed),
            error: self.last_error.lock().clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct CaptureStatsView {
    pub status: &'static str,
    pub received: u64,
    pub kernel_dropped: u64,
    pub interface_dropped: u64,
    pub pipeline_dropped: u64,
    pub paused_discarded: u64,
    pub queued_total: u64,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct InterfaceInfo {
    pub name: String,
    pub friendly_name: String,
    pub description: String,
    pub ipv4: Vec<String>,
    pub ipv6: Vec<String>,
    pub mac: Option<String>,
    /// "up", "down" or "unknown"
    pub status: &'static str,
    pub loopback: bool,
}

pub fn list_interfaces() -> Result<Vec<InterfaceInfo>> {
    npcap::ensure()?;
    let devices = pcap::Device::list().map_err(|e| map_pcap_error(&e.to_string()))?;
    #[cfg(windows)]
    let adapters = ipconfig::get_adapters().unwrap_or_default();
    let mut out = Vec::new();
    for d in devices {
        let loopback = d.flags.if_flags.contains(pcap::IfFlags::LOOPBACK) || d.name.contains("Loopback");
        let mut ipv4 = Vec::new();
        let mut ipv6 = Vec::new();
        for a in &d.addresses {
            match a.addr {
                std::net::IpAddr::V4(v) => ipv4.push(v.to_string()),
                std::net::IpAddr::V6(v) => ipv6.push(v.to_string()),
            }
        }
        let mut friendly = d.desc.clone().unwrap_or_else(|| d.name.clone());
        let mut mac = None;
        let mut status = match d.flags.connection_status {
            pcap::ConnectionStatus::Connected => "up",
            pcap::ConnectionStatus::Disconnected => "down",
            _ => "unknown",
        };
        #[cfg(windows)]
        if let Some(guid) = d.name.split("NPF_").nth(1) {
            if let Some(a) = adapters.iter().find(|a| a.adapter_name().eq_ignore_ascii_case(guid)) {
                friendly = a.friendly_name().to_string();
                mac = a.physical_address().filter(|p| !p.is_empty()).map(|p| p.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":"));
                status = if matches!(a.oper_status(), ipconfig::OperStatus::IfOperStatusUp) { "up" } else { "down" };
            }
        }
        out.push(InterfaceInfo {
            description: d.desc.clone().unwrap_or_default(),
            friendly_name: friendly,
            name: d.name,
            ipv4,
            ipv6,
            mac,
            status,
            loopback,
        });
    }
    // Usable adapters first: connected, with an IPv4 address, not loopback.
    out.sort_by_key(|i| (i.status != "up", i.ipv4.is_empty(), i.loopback));
    Ok(out)
}

pub type EmitRows = Arc<dyn Fn(Vec<PacketRow>) + Send + Sync>;

pub struct CaptureHandle {
    stop: Arc<AtomicBool>,
    paused: Arc<AtomicBool>,
    stats: Arc<SharedStats>,
    capture_thread: Option<JoinHandle<()>>,
    processor_thread: Option<JoinHandle<()>>,
    pub dlt: u32,
}

impl CaptureHandle {
    pub fn pause(&self) {
        self.paused.store(true, Ordering::Relaxed);
        self.stats.status.store(STATUS_PAUSED, Ordering::Relaxed);
    }

    pub fn resume(&self) {
        self.paused.store(false, Ordering::Relaxed);
        self.stats.status.store(STATUS_CAPTURING, Ordering::Relaxed);
    }

    pub fn is_paused(&self) -> bool {
        self.paused.load(Ordering::Relaxed)
    }

    /// Stop capturing and wait for both threads to finish draining.
    pub fn stop(mut self) {
        self.shutdown();
    }

    fn shutdown(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.capture_thread.take() {
            let _ = t.join();
        }
        if let Some(t) = self.processor_thread.take() {
            let _ = t.join();
        }
        if self.stats.status.load(Ordering::Relaxed) != STATUS_ERROR {
            self.stats.status.store(STATUS_STOPPED, Ordering::Relaxed);
        }
    }
}

impl Drop for CaptureHandle {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// What a packet source produced on one poll.
pub enum SourceEvent {
    Packet(RawPacket),
    /// Nothing arrived within the poll interval (lets the loop notice stop/pause requests).
    Idle,
    /// The source is exhausted (end of file, interface removed cleanly).
    End,
    Failed(String),
}

/// Where packets come from. Npcap is one implementation; tests use an in-memory one, which is what
/// lets the queue, pause, backpressure and failure handling be verified without a driver.
pub trait PacketSource: Send + 'static {
    fn datalink(&self) -> u32;
    fn next(&mut self) -> SourceEvent;
    /// Driver counters, if the source has them: (received, dropped by kernel, dropped by interface).
    fn driver_stats(&mut self) -> Option<(u64, u64, u64)>;
}

struct PcapSource {
    cap: pcap::Capture<pcap::Active>,
    dlt: u32,
}

impl PacketSource for PcapSource {
    fn datalink(&self) -> u32 {
        self.dlt
    }

    fn next(&mut self) -> SourceEvent {
        match self.cap.next_packet() {
            Ok(p) => SourceEvent::Packet(RawPacket {
                ts_us: p.header.ts.tv_sec as i64 * 1_000_000 + p.header.ts.tv_usec as i64,
                orig_len: p.header.len,
                data: p.data.to_vec(),
            }),
            Err(pcap::Error::TimeoutExpired) => SourceEvent::Idle,
            Err(pcap::Error::NoMorePackets) => SourceEvent::End,
            Err(e) => SourceEvent::Failed(format!("Capture stopped unexpectedly: {e}")),
        }
    }

    fn driver_stats(&mut self) -> Option<(u64, u64, u64)> {
        // Driver counters are 32-bit and reset per capture handle. `dropped` = kernel buffer overflow.
        self.cap.stats().ok().map(|s| (u64::from(s.received), u64::from(s.dropped), u64::from(s.if_dropped)))
    }
}

/// Open the device and start capturing. Errors (permissions, bad filter, missing driver) are
/// returned synchronously, before any state is modified.
pub fn start(
    device: &str,
    filter: &str,
    settings: &Settings,
    engine: Arc<Mutex<Engine>>,
    stats: Arc<SharedStats>,
    emit: EmitRows,
    prepare: impl FnOnce(u32) -> Result<()>,
) -> Result<CaptureHandle> {
    npcap::ensure()?;
    let mut cap = pcap::Capture::from_device(device)
        .map_err(|e| map_pcap_error(&e.to_string()))?
        .promisc(true)
        .snaplen(PCAP_SNAPLEN)
        .timeout(PCAP_READ_TIMEOUT_MS)
        .immediate_mode(true)
        .buffer_size(PCAP_KERNEL_BUFFER_BYTES)
        .open()
        .map_err(|e| map_pcap_error(&e.to_string()))?;
    if !filter.trim().is_empty() {
        cap.filter(filter, true).map_err(|e| NexusError::InvalidFilter(e.to_string()))?;
    }
    let dlt = cap.get_datalink().0 as u32;
    start_source(PcapSource { cap, dlt }, settings.queue_capacity, engine, stats, emit, prepare)
}

/// Run the capture pipeline over any packet source:
/// source thread --(bounded queue)--> processor thread --> engine.
pub fn start_source(
    mut source: impl PacketSource,
    queue_capacity: usize,
    engine: Arc<Mutex<Engine>>,
    stats: Arc<SharedStats>,
    emit: EmitRows,
    prepare: impl FnOnce(u32) -> Result<()>,
) -> Result<CaptureHandle> {
    let dlt = source.datalink();
    // Only now (source opened, filter valid) is the previous capture replaced.
    prepare(dlt)?;
    stats.reset();
    stats.status.store(STATUS_CAPTURING, Ordering::Relaxed);

    let (tx, rx) = sync_channel::<RawPacket>(queue_capacity);
    let stop = Arc::new(AtomicBool::new(false));
    let paused = Arc::new(AtomicBool::new(false));

    let cap_thread = {
        let (stop, paused, stats) = (stop.clone(), paused.clone(), stats.clone());
        std::thread::Builder::new()
            .name("nexus-capture".into())
            .spawn(move || {
                let mut last_poll = Instant::now();
                while !stop.load(Ordering::Relaxed) {
                    match source.next() {
                        SourceEvent::Packet(_) if paused.load(Ordering::Relaxed) => {
                            stats.paused_discarded.fetch_add(1, Ordering::Relaxed);
                        }
                        SourceEvent::Packet(raw) => match tx.try_send(raw) {
                            Ok(()) => {
                                stats.queued.fetch_add(1, Ordering::Relaxed);
                            }
                            Err(TrySendError::Full(_)) => {
                                stats.pipeline_dropped.fetch_add(1, Ordering::Relaxed);
                            }
                            Err(TrySendError::Disconnected(_)) => break,
                        },
                        SourceEvent::Idle => {}
                        SourceEvent::End => break,
                        SourceEvent::Failed(msg) => {
                            tracing::error!("{msg}");
                            *stats.last_error.lock() = Some(msg);
                            stats.status.store(STATUS_ERROR, Ordering::Relaxed);
                            break;
                        }
                    }
                    if last_poll.elapsed() >= Duration::from_millis(CAPTURE_STATS_POLL_MS) {
                        publish_stats(&mut source, &stats);
                        last_poll = Instant::now();
                    }
                }
                publish_stats(&mut source, &stats);
                // `tx` drops here, which lets the processor drain and exit.
            })
            .map_err(|e| NexusError::Capture(format!("could not start capture thread: {e}")))?
    };

    let proc_thread = {
        let stats = stats.clone();
        std::thread::Builder::new()
            .name("nexus-processor".into())
            .spawn(move || processor_loop(rx, dlt, engine, stats, emit))
            .map_err(|e| NexusError::Capture(format!("could not start processor thread: {e}")))?
    };

    Ok(CaptureHandle { stop, paused, stats, capture_thread: Some(cap_thread), processor_thread: Some(proc_thread), dlt })
}

fn publish_stats(source: &mut impl PacketSource, stats: &SharedStats) {
    if let Some((received, dropped, if_dropped)) = source.driver_stats() {
        stats.received.store(received, Ordering::Relaxed);
        stats.kernel_dropped.store(dropped, Ordering::Relaxed);
        stats.interface_dropped.store(if_dropped, Ordering::Relaxed);
    }
}

fn processor_loop(rx: std::sync::mpsc::Receiver<RawPacket>, dlt: u32, engine: Arc<Mutex<Engine>>, stats: Arc<SharedStats>, emit: EmitRows) {
    let mut batch: Vec<RawPacket> = Vec::with_capacity(MAX_BATCH_PACKETS);
    loop {
        let disconnected = match rx.recv_timeout(Duration::from_millis(BATCH_FLUSH_MS)) {
            Ok(p) => {
                batch.push(p);
                while batch.len() < MAX_BATCH_PACKETS {
                    match rx.try_recv() {
                        Ok(p) => batch.push(p),
                        Err(_) => break,
                    }
                }
                false
            }
            Err(RecvTimeoutError::Timeout) => false,
            Err(RecvTimeoutError::Disconnected) => true,
        };
        if !batch.is_empty() {
            let mut rows = Vec::with_capacity(batch.len());
            {
                let mut e = engine.lock();
                for p in batch.drain(..) {
                    // A panic while handling one packet must never take down the capture.
                    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| e.ingest(p, dlt))) {
                        Ok(row) => rows.push(row),
                        Err(_) => {
                            *stats.last_error.lock() = Some("An internal error occurred while decoding a packet; it was skipped.".into());
                            tracing::error!("panic while ingesting packet");
                        }
                    }
                }
            }
            emit(rows);
        }
        if disconnected {
            break;
        }
    }
}

/// Translate libpcap/Npcap error text into actionable guidance.
pub fn map_pcap_error(msg: &str) -> NexusError {
    let l = msg.to_lowercase();
    if l.contains("not found") || l.contains("no such device") {
        NexusError::Capture(format!("The network interface was not found - it may have been disconnected or removed. Refresh the interface list. ({msg})"))
    } else if l.contains("access is denied") || l.contains("permission") || l.contains("operation not permitted") {
        NexusError::Permission(msg.to_string())
    } else if l.contains("syntax error") || l.contains("filter") && l.contains("error") {
        NexusError::InvalidFilter(msg.to_string())
    } else if l.contains("wpcap") || l.contains("packet.dll") || l.contains("npcap") && l.contains("not") {
        NexusError::NpcapMissing(msg.to_string())
    } else {
        NexusError::Capture(msg.to_string())
    }
}

/// Compile a BPF expression without opening any device.
pub fn validate_filter(filter: &str) -> Result<()> {
    if filter.trim().is_empty() {
        return Ok(());
    }
    npcap::ensure()?;
    let cap = pcap::Capture::dead(pcap::Linktype::ETHERNET).map_err(|e| map_pcap_error(&e.to_string()))?;
    cap.compile(filter, true).map(|_| ()).map_err(|e| NexusError::InvalidFilter(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pcap_errors_are_classified_by_cause() {
        let missing = map_pcap_error("libpcap error: Error opening adapter: Network interface was not found.  (2150891563)");
        assert!(matches!(missing, NexusError::Capture(_)), "{missing:?}");
        assert!(missing.to_string().contains("not found"));
        assert!(matches!(map_pcap_error("Error opening adapter: Access is denied. (5)"), NexusError::Permission(_)));
        assert!(matches!(map_pcap_error("syntax error in filter"), NexusError::InvalidFilter(_)));
        assert!(matches!(map_pcap_error("something odd"), NexusError::Capture(_)));
    }

    // ---- pipeline tests over an in-memory source (no driver needed) ----

    use crate::testutil::{tcp_frame, Tcp, ACK};
    use std::collections::VecDeque;
    use std::sync::atomic::AtomicUsize;

    struct FakeSource {
        packets: VecDeque<RawPacket>,
        /// Reports Idle until set, so tests can pause before packets flow.
        go: Arc<AtomicBool>,
        stats: Option<(u64, u64, u64)>,
        fail_at_end: Option<String>,
    }

    impl FakeSource {
        fn new(n: usize) -> (Self, Arc<AtomicBool>) {
            let go = Arc::new(AtomicBool::new(true));
            let packets = (0..n)
                .map(|i| {
                    let f = tcp_frame([10, 0, 0, 1], [10, 0, 0, 2], &Tcp::new(1000, 80, i as u32, 0, ACK, 0));
                    RawPacket { ts_us: 1_700_000_000_000_000 + i as i64, orig_len: f.len() as u32, data: f }
                })
                .collect();
            (FakeSource { packets, go: go.clone(), stats: None, fail_at_end: None }, go)
        }
    }

    impl PacketSource for FakeSource {
        fn datalink(&self) -> u32 {
            crate::constants::DLT_EN10MB
        }
        fn next(&mut self) -> SourceEvent {
            if !self.go.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(2));
                return SourceEvent::Idle;
            }
            match self.packets.pop_front() {
                Some(p) => SourceEvent::Packet(p),
                None => match self.fail_at_end.take() {
                    Some(msg) => SourceEvent::Failed(msg),
                    None => {
                        std::thread::sleep(Duration::from_millis(2));
                        SourceEvent::Idle
                    }
                },
            }
        }
        fn driver_stats(&mut self) -> Option<(u64, u64, u64)> {
            self.stats
        }
    }

    fn engine() -> Arc<Mutex<Engine>> {
        Arc::new(Mutex::new(Engine::new(Settings::default())))
    }

    fn wait_for(what: &str, mut cond: impl FnMut() -> bool) {
        let t = Instant::now();
        while !cond() {
            assert!(t.elapsed() < Duration::from_secs(10), "timed out waiting for {what}");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn every_packet_flows_source_to_engine_to_ui_and_stop_is_clean() {
        let (src, _) = FakeSource::new(500);
        let (eng, stats) = (engine(), Arc::new(SharedStats::default()));
        let emitted = Arc::new(AtomicUsize::new(0));
        let e2 = emitted.clone();
        let emit: EmitRows = Arc::new(move |rows| {
            e2.fetch_add(rows.len(), Ordering::Relaxed);
        });
        eng.lock().reset(Settings::default(), crate::engine::SourceInfo { kind: "live", ..Default::default() }, true);
        let h = start_source(src, 1024, eng.clone(), stats.clone(), emit, |_| Ok(())).unwrap();
        wait_for("all packets ingested", || eng.lock().packet_count() == 500);
        assert_eq!(stats.view().status, "capturing");
        h.stop();
        assert_eq!(emitted.load(Ordering::Relaxed), 500, "every ingested packet is delivered to the UI");
        let v = stats.view();
        assert_eq!((v.status, v.queued_total, v.pipeline_dropped), ("stopped", 500, 0));
        assert_eq!(eng.lock().analytics_snapshot().tcp_packets, 500);
    }

    #[test]
    fn a_full_queue_drops_and_counts_but_accounts_for_every_packet() {
        const N: usize = 3_000;
        let (src, _) = FakeSource::new(N);
        let (eng, stats) = (engine(), Arc::new(SharedStats::default()));
        // A stalled consumer: the first delivery blocks, so the tiny queue fills up behind it.
        let stalled = Arc::new(AtomicBool::new(false));
        let s2 = stalled.clone();
        let emit: EmitRows = Arc::new(move |_| {
            if !s2.swap(true, Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(400));
            }
        });
        let h = start_source(src, 8, eng.clone(), stats.clone(), emit, |_| Ok(())).unwrap();
        wait_for("source exhausted", || {
            let v = stats.view();
            v.queued_total + v.pipeline_dropped == N as u64
        });
        h.stop();
        let v = stats.view();
        assert!(v.pipeline_dropped > 0, "backpressure must be visible, not silent");
        assert_eq!(v.queued_total + v.pipeline_dropped, N as u64, "no packet is unaccounted for");
        assert_eq!(eng.lock().packet_count(), v.queued_total, "everything queued was processed after stop");
    }

    #[test]
    fn paused_packets_are_counted_and_not_ingested() {
        let (src, go) = FakeSource::new(50);
        go.store(false, Ordering::Relaxed);
        let (eng, stats) = (engine(), Arc::new(SharedStats::default()));
        let h = start_source(src, 1024, eng.clone(), stats.clone(), Arc::new(|_| {}), |_| Ok(())).unwrap();
        h.pause();
        assert!(h.is_paused());
        assert_eq!(stats.view().status, "paused");
        go.store(true, Ordering::Relaxed);
        wait_for("packets discarded while paused", || stats.view().paused_discarded == 50);
        assert_eq!(eng.lock().packet_count(), 0);
        h.stop();
        assert_eq!(stats.view().queued_total, 0);
    }

    #[test]
    fn a_failing_source_surfaces_an_error_state_and_message() {
        let (mut src, _) = FakeSource::new(5);
        src.fail_at_end = Some("adapter disappeared".into());
        let (eng, stats) = (engine(), Arc::new(SharedStats::default()));
        let h = start_source(src, 64, eng.clone(), stats.clone(), Arc::new(|_| {}), |_| Ok(())).unwrap();
        wait_for("error state", || stats.view().status == "error");
        assert_eq!(stats.view().error.as_deref(), Some("adapter disappeared"));
        h.stop();
        assert_eq!(stats.view().status, "error", "stopping must not hide the failure");
        assert_eq!(eng.lock().packet_count(), 5, "packets before the failure are kept");
    }

    #[test]
    fn driver_counters_are_published_as_local_drops_not_network_loss() {
        let (mut src, _) = FakeSource::new(10);
        src.stats = Some((1_000, 7, 3));
        let (eng, stats) = (engine(), Arc::new(SharedStats::default()));
        let h = start_source(src, 64, eng, stats.clone(), Arc::new(|_| {}), |_| Ok(())).unwrap();
        wait_for("ingest", || stats.view().queued_total == 10);
        h.stop();
        let d = stats.drops();
        assert_eq!((d.received, d.kernel_dropped, d.interface_dropped), (1_000, 7, 3));
    }

    #[test]
    fn prepare_failure_leaves_nothing_running_and_state_untouched() {
        let (src, _) = FakeSource::new(5);
        let (eng, stats) = (engine(), Arc::new(SharedStats::default()));
        let r = start_source(src, 64, eng.clone(), stats.clone(), Arc::new(|_| {}), |_| Err(NexusError::Invalid("no".into())));
        assert!(r.is_err());
        assert_eq!(stats.view().status, "idle");
        assert_eq!(eng.lock().packet_count(), 0);
    }
}
