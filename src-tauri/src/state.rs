//! Shared application state and the operations that combine engine, capture and storage.

use crate::analytics::AnalyticsSnapshot;
use crate::capture::{self, CaptureHandle, CaptureStatsView, EmitRows, SharedStats, STATUS_IDLE, STATUS_STOPPED};
use crate::config::Settings;
use crate::constants::*;
use crate::diagnostics::DiagSnapshot;
use crate::engine::{now_ms, Engine, PacketRow, SourceInfo};
use crate::error::{NexusError, Result};
use crate::npcap::{self, NpcapStatus};
use crate::pcap_io::{read_capture, RawPacket, ReadSummary};
use crate::report;
use crate::storage::{NewSession, Storage};
use parking_lot::Mutex;
use serde::Serialize;
use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};

pub struct AppState {
    pub engine: Arc<Mutex<Engine>>,
    pub stats: Arc<SharedStats>,
    pub capture: Mutex<Option<CaptureHandle>>,
    pub storage: Mutex<Storage>,
    pub data_dir: PathBuf,
    pub importing: AtomicBool,
    sys: Mutex<System>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SystemInfo {
    pub cpu_percent: f32,
    pub memory_mb: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Snapshot {
    pub capture: CaptureStatsView,
    pub source: SourceInfo,
    pub analytics: AnalyticsSnapshot,
    pub diagnostics: DiagSnapshot,
    pub buffered_packets: usize,
    pub total_packets: u64,
    pub evicted_packets: u64,
    pub recording_note: Option<String>,
    pub recording_path: Option<String>,
    pub system: SystemInfo,
    pub importing: bool,
    pub paused: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct AppInfo {
    pub name: &'static str,
    pub version: &'static str,
    pub npcap: NpcapStatus,
    pub data_dir: String,
    pub privacy_notice: &'static str,
}

pub const PRIVACY_NOTICE: &str = "Packet captures can contain sensitive information such as addresses, hostnames and unencrypted content. Capture only networks you are authorised to monitor. NEXUS keeps all analysis on this computer and never uploads traffic.";

impl AppState {
    pub fn new(data_dir: PathBuf) -> Result<Self> {
        std::fs::create_dir_all(data_dir.join(SESSIONS_DIR))?;
        let storage = Storage::open(&data_dir.join(DB_FILE_NAME))?;
        let settings = storage.load_settings();
        Ok(AppState {
            engine: Arc::new(Mutex::new(Engine::new(settings))),
            stats: Arc::new(SharedStats::default()),
            capture: Mutex::new(None),
            storage: Mutex::new(storage),
            data_dir,
            importing: AtomicBool::new(false),
            sys: Mutex::new(System::new()),
        })
    }

    pub fn info(&self) -> AppInfo {
        AppInfo {
            name: APP_NAME,
            version: env!("CARGO_PKG_VERSION"),
            npcap: npcap::status(),
            data_dir: self.data_dir.display().to_string(),
            privacy_notice: PRIVACY_NOTICE,
        }
    }

    fn system_info(&self) -> SystemInfo {
        let mut sys = self.sys.lock();
        let pid = Pid::from_u32(std::process::id());
        sys.refresh_processes_specifics(ProcessesToUpdate::Some(&[pid]), true, ProcessRefreshKind::new().with_cpu().with_memory());
        let cores = std::thread::available_parallelism().map_or(1, usize::from) as f32;
        sys.process(pid).map_or(SystemInfo { cpu_percent: 0.0, memory_mb: 0.0 }, |p| SystemInfo {
            cpu_percent: (p.cpu_usage() / cores).min(100.0),
            memory_mb: p.memory() as f64 / (1024.0 * 1024.0),
        })
    }

    /// Run periodic live maintenance and build the state pushed to the UI once per second.
    pub fn snapshot(&self) -> Snapshot {
        let drops = self.stats.drops();
        let system = self.system_info();
        let mut e = self.engine.lock();
        e.tick(now_ms() * 1000, drops);
        let capture = self.stats.view();
        Snapshot {
            paused: capture.status == "paused",
            capture,
            source: e.source.clone(),
            analytics: e.analytics_snapshot(),
            diagnostics: e.diag_snapshot(),
            buffered_packets: e.retained(),
            total_packets: e.packet_count(),
            evicted_packets: e.evicted,
            recording_note: e.spool_note.clone(),
            recording_path: e.spool_path.as_ref().map(|p| p.display().to_string()),
            system,
            importing: self.importing.load(Ordering::Relaxed),
        }
    }

    pub fn is_capturing(&self) -> bool {
        self.capture.lock().is_some()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn start_capture(&self, device: &str, label: &str, filter: &str, emit: EmitRows) -> Result<()> {
        if self.importing.load(Ordering::Relaxed) {
            return Err(NexusError::Invalid("A file import is in progress.".into()));
        }
        let mut slot = self.capture.lock();
        if slot.is_some() {
            return Err(NexusError::AlreadyCapturing);
        }
        let settings = self.storage.lock().load_settings();
        let engine = self.engine.clone();
        let session_file = self.data_dir.join(SESSIONS_DIR).join(format!("capture-{}.{}", now_ms(), settings.default_export_format));
        let source = SourceInfo {
            kind: "live",
            name: label.to_string(),
            interface: Some(device.to_string()),
            filter: filter.trim().to_string(),
            started_ms: now_ms(),
            ended_ms: None,
        };
        let eng_for_prepare = engine.clone();
        let st = settings.clone();
        let handle = capture::start(device, filter, &settings, engine, self.stats.clone(), emit, move |dlt| {
            let mut e = eng_for_prepare.lock();
            e.reset(st.clone(), source, true);
            if st.record_sessions {
                if let Err(err) = e.start_spool(&session_file, dlt) {
                    // Recording is optional: report it and keep capturing.
                    e.spool_note = Some(format!("Session recording is unavailable: {err}"));
                }
            }
            Ok(())
        })?;
        *slot = Some(handle);
        Ok(())
    }

    pub fn pause(&self, pause: bool) -> Result<()> {
        let slot = self.capture.lock();
        let h = slot.as_ref().ok_or(NexusError::NotCapturing)?;
        if pause {
            h.pause();
        } else {
            h.resume();
        }
        Ok(())
    }

    /// Stop the capture, run final analysis and save the session. Returns the new session id.
    pub fn stop_capture(&self) -> Result<Option<i64>> {
        let handle = self.capture.lock().take().ok_or(NexusError::NotCapturing)?;
        handle.stop();
        let drops = self.stats.drops();
        {
            let mut e = self.engine.lock();
            e.finalize(drops);
        }
        self.save_current_session("live", None)
    }

    fn save_current_session(&self, source: &str, file_override: Option<String>) -> Result<Option<i64>> {
        let e = self.engine.lock();
        let record = e.settings.record_sessions || source == "import";
        if e.packet_count() == 0 || !record {
            return Ok(None);
        }
        let diag = e.diag_snapshot();
        let a = e.analytics_snapshot();
        let file = file_override.or_else(|| e.spool_path.as_ref().map(|p| p.display().to_string()));
        let rep = report::build(&e);
        let s = NewSession {
            name: if source == "live" { format!("{} capture", e.source.name) } else { e.source.name.clone() },
            source: source.into(),
            interface: e.source.interface.clone(),
            filter: e.source.filter.clone(),
            started_ms: e.source.started_ms,
            ended_ms: e.source.ended_ms.unwrap_or_else(now_ms),
            packet_count: a.total_packets as i64,
            byte_count: a.total_bytes as i64,
            file_path: file,
            health_score: diag.health.score.map(i64::from),
            health_label: diag.health.label.to_string(),
            finding_count: diag.findings.iter().filter(|f| f.category != "capture").count() as i64,
            report_json: serde_json::to_string(&rep)?,
        };
        drop(e);
        Ok(Some(self.storage.lock().insert_session(&s)?))
    }

    pub fn clear(&self) -> Result<()> {
        if self.is_capturing() || self.importing.load(Ordering::Relaxed) {
            return Err(NexusError::Invalid("Stop the current capture or import before clearing.".into()));
        }
        let settings = self.storage.lock().load_settings();
        self.engine.lock().reset(settings, SourceInfo { kind: "none", ..Default::default() }, false);
        self.stats.reset();
        self.stats.status.store(STATUS_IDLE, Ordering::Relaxed);
        Ok(())
    }

    /// Import a capture file for offline analysis. `save_session` records it in the session list.
    pub fn import(&self, path: &Path, display_name: &str, save_session: bool, emit: EmitRows) -> Result<ReadSummary> {
        if self.is_capturing() {
            return Err(NexusError::Invalid("Stop the live capture before importing a file.".into()));
        }
        if self.importing.swap(true, Ordering::SeqCst) {
            return Err(NexusError::Invalid("Another import is already running.".into()));
        }
        let result = self.import_inner(path, display_name, save_session, emit);
        self.importing.store(false, Ordering::SeqCst);
        result
    }

    fn import_inner(&self, path: &Path, display_name: &str, save_session: bool, emit: EmitRows) -> Result<ReadSummary> {
        let file = File::open(path)?;
        let settings = self.storage.lock().load_settings();
        {
            let mut e = self.engine.lock();
            e.reset(
                settings,
                SourceInfo { kind: "file", name: display_name.to_string(), interface: None, filter: String::new(), started_ms: now_ms(), ended_ms: None },
                false,
            );
        }
        self.stats.reset();
        self.stats.status.store(STATUS_STOPPED, Ordering::Relaxed);

        let mut buf: Vec<(u32, RawPacket)> = Vec::with_capacity(MAX_BATCH_PACKETS);
        let engine = self.engine.clone();
        let flush = |buf: &mut Vec<(u32, RawPacket)>| {
            if buf.is_empty() {
                return;
            }
            let mut rows: Vec<PacketRow> = Vec::with_capacity(buf.len());
            {
                let mut e = engine.lock();
                for (dlt, p) in buf.drain(..) {
                    if let Ok(r) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| e.ingest(p, dlt))) {
                        rows.push(r);
                    }
                }
            }
            emit(rows);
        };
        let summary = read_capture(BufReader::with_capacity(1 << 20, file), |dlt, p| {
            buf.push((dlt, p));
            if buf.len() >= MAX_BATCH_PACKETS {
                flush(&mut buf);
            }
        });
        flush(&mut buf);
        let summary = summary?;
        self.engine.lock().finalize(Default::default());
        if save_session {
            self.save_current_session("import", Some(path.display().to_string()))?;
        }
        Ok(summary)
    }

    pub fn save_settings(&self, s: Settings) -> Result<Settings> {
        let s = s.sanitized();
        self.storage.lock().save_settings(&s)?;
        // Display-only settings apply immediately; capture parameters apply to the next capture.
        let mut e = self.engine.lock();
        e.settings.redact_payload_display = s.redact_payload_display;
        e.view_window_s = s.analytics_window_s;
        Ok(s)
    }

    /// Delete a session and, if the file is one NEXUS recorded itself, the capture file too.
    pub fn delete_session(&self, id: i64) -> Result<()> {
        let path = self.storage.lock().delete_session(id)?;
        if let Some(p) = path {
            let owned = self.data_dir.join(SESSIONS_DIR);
            if let (Ok(fp), Ok(dir)) = (Path::new(&p).canonicalize(), owned.canonicalize()) {
                if fp.starts_with(dir) {
                    let _ = std::fs::remove_file(fp);
                }
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub fn engine_for_test(&self) -> &Arc<Mutex<Engine>> {
        &self.engine
    }

    /// Stop everything cleanly (window close / app exit during capture).
    pub fn shutdown(&self) {
        if self.is_capturing() {
            if let Err(e) = self.stop_capture() {
                tracing::warn!("shutdown: {e}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcap_io::make_writer;
    use crate::testutil::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("nexus-{tag}-{}-{}", std::process::id(), now_ms()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// A capture with a clean handshake, one retransmission, and an unreachable-port ICMP error.
    fn write_scenario(path: &Path, format: &str) {
        let c = [10, 0, 0, 1];
        let s = [10, 0, 0, 2];
        let f = std::fs::File::create(path).unwrap();
        let mut w = make_writer(std::io::BufWriter::new(f), format, 1).unwrap();
        let mut t = 1_700_000_000_000_000i64;
        let mut put = |dt_ms: i64, frame: Vec<u8>| {
            t += dt_ms * 1000;
            w.write_packet(&RawPacket { ts_us: t, orig_len: frame.len() as u32, data: frame }).unwrap();
        };
        put(0, tcp_frame(c, s, &Tcp::new(50000, 80, 999, 0, SYN, 0)));
        put(10, tcp_frame(s, c, &Tcp::new(80, 50000, 4999, 1000, SYN | ACK, 0)));
        put(1, tcp_frame(c, s, &Tcp::new(50000, 80, 1000, 5000, ACK, 0)));
        put(10, tcp_frame(c, s, &Tcp::new(50000, 80, 1000, 5000, ACK | PSH, 100)));
        put(300, tcp_frame(c, s, &Tcp::new(50000, 80, 1000, 5000, ACK | PSH, 100)));
        let orig = Ip4::new(c, [10, 0, 0, 9], 17).build(&[0, 1, 0, 53, 0, 8, 0, 0]);
        put(5, icmp_frame(s, c, 3, 3, [0; 4], &orig));
        w.finish().unwrap();
    }

    #[test]
    fn import_analyse_save_reopen_export_pipeline() {
        let dir = temp_dir("e2e");
        let state = AppState::new(dir.join("data")).unwrap();
        for fmt in ["pcap", "pcapng"] {
            let file = dir.join(format!("scenario.{fmt}"));
            write_scenario(&file, fmt);
            let batches = Arc::new(Mutex::new(Vec::<usize>::new()));
            let b = batches.clone();
            let emit: EmitRows = Arc::new(move |rows| b.lock().push(rows.len()));
            let sum = state.import(&file, &format!("scenario.{fmt}"), true, emit.clone()).unwrap();
            assert_eq!((sum.packets, sum.format), (6, fmt));
            assert_eq!(batches.lock().iter().sum::<usize>(), 6, "every packet reaches the UI");

            let snap = state.snapshot();
            assert_eq!(snap.total_packets, 6);
            assert_eq!(snap.analytics.tcp_packets, 5);
            assert_eq!(snap.analytics.icmp_packets, 1);
            let ids: Vec<&str> = snap.diagnostics.findings.iter().map(|f| f.id.as_str()).collect();
            assert!(ids.iter().any(|i| i.starts_with("tcp-retrans:")), "{ids:?}");
            assert!(ids.iter().any(|i| i.starts_with("icmp:")), "{ids:?}");
            assert!(snap.diagnostics.counters.tcp_handshakes == 1);
            assert_eq!(snap.capture.pipeline_dropped, 0);

            // Reopening a saved session reproduces identical findings.
            let sessions = state.storage.lock().list_sessions().unwrap();
            let rec = sessions.iter().find(|s| s.name == format!("scenario.{fmt}")).unwrap();
            assert_eq!(rec.packet_count, 6);
            let before: Vec<String> = snap.diagnostics.findings.iter().map(|f| format!("{}:{}", f.id, f.count)).collect();
            state.import(Path::new(rec.file_path.as_ref().unwrap()), &rec.name, false, emit.clone()).unwrap();
            let after: Vec<String> = state.snapshot().diagnostics.findings.iter().map(|f| format!("{}:{}", f.id, f.count)).collect();
            assert_eq!(before, after);

            // Export what was loaded and re-import the export.
            let out = dir.join(format!("export.{fmt}"));
            let (w, _) = state.engine_for_test().lock().export(&out, fmt, None).unwrap();
            assert_eq!(w, 6);
            let re = state.import(&out, "export", false, emit).unwrap();
            assert_eq!(re.packets, 6);
        }
        assert_eq!(state.storage.lock().list_sessions().unwrap().len(), 2);
        let first = state.storage.lock().list_sessions().unwrap()[0].id;
        state.delete_session(first).unwrap();
        assert_eq!(state.storage.lock().list_sessions().unwrap().len(), 1);
        // Imported files are never deleted from their original location.
        assert!(dir.join("scenario.pcap").exists() && dir.join("scenario.pcapng").exists());
        drop(state);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupt_and_empty_files_are_rejected_without_crashing() {
        let dir = temp_dir("bad");
        let state = AppState::new(dir.join("data")).unwrap();
        let emit: EmitRows = Arc::new(|_| {});
        std::fs::write(dir.join("empty.pcap"), b"").unwrap();
        std::fs::write(dir.join("junk.pcap"), vec![0xAB; 4096]).unwrap();
        assert!(state.import(&dir.join("empty.pcap"), "e", false, emit.clone()).is_err());
        assert!(state.import(&dir.join("junk.pcap"), "j", false, emit.clone()).is_err());
        assert!(state.import(&dir.join("missing.pcap"), "m", false, emit).is_err());
        assert!(!state.importing.load(Ordering::SeqCst), "failed imports release the import lock");
        drop(state);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn stopping_without_a_capture_is_a_clear_error() {
        let dir = temp_dir("nocap");
        let state = AppState::new(dir.join("data")).unwrap();
        assert!(matches!(state.stop_capture(), Err(NexusError::NotCapturing)));
        assert!(matches!(state.pause(true), Err(NexusError::NotCapturing)));
        drop(state);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn settings_persist_and_apply_display_options_immediately() {
        let dir = temp_dir("settings");
        let state = AppState::new(dir.join("data")).unwrap();
        state.save_settings(Settings { redact_payload_display: true, default_filter: "udp".into(), ..Settings::default() }).unwrap();
        assert!(state.engine.lock().settings.redact_payload_display);
        drop(state);
        let state2 = AppState::new(dir.join("data")).unwrap();
        assert_eq!(state2.storage.lock().load_settings().default_filter, "udp");
        drop(state2);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
