//! Exercises the real Tauri command functions against a mock app. Commands that need a webview
//! `AppHandle` (start_capture, import_capture, open_session) are covered through `AppState` unit
//! tests and the live-capture integration tests.
//!
//! Windows note: binaries that link Tauri's webview types need a Common-Controls v6 manifest, which
//! build.rs embeds for test targets (tests/windows-test.manifest).

use nexus_lib::commands::*;
use nexus_lib::error::NexusError;
use nexus_lib::state::AppState;
use std::path::PathBuf;
use std::sync::Arc;
use tauri::test::{mock_app, MockRuntime};
use tauri::{App, Manager, State};

fn app(tag: &str) -> (App<MockRuntime>, PathBuf) {
    let unique = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let dir = std::env::temp_dir().join(format!("nexus-cmd-{tag}-{}-{unique}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let app = mock_app();
    app.manage(Arc::new(AppState::new(dir.join("data")).unwrap()));
    (app, dir)
}

fn run<T>(f: impl std::future::Future<Output = T>) -> T {
    tauri::async_runtime::block_on(f)
}

#[test]
fn app_info_and_snapshot_describe_an_idle_app() {
    let (app, dir) = app("info");
    let st: State<'_, Arc<AppState>> = app.state();
    let info = run(app_info(st.clone())).unwrap();
    assert_eq!(info.name, "NEXUS");
    assert!(info.privacy_notice.contains("authorised"));
    let snap = run(get_snapshot(st)).unwrap();
    assert_eq!((snap.total_packets, snap.capture.status), (0, "idle"));
    assert_eq!(snap.diagnostics.health.label, "Insufficient data");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn capture_controls_report_clear_errors_when_nothing_is_running() {
    let (app, dir) = app("controls");
    let st: State<'_, Arc<AppState>> = app.state();
    assert!(matches!(run(stop_capture(st.clone())), Err(NexusError::NotCapturing)));
    assert!(matches!(run(pause_capture(st.clone())), Err(NexusError::NotCapturing)));
    assert!(matches!(run(resume_capture(st.clone())), Err(NexusError::NotCapturing)));
    assert!(run(clear_capture(st.clone())).is_ok());
    assert!(run(get_packet(st.clone(), 1)).unwrap().is_none());
    assert!(run(get_rows_after(st.clone(), 0, 100)).unwrap().is_empty());
    assert!(run(set_analytics_window(st, 5)).is_ok());
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn empty_filters_are_valid_without_needing_the_driver() {
    assert!(run(validate_filter(String::new())).is_ok());
    assert!(run(validate_filter("   ".into())).is_ok());
}

#[test]
fn settings_roundtrip_through_the_commands_and_are_sanitised() {
    let (app, dir) = app("settings");
    let st: State<'_, Arc<AppState>> = app.state();
    let mut s = run(get_settings(st.clone())).unwrap();
    assert_eq!(s.theme, "dark");
    s.queue_capacity = 1;
    s.default_filter = "udp".into();
    let saved = run(save_settings(st.clone(), s)).unwrap();
    assert_eq!(saved.queue_capacity, 256, "out-of-range values are clamped");
    assert_eq!(run(get_settings(st)).unwrap().default_filter, "udp");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn export_and_report_refuse_to_write_empty_captures() {
    let (app, dir) = app("export");
    let st: State<'_, Arc<AppState>> = app.state();
    let out = dir.join("x.pcapng").display().to_string();
    let e = run(export_capture(st.clone(), out.clone(), "pcapng".into(), None)).unwrap_err();
    assert!(e.to_string().contains("no packets"), "{e}");
    assert!(!PathBuf::from(&out).exists(), "no file should be created for an empty export");
    let e = run(export_report(st.clone(), dir.join("r.json").display().to_string(), "json".into(), None)).unwrap_err();
    assert!(e.to_string().contains("no capture loaded"), "{e}");
    let e = run(export_report(st, dir.join("r.csv").display().to_string(), "csv".into(), Some(999))).unwrap_err();
    assert!(e.to_string().contains("no longer exists"), "{e}");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn session_commands_validate_their_input() {
    let (app, dir) = app("sessions");
    let st: State<'_, Arc<AppState>> = app.state();
    assert!(run(list_sessions(st.clone())).unwrap().is_empty());
    let e = run(rename_session(st.clone(), 1, "   ".into())).unwrap_err();
    assert!(e.to_string().contains("cannot be empty"), "{e}");
    let e = run(rename_session(st.clone(), 424242, "name".into())).unwrap_err();
    assert!(e.to_string().contains("no longer exists"), "{e}");
    assert!(run(delete_session(st, 424242)).is_ok(), "deleting a missing session is a no-op");
    let _ = std::fs::remove_dir_all(dir);
}
