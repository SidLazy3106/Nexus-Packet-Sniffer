pub mod analytics;
pub mod capture;
pub mod commands;
pub mod config;
pub mod constants;
pub mod decoder;
pub mod diagnostics;
pub mod engine;
pub mod error;
pub mod npcap;
pub mod pcap_io;
pub mod report;
pub mod state;
pub mod storage;
#[cfg(test)]
pub mod testutil;

use constants::*;
use state::AppState;
use std::sync::Arc;
use std::time::Duration;
use tauri::{Emitter, Manager, RunEvent};

pub fn run() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let app = tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let dir = app.path().app_data_dir().map_err(|e| format!("cannot resolve the application data folder: {e}"))?;
            let state = Arc::new(AppState::new(dir).map_err(|e| format!("cannot open application storage: {e}"))?);
            app.manage(state.clone());

            // One-second state push (throughput, diagnostics, capture counters).
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                let mut tick = tokio::time::interval(Duration::from_millis(SNAPSHOT_INTERVAL_MS));
                tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    tick.tick().await;
                    let st = state.clone();
                    if let Ok(snap) = tauri::async_runtime::spawn_blocking(move || st.snapshot()).await {
                        let _ = handle.emit(EVENT_SNAPSHOT, snap);
                    }
                }
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::app_info,
            commands::list_interfaces,
            commands::validate_filter,
            commands::start_capture,
            commands::stop_capture,
            commands::pause_capture,
            commands::resume_capture,
            commands::clear_capture,
            commands::get_snapshot,
            commands::get_packet,
            commands::get_rows_after,
            commands::set_analytics_window,
            commands::get_settings,
            commands::save_settings,
            commands::export_capture,
            commands::import_capture,
            commands::list_sessions,
            commands::open_session,
            commands::rename_session,
            commands::delete_session,
            commands::export_report,
        ])
        .build(tauri::generate_context!())
        .expect("failed to build the NEXUS application");

    app.run(|handle, event| {
        // Make sure an active capture is stopped and saved when the window is closed.
        if let RunEvent::Exit = event {
            if let Some(state) = handle.try_state::<Arc<AppState>>() {
                state.shutdown();
            }
        }
    });
}
