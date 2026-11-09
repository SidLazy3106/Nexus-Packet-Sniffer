//! Tauri command surface. Each command is a thin adapter over `AppState`.

use crate::capture::{self, EmitRows, InterfaceInfo};
use crate::config::Settings;
use crate::constants::*;
use crate::engine::PacketDetail;
use crate::engine::PacketRow;
use crate::error::{NexusError, Result};
use crate::pcap_io::ReadSummary;
use crate::report;
use crate::state::{AppInfo, AppState, Snapshot};
use crate::storage::SessionRecord;
use std::path::PathBuf;
use std::sync::Arc;
use tauri::{AppHandle, Emitter, State};

type S<'a> = State<'a, Arc<AppState>>;

fn emitter(app: &AppHandle) -> EmitRows {
    let app = app.clone();
    Arc::new(move |rows: Vec<PacketRow>| {
        if !rows.is_empty() {
            let _ = app.emit(EVENT_PACKETS, rows);
        }
    })
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> Result<T> + Send + 'static) -> Result<T> {
    tauri::async_runtime::spawn_blocking(f)
        .await
        .map_err(|e| NexusError::Invalid(format!("background task failed: {e}")))?
}

#[tauri::command]
pub async fn app_info(state: S<'_>) -> Result<AppInfo> {
    Ok(state.info())
}

#[tauri::command]
pub async fn list_interfaces() -> Result<Vec<InterfaceInfo>> {
    blocking(capture::list_interfaces).await
}

#[tauri::command]
pub async fn validate_filter(filter: String) -> Result<()> {
    blocking(move || capture::validate_filter(&filter)).await
}

#[tauri::command]
pub async fn start_capture(app: AppHandle, state: S<'_>, interface: String, label: String, filter: String) -> Result<()> {
    let st = state.inner().clone();
    let emit = emitter(&app);
    blocking(move || st.start_capture(&interface, &label, &filter, emit)).await
}

#[tauri::command]
pub async fn stop_capture(state: S<'_>) -> Result<Option<i64>> {
    let st = state.inner().clone();
    blocking(move || st.stop_capture()).await
}

#[tauri::command]
pub async fn pause_capture(state: S<'_>) -> Result<()> {
    state.pause(true)
}

#[tauri::command]
pub async fn resume_capture(state: S<'_>) -> Result<()> {
    state.pause(false)
}

#[tauri::command]
pub async fn clear_capture(state: S<'_>) -> Result<()> {
    state.clear()
}

#[tauri::command]
pub async fn get_snapshot(state: S<'_>) -> Result<Snapshot> {
    Ok(state.snapshot())
}

#[tauri::command]
pub async fn get_packet(state: S<'_>, no: u64) -> Result<Option<PacketDetail>> {
    Ok(state.engine.lock().get_packet(no))
}

#[tauri::command]
pub async fn get_rows_after(state: S<'_>, after: u64, limit: usize) -> Result<Vec<PacketRow>> {
    Ok(state.engine.lock().rows_after(after, limit.min(50_000)))
}

#[tauri::command]
pub async fn set_analytics_window(state: S<'_>, seconds: usize) -> Result<()> {
    state.engine.lock().view_window_s = seconds.clamp(10, 3600);
    Ok(())
}

#[tauri::command]
pub async fn get_settings(state: S<'_>) -> Result<Settings> {
    Ok(state.storage.lock().load_settings())
}

#[tauri::command]
pub async fn save_settings(state: S<'_>, settings: Settings) -> Result<Settings> {
    state.save_settings(settings)
}

#[derive(Debug, serde::Serialize)]
pub struct ExportResult {
    pub written: u64,
    pub skipped_other_link_type: u64,
}

#[tauri::command]
pub async fn export_capture(state: S<'_>, path: String, format: String, selection: Option<Vec<u64>>) -> Result<ExportResult> {
    let st = state.inner().clone();
    blocking(move || {
        let fmt = if format.eq_ignore_ascii_case("pcap") { "pcap" } else { "pcapng" };
        let (written, skipped) = st.engine.lock().export(&PathBuf::from(path), fmt, selection.as_deref())?;
        Ok(ExportResult { written, skipped_other_link_type: skipped })
    })
    .await
}

#[tauri::command]
pub async fn import_capture(app: AppHandle, state: S<'_>, path: String) -> Result<ReadSummary> {
    let st = state.inner().clone();
    let emit = emitter(&app);
    blocking(move || {
        let p = PathBuf::from(&path);
        let name = p.file_name().map_or_else(|| path.clone(), |n| n.to_string_lossy().into_owned());
        st.import(&p, &name, true, emit)
    })
    .await
}

#[tauri::command]
pub async fn list_sessions(state: S<'_>) -> Result<Vec<SessionRecord>> {
    state.storage.lock().list_sessions()
}

#[tauri::command]
pub async fn open_session(app: AppHandle, state: S<'_>, id: i64) -> Result<ReadSummary> {
    let st = state.inner().clone();
    let emit = emitter(&app);
    blocking(move || {
        let rec = st.storage.lock().get_session(id)?.ok_or_else(|| NexusError::Invalid("That session no longer exists.".into()))?;
        let path = rec.file_path.clone().ok_or_else(|| NexusError::Invalid("This session has no capture file (recording was disabled), so only its saved report is available.".into()))?;
        if !PathBuf::from(&path).exists() {
            return Err(NexusError::Invalid(format!("The capture file for this session is missing: {path}")));
        }
        st.import(&PathBuf::from(path), &rec.name, false, emit)
    })
    .await
}

#[tauri::command]
pub async fn rename_session(state: S<'_>, id: i64, name: String) -> Result<()> {
    let name = name.trim();
    if name.is_empty() {
        return Err(NexusError::Invalid("The session name cannot be empty.".into()));
    }
    if state.storage.lock().rename_session(id, name)? {
        Ok(())
    } else {
        Err(NexusError::Invalid("That session no longer exists.".into()))
    }
}

#[tauri::command]
pub async fn delete_session(state: S<'_>, id: i64) -> Result<()> {
    state.delete_session(id)
}

/// Export the diagnostic report of the loaded capture, or of a saved session (`session_id`).
#[tauri::command]
pub async fn export_report(state: S<'_>, path: String, format: String, session_id: Option<i64>) -> Result<()> {
    let st = state.inner().clone();
    blocking(move || {
        let value = match session_id {
            Some(id) => {
                let raw = st.storage.lock().session_report(id)?.ok_or_else(|| NexusError::Invalid("That session no longer exists.".into()))?;
                serde_json::from_str(&raw)?
            }
            None => {
                let e = st.engine.lock();
                if e.packet_count() == 0 {
                    return Err(NexusError::Invalid("There is no capture loaded to report on.".into()));
                }
                report::build(&e)
            }
        };
        let body = if format.eq_ignore_ascii_case("csv") { report::to_csv(&value) } else { serde_json::to_string_pretty(&value)? };
        std::fs::write(path, body)?;
        Ok(())
    })
    .await
}
