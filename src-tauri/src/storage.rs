//! SQLite persistence for settings and capture-session metadata. Packet bytes live in
//! PCAP/PCAPNG files next to the database, never in the database itself.

use crate::config::Settings;
use crate::error::Result;
use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;
use std::path::Path;

pub struct Storage {
    conn: Connection,
}

#[derive(Debug, Clone, Serialize)]
pub struct SessionRecord {
    pub id: i64,
    pub name: String,
    /// "live" or "import"
    pub source: String,
    pub interface: Option<String>,
    pub filter: String,
    pub started_ms: i64,
    pub ended_ms: i64,
    pub packet_count: i64,
    pub byte_count: i64,
    pub file_path: Option<String>,
    pub file_exists: bool,
    pub health_score: Option<i64>,
    pub health_label: String,
    pub finding_count: i64,
}

pub struct NewSession {
    pub name: String,
    pub source: String,
    pub interface: Option<String>,
    pub filter: String,
    pub started_ms: i64,
    pub ended_ms: i64,
    pub packet_count: i64,
    pub byte_count: i64,
    pub file_path: Option<String>,
    pub health_score: Option<i64>,
    pub health_label: String,
    pub finding_count: i64,
    pub report_json: String,
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    source TEXT NOT NULL,
    interface TEXT,
    filter TEXT NOT NULL DEFAULT '',
    started_ms INTEGER NOT NULL,
    ended_ms INTEGER NOT NULL,
    packet_count INTEGER NOT NULL,
    byte_count INTEGER NOT NULL,
    file_path TEXT,
    health_score INTEGER,
    health_label TEXT NOT NULL DEFAULT '',
    finding_count INTEGER NOT NULL DEFAULT 0,
    report_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_sessions_started ON sessions(started_ms DESC);
";

impl Storage {
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")?;
        Self::init(conn)
    }

    pub fn open_in_memory() -> Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Self> {
        conn.execute_batch(SCHEMA)?;
        Ok(Storage { conn })
    }

    pub fn load_settings(&self) -> Settings {
        let json: Option<String> = self
            .conn
            .query_row("SELECT value FROM settings WHERE key='app'", [], |r| r.get(0))
            .optional()
            .ok()
            .flatten();
        json.and_then(|j| serde_json::from_str::<Settings>(&j).ok()).unwrap_or_default().sanitized()
    }

    pub fn save_settings(&self, s: &Settings) -> Result<()> {
        self.conn.execute(
            "INSERT INTO settings(key,value) VALUES('app',?1) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            params![serde_json::to_string(s)?],
        )?;
        Ok(())
    }

    pub fn insert_session(&self, s: &NewSession) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO sessions(name,source,interface,filter,started_ms,ended_ms,packet_count,byte_count,file_path,health_score,health_label,finding_count,report_json)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
            params![s.name, s.source, s.interface, s.filter, s.started_ms, s.ended_ms, s.packet_count, s.byte_count, s.file_path, s.health_score, s.health_label, s.finding_count, s.report_json],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    fn map_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<SessionRecord> {
        let file_path: Option<String> = r.get(9)?;
        Ok(SessionRecord {
            id: r.get(0)?,
            name: r.get(1)?,
            source: r.get(2)?,
            interface: r.get(3)?,
            filter: r.get(4)?,
            started_ms: r.get(5)?,
            ended_ms: r.get(6)?,
            packet_count: r.get(7)?,
            byte_count: r.get(8)?,
            file_exists: file_path.as_deref().is_some_and(|p| Path::new(p).exists()),
            file_path,
            health_score: r.get(10)?,
            health_label: r.get(11)?,
            finding_count: r.get(12)?,
        })
    }

    const COLS: &'static str = "id,name,source,interface,filter,started_ms,ended_ms,packet_count,byte_count,file_path,health_score,health_label,finding_count";

    pub fn list_sessions(&self) -> Result<Vec<SessionRecord>> {
        let mut st = self.conn.prepare(&format!("SELECT {} FROM sessions ORDER BY started_ms DESC, id DESC", Self::COLS))?;
        let rows = st.query_map([], Self::map_row)?.collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn get_session(&self, id: i64) -> Result<Option<SessionRecord>> {
        Ok(self
            .conn
            .query_row(&format!("SELECT {} FROM sessions WHERE id=?1", Self::COLS), params![id], Self::map_row)
            .optional()?)
    }

    pub fn session_report(&self, id: i64) -> Result<Option<String>> {
        Ok(self.conn.query_row("SELECT report_json FROM sessions WHERE id=?1", params![id], |r| r.get(0)).optional()?)
    }

    pub fn rename_session(&self, id: i64, name: &str) -> Result<bool> {
        Ok(self.conn.execute("UPDATE sessions SET name=?1 WHERE id=?2", params![name, id])? > 0)
    }

    /// Delete a session row, returning its file path so the caller can remove owned files.
    pub fn delete_session(&self, id: i64) -> Result<Option<String>> {
        let path: Option<Option<String>> = self.conn.query_row("SELECT file_path FROM sessions WHERE id=?1", params![id], |r| r.get(0)).optional()?;
        self.conn.execute("DELETE FROM sessions WHERE id=?1", params![id])?;
        Ok(path.flatten())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn new_session(name: &str, started: i64) -> NewSession {
        NewSession {
            name: name.into(),
            source: "live".into(),
            interface: Some("Ethernet".into()),
            filter: "tcp".into(),
            started_ms: started,
            ended_ms: started + 1000,
            packet_count: 10,
            byte_count: 1234,
            file_path: Some("C:/definitely/missing.pcapng".into()),
            health_score: Some(95),
            health_label: "Healthy".into(),
            finding_count: 2,
            report_json: "{\"a\":1}".into(),
        }
    }

    #[test]
    fn settings_default_roundtrip_and_sanitise() {
        let st = Storage::open_in_memory().unwrap();
        assert_eq!(st.load_settings().theme, "dark");
        let s = Settings { queue_capacity: 1, max_packets_in_memory: usize::MAX, default_filter: "port 53".into(), ..Settings::default() };
        st.save_settings(&s).unwrap();
        let back = st.load_settings();
        assert_eq!(back.default_filter, "port 53");
        assert_eq!(back.queue_capacity, 256);
        assert_eq!(back.max_packets_in_memory, 5_000_000);
    }

    #[test]
    fn corrupt_settings_fall_back_to_defaults() {
        let st = Storage::open_in_memory().unwrap();
        st.conn.execute("INSERT INTO settings(key,value) VALUES('app','{not json')", []).unwrap();
        assert_eq!(st.load_settings().queue_capacity, Settings::default().queue_capacity);
    }

    #[test]
    fn partial_settings_json_keeps_defaults_for_new_fields() {
        let st = Storage::open_in_memory().unwrap();
        st.conn.execute("INSERT INTO settings(key,value) VALUES('app','{\"theme\":\"dark\",\"default_filter\":\"udp\"}')", []).unwrap();
        let s = st.load_settings();
        assert_eq!(s.default_filter, "udp");
        assert_eq!(s.diag.dupack_threshold, 3);
    }

    #[test]
    fn session_lifecycle() {
        let st = Storage::open_in_memory().unwrap();
        let a = st.insert_session(&new_session("first", 100)).unwrap();
        let b = st.insert_session(&new_session("second", 200)).unwrap();
        let list = st.list_sessions().unwrap();
        assert_eq!(list.iter().map(|s| s.id).collect::<Vec<_>>(), vec![b, a]);
        assert!(!list[0].file_exists);
        assert_eq!(list[0].finding_count, 2);
        assert_eq!(st.session_report(a).unwrap().unwrap(), "{\"a\":1}");
        assert!(st.rename_session(a, "renamed").unwrap());
        assert_eq!(st.get_session(a).unwrap().unwrap().name, "renamed");
        assert_eq!(st.delete_session(a).unwrap().unwrap(), "C:/definitely/missing.pcapng");
        assert!(st.get_session(a).unwrap().is_none());
        assert!(st.delete_session(9999).unwrap().is_none());
    }

    #[test]
    fn data_survives_reopening_the_database_file() {
        let dir = std::env::temp_dir().join(format!("nexus-db-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("t.sqlite3");
        {
            let st = Storage::open(&path).unwrap();
            st.insert_session(&new_session("persisted", 5)).unwrap();
        }
        let st = Storage::open(&path).unwrap();
        assert_eq!(st.list_sessions().unwrap()[0].name, "persisted");
        drop(st);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
