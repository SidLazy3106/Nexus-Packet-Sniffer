//! Diagnostic report generation (JSON and CSV). Reports contain IP addresses and should be
//! handled like the captures they come from.

use crate::engine::Engine;
use serde_json::{json, Value};

pub const PRIVACY_NOTE: &str = "This report contains IP addresses and traffic metadata from a packet capture. Share it only with people authorised to see that information.";

pub fn build(e: &Engine) -> Value {
    let a = e.analytics_snapshot();
    json!({
        "tool": "NEXUS Network Packet Analyzer",
        "version": env!("CARGO_PKG_VERSION"),
        "generated_ms": crate::engine::now_ms(),
        "privacy_note": PRIVACY_NOTE,
        "source": e.source,
        "analytics": {
            "total_packets": a.total_packets,
            "total_bytes": a.total_bytes,
            "tcp_packets": a.tcp_packets,
            "udp_packets": a.udp_packets,
            "icmp_packets": a.icmp_packets,
            "other_packets": a.other_packets,
            "protocols": a.protocols,
            "top_sources": a.top_sources,
            "top_destinations": a.top_destinations,
            "total_connections": a.total_connections,
            "first_ts_us": a.first_ts_us,
            "last_ts_us": a.last_ts_us,
        },
        "diagnostics": e.diag_snapshot(),
        "methodology": "All findings are derived from packets visible at the capture point. Retransmission, duplicate-ACK, reordering and gap classifications are inferences from TCP sequence numbers and timing; they do not locate where on the path a problem occurred. Local capture drops are reported separately from network behaviour.",
    })
}

fn esc(s: &str) -> String {
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

fn text(v: &Value) -> String {
    v.as_str().map_or_else(|| v.to_string(), str::to_string)
}

fn join(v: &Value, sep: &str, f: impl Fn(&Value) -> String) -> String {
    v.as_array().map_or(String::new(), |a| a.iter().map(f).collect::<Vec<_>>().join(sep))
}

/// One row per finding. Works from the JSON report so saved sessions can be exported too.
pub fn to_csv(report: &Value) -> String {
    let mut out = String::from("id,title,severity,confidence,category,protocol,first_ts_us,last_ts_us,count,flow,description,evidence_packets,evidence,possible_causes,recommendations,limitations\n");
    let empty = vec![];
    let findings = report.pointer("/diagnostics/findings").and_then(Value::as_array).unwrap_or(&empty);
    for f in findings {
        let evidence_pkts = join(&f["evidence"], ";", |e| e["packet_no"].as_u64().map_or(String::new(), |n| n.to_string()));
        let evidence = join(&f["evidence"], " | ", |e| text(&e["note"]));
        let row = [
            text(&f["id"]),
            text(&f["title"]),
            text(&f["severity"]),
            text(&f["confidence"]),
            text(&f["category"]),
            text(&f["protocol"]),
            text(&f["first_ts_us"]),
            text(&f["last_ts_us"]),
            text(&f["count"]),
            f["flow"].as_str().unwrap_or("").to_string(),
            text(&f["description"]),
            evidence_pkts,
            evidence,
            join(&f["possible_causes"], " | ", text),
            join(&f["recommendations"], " | ", text),
            join(&f["limitations"], " | ", text),
        ];
        out.push_str(&row.iter().map(|c| esc(c)).collect::<Vec<_>>().join(","));
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_escapes_and_lists_one_row_per_finding() {
        let r = json!({"diagnostics":{"findings":[
            {"id":"a","title":"T, with comma","severity":"Low","confidence":"High","category":"tcp","protocol":"TCP","first_ts_us":1,"last_ts_us":2,"count":3,"flow":null,
             "description":"said \"hi\"\nnewline","evidence":[{"packet_no":5,"note":"n1"},{"packet_no":null,"note":"agg"}],
             "possible_causes":["c1","c2"],"recommendations":["r"],"limitations":["l"]}
        ]}});
        let csv = to_csv(&r);
        let lines: Vec<&str> = csv.split('\n').collect();
        assert!(lines[0].starts_with("id,title,severity"));
        assert!(csv.contains("\"T, with comma\""));
        assert!(csv.contains("\"said \"\"hi\"\"\nnewline\""));
        assert!(csv.contains(",5;,"), "{csv}");
        assert!(csv.contains("c1 | c2"));
    }

    #[test]
    fn csv_of_empty_report_has_only_header() {
        assert_eq!(to_csv(&json!({})).lines().count(), 1);
    }

    #[test]
    fn report_json_contains_privacy_note_and_methodology() {
        let e = Engine::new(Default::default());
        let r = build(&e);
        assert!(r["privacy_note"].as_str().unwrap().contains("IP addresses"));
        assert!(r["methodology"].as_str().unwrap().contains("do not locate"));
        assert_eq!(r["analytics"]["total_packets"], 0);
    }
}
