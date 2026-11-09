//! User-tunable settings and diagnostic thresholds with documented defaults.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DiagConfig {
    /// DNS response slower than this is reported (ms).
    pub dns_slow_ms: f64,
    /// Seconds before an unanswered DNS query is considered unanswered.
    pub dns_timeout_s: f64,
    /// Unanswered DNS queries to the same server required to raise a finding.
    pub dns_unanswered_min: u32,
    /// Seconds before a SYN with no SYN-ACK/RST is considered unanswered.
    pub syn_timeout_s: f64,
    /// Failed connection attempts to one destination required to raise a finding.
    pub conn_fail_min: u32,
    /// Duplicate ACKs (same ack number) required to flag (RFC 5681 uses 3).
    pub dupack_threshold: u32,
    /// Handshake interval considered high (ms).
    pub handshake_slow_ms: f64,
    /// RTT sample > this multiple of the flow median (and > rtt_min_ms) is a variation.
    pub rtt_variation_factor: f64,
    pub rtt_min_ms: f64,
    pub rtt_min_samples: usize,
    /// Retransmission ratio (retransmissions / data segments) for Medium / High severity.
    pub retrans_ratio_medium: f64,
    pub retrans_ratio_high: f64,
    /// Traffic spike: bytes in one second > mean + k*stddev and > spike_min_bytes.
    pub spike_sigma: f64,
    pub spike_min_bytes: u64,
    pub spike_min_history_s: usize,
    /// Share of ICMP/ARP above this (with at least mix_min_packets) is unusual.
    pub mix_share: f64,
    pub mix_min_packets: u64,
    /// Malformed packets required before a finding is raised.
    pub malformed_min: u32,
    /// Minimum packets before a health score is meaningful.
    pub health_min_packets: u64,
    /// A lower sequence number arriving within this window after higher data is out-of-order.
    pub reorder_window_ms: f64,
    /// A flow needs at least this many segments before a retransmission/reordering *ratio* raises severity.
    pub ratio_min_segments: u64,
    /// A run of this many duplicate ACKs raises the finding to Medium.
    pub dupack_medium_run: u32,
    /// RST segments from one host before a "many resets" finding.
    pub rst_burst_min: u32,
    /// Failed attempts to one destination for High severity (conn_fail_min is the Medium threshold).
    pub conn_fail_high: u32,
    /// An RTT outlier above this is Medium instead of Low (ms).
    pub rtt_medium_ms: f64,
    /// Sequence gaps in a capture before the gap finding is Low instead of Informational.
    pub gap_low_count: u64,
    /// Malformed observations of one kind before Medium instead of Low.
    pub malformed_medium_count: u32,
    /// A spike above this many sigma and this multiple of the baseline mean is Low instead of Informational.
    pub spike_high_sigma: f64,
    pub spike_high_ratio: f64,
}

impl Default for DiagConfig {
    fn default() -> Self {
        Self {
            dns_slow_ms: 500.0,
            dns_timeout_s: 5.0,
            dns_unanswered_min: 3,
            syn_timeout_s: 3.0,
            conn_fail_min: 3,
            dupack_threshold: 3,
            handshake_slow_ms: 300.0,
            rtt_variation_factor: 5.0,
            rtt_min_ms: 50.0,
            rtt_min_samples: 8,
            retrans_ratio_medium: 0.01,
            retrans_ratio_high: 0.05,
            spike_sigma: 4.0,
            spike_min_bytes: 1_000_000,
            spike_min_history_s: 20,
            mix_share: 0.5,
            mix_min_packets: 200,
            malformed_min: 1,
            health_min_packets: 50,
            reorder_window_ms: 100.0,
            ratio_min_segments: 20,
            dupack_medium_run: 10,
            rst_burst_min: 10,
            conn_fail_high: 10,
            rtt_medium_ms: 1000.0,
            gap_low_count: 50,
            malformed_medium_count: 50,
            spike_high_sigma: 10.0,
            spike_high_ratio: 5.0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub theme: String,
    pub default_interface: Option<String>,
    pub default_filter: String,
    /// Maximum packets kept in memory (ring buffer).
    pub max_packets_in_memory: usize,
    /// Bounded queue between capture thread and processor (packets).
    pub queue_capacity: usize,
    /// Payload bytes retained after the headers (memory + exported files). 0 = headers only.
    pub payload_retention_bytes: usize,
    /// Mask payload bytes in the hex viewer.
    pub redact_payload_display: bool,
    /// Spool live captures to disk and save as a session on stop.
    pub record_sessions: bool,
    /// Cap on a recorded session file (MB). Recording stops (capture continues) at the cap.
    pub max_session_file_mb: u64,
    pub default_export_format: String,
    pub analytics_window_s: usize,
    pub diag: DiagConfig,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            theme: "dark".into(),
            default_interface: None,
            default_filter: String::new(),
            max_packets_in_memory: 200_000,
            queue_capacity: 8_192,
            payload_retention_bytes: 256,
            redact_payload_display: false,
            record_sessions: true,
            max_session_file_mb: 512,
            default_export_format: "pcapng".into(),
            analytics_window_s: 60,
            diag: DiagConfig::default(),
        }
    }
}

impl Settings {
    /// Clamp values into safe ranges so a hand-edited database cannot cause runaway memory use.
    pub fn sanitized(mut self) -> Self {
        self.max_packets_in_memory = self.max_packets_in_memory.clamp(1_000, 5_000_000);
        self.queue_capacity = self.queue_capacity.clamp(256, 262_144);
        self.payload_retention_bytes = self.payload_retention_bytes.min(65_535);
        self.max_session_file_mb = self.max_session_file_mb.clamp(1, 20_480);
        self.analytics_window_s = self.analytics_window_s.clamp(10, 3_600);
        if self.default_export_format != "pcap" {
            self.default_export_format = "pcapng".into();
        }
        self
    }
}
