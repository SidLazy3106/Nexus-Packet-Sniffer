// Types mirroring the Rust backend's serialised structures.

export interface PacketRow {
  no: number
  ts_us: number
  src: string
  dst: string
  sport: number | null
  dport: number | null
  protocol: string
  length: number
  info: string
  anomaly: boolean
  flags: string | null
}

export interface Field { name: string; value: string; offset: number; len: number }
export interface Layer { name: string; offset: number; len: number; fields: Field[] }
export interface Anomaly { kind: string; layer: string; detail: string }

export interface PacketDetail {
  row: PacketRow
  layers: Layer[]
  anomalies: Anomaly[]
  hex: string
  payload_offset: number
  captured_len: number
  original_len: number
  redacted: boolean
  payload_preview: string
  cut_by_retention: boolean
}

export interface InterfaceInfo {
  name: string
  friendly_name: string
  description: string
  ipv4: string[]
  ipv6: string[]
  mac: string | null
  status: 'up' | 'down' | 'unknown'
  loopback: boolean
}

export interface NpcapStatus { available: boolean; detail: string; download_url: string; admin_note: string }
export interface AppInfo { name: string; version: string; npcap: NpcapStatus; data_dir: string; privacy_notice: string }

export interface CaptureStats {
  status: 'idle' | 'capturing' | 'paused' | 'stopped' | 'error'
  received: number
  kernel_dropped: number
  interface_dropped: number
  pipeline_dropped: number
  paused_discarded: number
  queued_total: number
  error: string | null
}

export interface SourceInfo {
  kind: 'none' | 'live' | 'file'
  name: string
  interface: string | null
  filter: string
  started_ms: number
  ended_ms: number | null
}

export interface Bucket { sec: number; packets: number; bytes: number; tcp: number; udp: number; icmp: number; other: number }
export interface Count { name: string; packets: number; bytes: number }

export interface AnalyticsSnapshot {
  total_packets: number
  total_bytes: number
  packets_per_sec: number
  bytes_per_sec: number
  tcp_packets: number
  udp_packets: number
  icmp_packets: number
  other_packets: number
  protocols: Count[]
  top_sources: Count[]
  top_destinations: Count[]
  total_connections: number
  active_connections: number
  untracked_packets: number
  series: Bucket[]
  window_s: number
  first_ts_us: number | null
  last_ts_us: number | null
}

export type Severity = 'Informational' | 'Low' | 'Medium' | 'High' | 'Critical'
export type Confidence = 'Low' | 'Medium' | 'High'

export interface Evidence { packet_no: number | null; ts_us: number; note: string }
export interface Measurement { label: string; value: string; kind: 'measured' | 'estimated' }

export interface Finding {
  id: string
  title: string
  severity: Severity
  confidence: Confidence
  category: string
  protocol: string
  first_ts_us: number
  last_ts_us: number
  count: number
  description: string
  evidence: Evidence[]
  measurements: Measurement[]
  possible_causes: string[]
  recommendations: string[]
  limitations: string[]
  flow: string | null
}

export interface TimelineEvent {
  ts_us: number
  finding_id: string
  title: string
  severity: Severity
  packet_no: number | null
  note: string
}

export interface LatencyObservation {
  kind: string
  label: string
  ts_us: number
  value_ms: number
  packet_no: number
  measured: boolean
  note: string
}

export interface Counters {
  tcp_retransmissions: number
  tcp_duplicate_acks: number
  tcp_out_of_order: number
  tcp_sequence_gaps: number
  tcp_resets: number
  tcp_handshakes: number
  tcp_refused: number
  dns_queries: number
  dns_responses: number
  icmp_errors: number
  fragments: number
  malformed: number
}

export interface Health { score: number | null; label: string; basis: string; capture_integrity: 'ok' | 'degraded' }

export interface DiagSnapshot {
  findings: Finding[]
  timeline: TimelineEvent[]
  health: Health
  counters: Counters
  latency: LatencyObservation[]
  capture: { received: number; kernel_dropped: number; interface_dropped: number; pipeline_dropped: number }
  dropped_findings: number
}

export interface Snapshot {
  capture: CaptureStats
  source: SourceInfo
  analytics: AnalyticsSnapshot
  diagnostics: DiagSnapshot
  buffered_packets: number
  total_packets: number
  evicted_packets: number
  recording_note: string | null
  recording_path: string | null
  system: { cpu_percent: number; memory_mb: number }
  importing: boolean
  paused: boolean
}

export interface DiagConfig {
  dns_slow_ms: number
  dns_timeout_s: number
  dns_unanswered_min: number
  syn_timeout_s: number
  conn_fail_min: number
  dupack_threshold: number
  handshake_slow_ms: number
  rtt_variation_factor: number
  rtt_min_ms: number
  rtt_min_samples: number
  retrans_ratio_medium: number
  retrans_ratio_high: number
  spike_sigma: number
  spike_min_bytes: number
  spike_min_history_s: number
  mix_share: number
  mix_min_packets: number
  malformed_min: number
  health_min_packets: number
  reorder_window_ms: number
  ratio_min_segments: number
  dupack_medium_run: number
  rst_burst_min: number
  conn_fail_high: number
  rtt_medium_ms: number
  gap_low_count: number
  malformed_medium_count: number
  spike_high_sigma: number
  spike_high_ratio: number
}

export interface Settings {
  theme: string
  default_interface: string | null
  default_filter: string
  max_packets_in_memory: number
  queue_capacity: number
  payload_retention_bytes: number
  redact_payload_display: boolean
  record_sessions: boolean
  max_session_file_mb: number
  default_export_format: 'pcap' | 'pcapng'
  analytics_window_s: number
  diag: DiagConfig
}

export interface SessionRecord {
  id: number
  name: string
  source: 'live' | 'import'
  interface: string | null
  filter: string
  started_ms: number
  ended_ms: number
  packet_count: number
  byte_count: number
  file_path: string | null
  file_exists: boolean
  health_score: number | null
  health_label: string
  finding_count: number
}

export interface ReadSummary { packets: number; format: string; dlt: number; truncated_tail: boolean }
export interface ExportResult { written: number; skipped_other_link_type: number }
