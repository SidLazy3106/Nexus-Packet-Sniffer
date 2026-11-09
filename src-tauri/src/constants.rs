//! Application-wide constants. Tunable values live in `config::Settings`;
//! this module holds fixed protocol numbers and hard safety limits.

pub const APP_NAME: &str = "NEXUS";
pub const DB_FILE_NAME: &str = "nexus.sqlite3";
pub const SESSIONS_DIR: &str = "sessions";
pub const NPCAP_DIR_WINDOWS: &str = r"C:\Windows\System32\Npcap";
pub const NPCAP_DOWNLOAD_URL: &str = "https://npcap.com/#download";

// Event names shared with the frontend.
pub const EVENT_PACKETS: &str = "nexus://packets";
pub const EVENT_SNAPSHOT: &str = "nexus://snapshot";

// Capture engine.
pub const PCAP_READ_TIMEOUT_MS: i32 = 100;
pub const PCAP_SNAPLEN: i32 = 65_535;
pub const PCAP_KERNEL_BUFFER_BYTES: i32 = 16 * 1024 * 1024;
pub const BATCH_FLUSH_MS: u64 = 100;
pub const MAX_BATCH_PACKETS: usize = 2_000;
pub const SNAPSHOT_INTERVAL_MS: u64 = 1_000;
pub const CAPTURE_STATS_POLL_MS: u64 = 1_000;

// Link-layer types (pcap DLT values).
pub const DLT_NULL: u32 = 0;
pub const DLT_EN10MB: u32 = 1;
pub const DLT_RAW: u32 = 101;

// EtherTypes.
pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_ARP: u16 = 0x0806;
pub const ETHERTYPE_VLAN: u16 = 0x8100;
pub const ETHERTYPE_IPV6: u16 = 0x86DD;

// IP protocol numbers.
pub const IPPROTO_HOPOPT: u8 = 0;
pub const IPPROTO_ICMP: u8 = 1;
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;
pub const IPPROTO_ROUTING: u8 = 43;
pub const IPPROTO_FRAGMENT: u8 = 44;
pub const IPPROTO_ICMPV6: u8 = 58;
pub const IPPROTO_NONE: u8 = 59;
pub const IPPROTO_DSTOPTS: u8 = 60;

// Well-known ports.
pub const PORT_DNS: u16 = 53;
pub const PORT_MDNS: u16 = 5353;
pub const PORT_DHCP_SERVER: u16 = 67;
pub const PORT_DHCP_CLIENT: u16 = 68;

// TCP flag bits.
pub const TCP_FIN: u16 = 0x01;
pub const TCP_SYN: u16 = 0x02;
pub const TCP_RST: u16 = 0x04;
pub const TCP_PSH: u16 = 0x08;
pub const TCP_ACK: u16 = 0x10;
pub const TCP_URG: u16 = 0x20;
pub const TCP_ECE: u16 = 0x40;
pub const TCP_CWR: u16 = 0x80;

// Decoder safety limits.
pub const MAX_IPV6_EXT_HEADERS: usize = 8;
pub const MAX_DNS_NAME_LEN: usize = 255;
pub const MAX_DNS_POINTER_JUMPS: usize = 16;
pub const MAX_TCP_OPTIONS: usize = 40;
pub const HEX_PREVIEW_BYTES: usize = 64;

// Bounded-state limits for analyzers.
pub const MAX_TRACKED_FLOWS: usize = 20_000;
pub const MAX_TRACKED_ENDPOINTS: usize = 20_000;
pub const MAX_TRACKED_DNS: usize = 5_000;
pub const MAX_TRACKED_PINGS: usize = 2_000;
pub const MAX_DIAG_FLOWS: usize = 5_000;
pub const MAX_SEEN_SEGMENTS_PER_DIR: usize = 128;
pub const MAX_RTT_SAMPLES_PER_FLOW: usize = 256;
pub const MAX_FINDINGS: usize = 500;
pub const MAX_EVIDENCE_PER_FINDING: usize = 20;
pub const MAX_TIMELINE_PER_FINDING: usize = 50;
/// Severity weights for the health score (scaled by the confidence factors below).
pub const HEALTH_WEIGHT_LOW: f64 = 4.0;
pub const HEALTH_WEIGHT_MEDIUM: f64 = 12.0;
pub const HEALTH_WEIGHT_HIGH: f64 = 25.0;
pub const HEALTH_WEIGHT_CRITICAL: f64 = 40.0;
pub const HEALTH_CONF_HIGH: f64 = 1.0;
pub const HEALTH_CONF_MEDIUM: f64 = 0.7;
pub const HEALTH_CONF_LOW: f64 = 0.4;
/// IP fragments seen before the fragmentation observation is reported.
pub const FRAGMENT_REPORT_MIN: u64 = 10;
/// Driver-drop ratio above which the capture-drops finding is High instead of Medium.
pub const CAPTURE_DROP_HIGH_RATIO: f64 = 0.01;
/// Recent latency observations kept for display.
pub const MAX_LATENCY_OBSERVATIONS: usize = 1_000;
/// Timeline events returned in a snapshot (newest kept).
pub const MAX_TIMELINE_EVENTS: usize = 400;
/// Idle table entries (pings, flows) older than this are pruned when a table is full.
pub const STALE_ENTRY_US: i64 = 60_000_000;
/// Health score: repeats within a group of related findings add this fraction of ln(n) of the base weight.
pub const HEALTH_REPEAT_FACTOR: f64 = 0.25;
/// Health score: total penalty at which the score has decayed to 1/e (about 37).
pub const HEALTH_DECAY: f64 = 120.0;
pub const MAX_TIMESERIES_SECONDS: usize = 7_200;
pub const ACTIVE_FLOW_WINDOW_US: i64 = 30_000_000;

// pcap file formats.
pub const PCAP_MAGIC_MICROS: u32 = 0xA1B2_C3D4;
pub const PCAP_MAGIC_NANOS: u32 = 0xA1B2_3C4D;
pub const PCAPNG_SHB_TYPE: u32 = 0x0A0D_0D0A;
pub const PCAPNG_IDB_TYPE: u32 = 0x0000_0001;
pub const PCAPNG_SPB_TYPE: u32 = 0x0000_0003;
pub const PCAPNG_EPB_TYPE: u32 = 0x0000_0006;
pub const PCAPNG_BYTE_ORDER_MAGIC: u32 = 0x1A2B_3C4D;
pub const MAX_IMPORT_PACKET_LEN: u32 = 262_144;
