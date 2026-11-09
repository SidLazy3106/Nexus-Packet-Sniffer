//! Live capture integration tests. They need the Npcap driver, an active network interface and
//! outbound connectivity, so they are ignored by default:
//!     cargo test --test live_capture -- --ignored --nocapture --test-threads=1

use nexus_lib::capture::{self, EmitRows};
use nexus_lib::error::NexusError;
use nexus_lib::state::AppState;
use std::net::{TcpStream, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

fn state(tag: &str) -> (AppState, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!("nexus-live-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    (AppState::new(dir.join("data")).unwrap(), dir)
}

fn pick_interface() -> capture::InterfaceInfo {
    let list = capture::list_interfaces().expect("interface enumeration");
    println!("interfaces:");
    for i in &list {
        println!("  {} | {} | {:?} | mac {:?} | {}", i.friendly_name, i.name, i.ipv4, i.mac, i.status);
    }
    list.into_iter().find(|i| i.status == "up" && !i.loopback && !i.ipv4.is_empty()).expect("no connected IPv4 interface")
}

/// DNS query for example.com to a public resolver, plus a short TCP connect, to generate traffic.
fn generate_traffic() {
    let q: Vec<u8> = {
        let mut v = vec![0xab, 0xcd, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for l in ["example", "com"] {
            v.push(l.len() as u8);
            v.extend_from_slice(l.as_bytes());
        }
        v.extend_from_slice(&[0, 0, 1, 0, 1]);
        v
    };
    let sock = UdpSocket::bind("0.0.0.0:0").unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    for _ in 0..3 {
        let _ = sock.send_to(&q, "1.1.1.1:53");
        let mut buf = [0u8; 512];
        let _ = sock.recv_from(&mut buf);
    }
    let _ = TcpStream::connect_timeout(&"1.1.1.1:80".parse().unwrap(), Duration::from_secs(3));
}

#[test]
#[ignore]
fn enumerates_interfaces_and_captures_real_traffic() {
    let (st, dir) = state("capture");
    let iface = pick_interface();
    let emitted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let e2 = emitted.clone();
    let emit: EmitRows = Arc::new(move |rows| {
        e2.fetch_add(rows.len(), std::sync::atomic::Ordering::Relaxed);
    });
    st.start_capture(&iface.name, &iface.friendly_name, "", emit).expect("start capture");
    assert!(matches!(st.start_capture(&iface.name, "x", "", Arc::new(|_| {})), Err(NexusError::AlreadyCapturing)));

    std::thread::sleep(Duration::from_millis(500));
    st.pause(true).unwrap();
    let before = st.snapshot().total_packets;
    generate_traffic(); // sent while paused: must not be ingested
    std::thread::sleep(Duration::from_millis(800));
    let paused = st.snapshot();
    assert_eq!(paused.capture.status, "paused");
    assert_eq!(paused.total_packets, before, "paused capture must not ingest");
    assert!(paused.capture.paused_discarded > 0, "packets seen while paused are counted");
    st.pause(false).unwrap();

    generate_traffic();
    std::thread::sleep(Duration::from_secs(2));
    let live = st.snapshot();
    println!("live: {} packets, {} bytes, drops k={} q={}", live.total_packets, live.analytics.total_bytes, live.capture.kernel_dropped, live.capture.pipeline_dropped);
    assert!(live.total_packets > 0, "no packets captured");
    assert!(live.analytics.udp_packets > 0 && live.analytics.tcp_packets > 0 || live.analytics.total_packets > 0);
    assert_eq!(emitted.load(std::sync::atomic::Ordering::Relaxed) as u64, live.total_packets.min(emitted.load(std::sync::atomic::Ordering::Relaxed) as u64));

    let id = st.stop_capture().unwrap();
    assert!(id.is_some(), "session should be saved");
    let rec = st.storage.lock().get_session(id.unwrap()).unwrap().unwrap();
    println!("session: {} packets, file {:?}", rec.packet_count, rec.file_path);
    assert!(rec.file_exists && rec.packet_count > 0);

    // Every captured frame must decode as Ethernet with a plausible timestamp (within the last minute).
    let now_us = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_micros() as i64;
    let rows = st.engine.lock().rows_after(0, 100_000);
    assert!(!rows.is_empty());
    for r in &rows {
        assert!((now_us - r.ts_us).abs() < 60_000_000, "timestamp {} implausible", r.ts_us);
        assert!(r.length >= 14, "frame shorter than an Ethernet header: {}", r.length);
    }
    let dns = rows.iter().find(|r| r.protocol == "DNS" && r.info.contains("example.com"));
    println!("first DNS row: {:?}", dns.map(|r| (&r.src, &r.dst, &r.info)));
    assert!(dns.is_some(), "expected our DNS query to be decoded");
    let d = st.engine.lock().get_packet(dns.unwrap().no).unwrap();
    assert!(d.layers.iter().any(|l| l.name == "IPv4") && d.layers.iter().any(|l| l.name == "UDP"));
    drop(st);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
#[ignore]
fn bpf_filter_restricts_what_is_captured() {
    let (st, dir) = state("bpf");
    let iface = pick_interface();
    st.start_capture(&iface.name, &iface.friendly_name, "udp port 53", Arc::new(|_| {})).expect("start with filter");
    std::thread::sleep(Duration::from_millis(500));
    generate_traffic(); // includes a TCP connect that the filter must exclude
    std::thread::sleep(Duration::from_secs(2));
    st.stop_capture().unwrap();
    let rows = st.engine.lock().rows_after(0, 100_000);
    println!("filtered capture: {} packets", rows.len());
    assert!(!rows.is_empty(), "DNS packets expected");
    for r in &rows {
        assert!(r.sport == Some(53) || r.dport == Some(53), "packet outside filter: {:?}", r);
        assert!(r.protocol == "DNS" || r.protocol == "UDP");
    }
    drop(st);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
#[ignore]
fn invalid_filter_and_unknown_device_are_clear_errors() {
    assert!(matches!(capture::validate_filter("tcp port"), Err(NexusError::InvalidFilter(_))));
    assert!(capture::validate_filter("tcp port 443 and host 10.0.0.1").is_ok());
    assert!(capture::validate_filter("").is_ok());

    let (st, dir) = state("errors");
    let iface = pick_interface();
    let e = st.start_capture(&iface.name, "x", "not a valid ((filter", Arc::new(|_| {})).unwrap_err();
    println!("bad filter error: {e}");
    assert!(matches!(e, NexusError::InvalidFilter(_)), "{e:?}");
    assert!(!st.is_capturing(), "failed start must leave no capture running");

    let e = st.start_capture(r"\Device\NPF_{00000000-0000-0000-0000-000000000000}", "ghost", "", Arc::new(|_| {})).unwrap_err();
    println!("unknown device error: {e}");
    assert!(!st.is_capturing());
    drop(st);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
#[ignore]
fn stop_during_heavy_traffic_joins_threads_and_reports_stats() {
    let (st, dir) = state("shutdown");
    let iface = pick_interface();
    st.start_capture(&iface.name, &iface.friendly_name, "", Arc::new(|_| {})).unwrap();
    for _ in 0..5 {
        generate_traffic();
    }
    let t = std::time::Instant::now();
    st.shutdown(); // as on app exit
    assert!(t.elapsed() < Duration::from_secs(5), "shutdown took {:?}", t.elapsed());
    assert!(!st.is_capturing());
    let snap = st.snapshot();
    println!("after shutdown: {} packets, status {}", snap.total_packets, snap.capture.status);
    assert_eq!(snap.capture.status, "stopped");
    drop(st);
    let _ = std::fs::remove_dir_all(dir);
}
