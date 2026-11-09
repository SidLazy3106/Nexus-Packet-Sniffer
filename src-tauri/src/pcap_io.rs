//! Streaming PCAP / PCAPNG reader and writers. Implemented directly so that offline analysis
//! works without Npcap and without trusting length fields from untrusted files.

use crate::constants::*;
use crate::error::{NexusError, Result};
use std::io::{Read, Write};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawPacket {
    /// Microseconds since the Unix epoch.
    pub ts_us: i64,
    pub orig_len: u32,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct ReadSummary {
    pub packets: u64,
    pub format: &'static str,
    /// Link type of the first interface seen.
    pub dlt: u32,
    /// True if the file ended in the middle of a record.
    pub truncated_tail: bool,
}

fn bad(msg: impl Into<String>) -> NexusError {
    NexusError::BadCaptureFile(msg.into())
}

/// Read exactly `buf.len()` bytes. Returns Ok(false) on clean EOF before the first byte,
/// Err on EOF mid-buffer.
fn read_full<R: Read>(r: &mut R, buf: &mut [u8]) -> std::io::Result<Option<bool>> {
    let mut got = 0;
    while got < buf.len() {
        let n = r.read(&mut buf[got..])?;
        if n == 0 {
            return Ok(if got == 0 { None } else { Some(false) });
        }
        got += n;
    }
    Ok(Some(true))
}

#[derive(Clone, Copy)]
struct Endian {
    big: bool,
}
impl Endian {
    fn u16(self, b: &[u8]) -> u16 {
        let a = [b[0], b[1]];
        if self.big { u16::from_be_bytes(a) } else { u16::from_le_bytes(a) }
    }
    fn u32(self, b: &[u8]) -> u32 {
        let a = [b[0], b[1], b[2], b[3]];
        if self.big { u32::from_be_bytes(a) } else { u32::from_le_bytes(a) }
    }
}

/// Stream every packet of a PCAP or PCAPNG file to `on_packet(dlt, packet)`.
pub fn read_capture<R: Read>(mut r: R, mut on_packet: impl FnMut(u32, RawPacket)) -> Result<ReadSummary> {
    let mut magic = [0u8; 4];
    match read_full(&mut r, &mut magic)? {
        Some(true) => {}
        _ => return Err(bad("file is empty or shorter than a capture header")),
    }
    let m_le = u32::from_le_bytes(magic);
    if m_le == PCAPNG_SHB_TYPE {
        read_pcapng(r, on_packet)
    } else if let Some((big, nanos)) = match m_le {
        PCAP_MAGIC_MICROS => Some((false, false)),
        PCAP_MAGIC_NANOS => Some((false, true)),
        x if x == PCAP_MAGIC_MICROS.swap_bytes() => Some((true, false)),
        x if x == PCAP_MAGIC_NANOS.swap_bytes() => Some((true, true)),
        _ => None,
    } {
        read_pcap(r, Endian { big }, nanos, &mut on_packet)
    } else {
        Err(bad("unrecognised file signature (not PCAP or PCAPNG)"))
    }
}

fn read_pcap<R: Read>(
    mut r: R,
    e: Endian,
    nanos: bool,
    on_packet: &mut impl FnMut(u32, RawPacket),
) -> Result<ReadSummary> {
    let mut hdr = [0u8; 20];
    if read_full(&mut r, &mut hdr)? != Some(true) {
        return Err(bad("PCAP global header is truncated"));
    }
    let dlt = e.u32(&hdr[16..20]) & 0x0fff_ffff;
    let mut summary = ReadSummary { format: "pcap", dlt, ..Default::default() };
    loop {
        let mut rec = [0u8; 16];
        match read_full(&mut r, &mut rec)? {
            None => break,
            Some(false) => {
                summary.truncated_tail = true;
                break;
            }
            Some(true) => {}
        }
        let sec = e.u32(&rec[0..4]) as i64;
        let frac = e.u32(&rec[4..8]) as i64;
        let incl = e.u32(&rec[8..12]);
        let orig = e.u32(&rec[12..16]);
        if incl > MAX_IMPORT_PACKET_LEN {
            return Err(bad(format!("record {} claims {incl} captured bytes (limit {MAX_IMPORT_PACKET_LEN})", summary.packets + 1)));
        }
        let mut data = vec![0u8; incl as usize];
        if incl > 0 && read_full(&mut r, &mut data)? != Some(true) {
            summary.truncated_tail = true;
            break;
        }
        let ts_us = sec * 1_000_000 + if nanos { frac / 1000 } else { frac };
        summary.packets += 1;
        on_packet(dlt, RawPacket { ts_us, orig_len: orig.max(incl), data });
    }
    Ok(summary)
}

struct Iface {
    dlt: u32,
    /// Ticks per second.
    units_per_sec: u128,
}

fn read_pcapng<R: Read>(mut r: R, mut on_packet: impl FnMut(u32, RawPacket)) -> Result<ReadSummary> {
    const MAX_BLOCK: u32 = 64 * 1024 * 1024;
    let mut summary = ReadSummary { format: "pcapng", ..Default::default() };
    let mut e = Endian { big: false };
    let mut ifaces: Vec<Iface> = Vec::new();
    let mut first_block = true;
    let mut pending_type: Option<u32> = Some(PCAPNG_SHB_TYPE); // magic already consumed
    loop {
        let btype = match pending_type.take() {
            Some(t) => t,
            None => {
                let mut tb = [0u8; 4];
                match read_full(&mut r, &mut tb)? {
                    None => break,
                    Some(false) => {
                        summary.truncated_tail = true;
                        break;
                    }
                    Some(true) => {}
                }
                // Before the SHB tells us the byte order, block types are read little-endian;
                // after, with the section's endianness.
                if e.big { u32::from_be_bytes(tb) } else { u32::from_le_bytes(tb) }
            }
        };
        let mut lb = [0u8; 4];
        if read_full(&mut r, &mut lb)? != Some(true) {
            summary.truncated_tail = true;
            break;
        }
        // The SHB's length endianness is unknown until we read its byte-order magic.
        let mut body: Vec<u8>;
        let total_len;
        if btype == PCAPNG_SHB_TYPE {
            let mut bom = [0u8; 4];
            if read_full(&mut r, &mut bom)? != Some(true) {
                return Err(bad("PCAPNG section header is truncated"));
            }
            e = if u32::from_le_bytes(bom) == PCAPNG_BYTE_ORDER_MAGIC {
                Endian { big: false }
            } else if u32::from_be_bytes(bom) == PCAPNG_BYTE_ORDER_MAGIC {
                Endian { big: true }
            } else {
                return Err(bad("PCAPNG byte-order magic is invalid"));
            };
            total_len = e.u32(&lb);
            if !(16..=MAX_BLOCK).contains(&total_len) || total_len % 4 != 0 {
                return Err(bad("PCAPNG section header has an invalid length"));
            }
            body = vec![0u8; total_len as usize - 12];
            body[..4].copy_from_slice(&bom);
            if read_full(&mut r, &mut body[4..])? != Some(true) && body.len() > 4 {
                summary.truncated_tail = true;
                break;
            }
            // New section resets interfaces.
            ifaces.clear();
        } else {
            if first_block {
                return Err(bad("PCAPNG file does not start with a section header"));
            }
            total_len = e.u32(&lb);
            if !(12..=MAX_BLOCK).contains(&total_len) || total_len % 4 != 0 {
                return Err(bad(format!("PCAPNG block has invalid length {total_len}")));
            }
            body = vec![0u8; total_len as usize - 12];
            if !body.is_empty() && read_full(&mut r, &mut body)? != Some(true) {
                summary.truncated_tail = true;
                break;
            }
        }
        first_block = false;
        let mut trailer = [0u8; 4];
        if read_full(&mut r, &mut trailer)? != Some(true) {
            summary.truncated_tail = true;
            break;
        }
        match btype {
            PCAPNG_IDB_TYPE => {
                if body.len() < 8 {
                    return Err(bad("PCAPNG interface block is too short"));
                }
                let dlt = e.u16(&body[0..2]) as u32;
                let mut units: u128 = 1_000_000;
                // Options start after linktype(2) reserved(2) snaplen(4).
                let mut i = 8;
                while i + 4 <= body.len() {
                    let code = e.u16(&body[i..i + 2]);
                    let len = e.u16(&body[i + 2..i + 4]) as usize;
                    if code == 0 {
                        break;
                    }
                    if code == 9 && len >= 1 && i + 4 < body.len() {
                        let v = body[i + 4];
                        let exp = (v & 0x7f) as u32;
                        units = if v & 0x80 == 0 {
                            10u128.checked_pow(exp.min(18)).unwrap_or(1_000_000)
                        } else {
                            1u128 << exp.min(60)
                        };
                    }
                    i += 4 + len.div_ceil(4) * 4;
                }
                if summary.dlt == 0 && ifaces.is_empty() {
                    summary.dlt = dlt;
                }
                ifaces.push(Iface { dlt, units_per_sec: units.max(1) });
            }
            PCAPNG_EPB_TYPE => {
                if body.len() < 20 {
                    return Err(bad("PCAPNG enhanced packet block is too short"));
                }
                let id = e.u32(&body[0..4]) as usize;
                let hi = e.u32(&body[4..8]) as u128;
                let lo = e.u32(&body[8..12]) as u128;
                let cap = e.u32(&body[12..16]);
                let orig = e.u32(&body[16..20]);
                let Some(iface) = ifaces.get(id) else {
                    return Err(bad(format!("packet references undefined interface {id}")));
                };
                if cap > MAX_IMPORT_PACKET_LEN || 20 + cap as usize > body.len() {
                    return Err(bad("PCAPNG packet length exceeds its block"));
                }
                let ticks = (hi << 32) | lo;
                let ts_us = (ticks * 1_000_000 / iface.units_per_sec) as i64;
                summary.packets += 1;
                on_packet(iface.dlt, RawPacket { ts_us, orig_len: orig.max(cap), data: body[20..20 + cap as usize].to_vec() });
            }
            PCAPNG_SPB_TYPE => {
                let Some(iface) = ifaces.first() else {
                    return Err(bad("simple packet block without an interface"));
                };
                if body.len() < 4 {
                    return Err(bad("PCAPNG simple packet block is too short"));
                }
                let orig = e.u32(&body[0..4]);
                let cap = (orig as usize).min(body.len() - 4);
                summary.packets += 1;
                // Simple packet blocks carry no timestamp.
                on_packet(iface.dlt, RawPacket { ts_us: 0, orig_len: orig, data: body[4..4 + cap].to_vec() });
            }
            _ => {}
        }
    }
    Ok(summary)
}

/// Common interface for capture writers.
pub trait PacketSink {
    fn write_packet(&mut self, p: &RawPacket) -> std::io::Result<()>;
    fn finish(&mut self) -> std::io::Result<()>;
}

pub struct PcapWriter<W: Write> {
    w: W,
}

impl<W: Write> PcapWriter<W> {
    pub fn new(mut w: W, dlt: u32) -> std::io::Result<Self> {
        w.write_all(&PCAP_MAGIC_MICROS.to_le_bytes())?;
        w.write_all(&2u16.to_le_bytes())?;
        w.write_all(&4u16.to_le_bytes())?;
        w.write_all(&0i32.to_le_bytes())?;
        w.write_all(&0u32.to_le_bytes())?;
        w.write_all(&(PCAP_SNAPLEN as u32).to_le_bytes())?;
        w.write_all(&dlt.to_le_bytes())?;
        Ok(PcapWriter { w })
    }
}

impl<W: Write> PacketSink for PcapWriter<W> {
    fn write_packet(&mut self, p: &RawPacket) -> std::io::Result<()> {
        let ts = p.ts_us.max(0);
        self.w.write_all(&((ts / 1_000_000) as u32).to_le_bytes())?;
        self.w.write_all(&((ts % 1_000_000) as u32).to_le_bytes())?;
        self.w.write_all(&(p.data.len() as u32).to_le_bytes())?;
        self.w.write_all(&p.orig_len.max(p.data.len() as u32).to_le_bytes())?;
        self.w.write_all(&p.data)
    }
    fn finish(&mut self) -> std::io::Result<()> {
        self.w.flush()
    }
}

pub struct PcapNgWriter<W: Write> {
    w: W,
}

impl<W: Write> PcapNgWriter<W> {
    pub fn new(mut w: W, dlt: u32) -> std::io::Result<Self> {
        // Section header block, no options.
        w.write_all(&PCAPNG_SHB_TYPE.to_le_bytes())?;
        w.write_all(&28u32.to_le_bytes())?;
        w.write_all(&PCAPNG_BYTE_ORDER_MAGIC.to_le_bytes())?;
        w.write_all(&1u16.to_le_bytes())?;
        w.write_all(&0u16.to_le_bytes())?;
        w.write_all(&(-1i64).to_le_bytes())?;
        w.write_all(&28u32.to_le_bytes())?;
        // Interface description block with if_tsresol = 6 (microseconds).
        let len = 32u32;
        w.write_all(&PCAPNG_IDB_TYPE.to_le_bytes())?;
        w.write_all(&len.to_le_bytes())?;
        w.write_all(&(dlt as u16).to_le_bytes())?;
        w.write_all(&0u16.to_le_bytes())?;
        w.write_all(&(PCAP_SNAPLEN as u32).to_le_bytes())?;
        w.write_all(&9u16.to_le_bytes())?;
        w.write_all(&1u16.to_le_bytes())?;
        w.write_all(&[6, 0, 0, 0])?;
        w.write_all(&0u32.to_le_bytes())?; // opt_endofopt
        w.write_all(&len.to_le_bytes())?;
        Ok(PcapNgWriter { w })
    }
}

impl<W: Write> PacketSink for PcapNgWriter<W> {
    fn write_packet(&mut self, p: &RawPacket) -> std::io::Result<()> {
        let padded = p.data.len().div_ceil(4) * 4;
        let total = (32 + padded) as u32;
        let ts = p.ts_us.max(0) as u64;
        self.w.write_all(&PCAPNG_EPB_TYPE.to_le_bytes())?;
        self.w.write_all(&total.to_le_bytes())?;
        self.w.write_all(&0u32.to_le_bytes())?;
        self.w.write_all(&((ts >> 32) as u32).to_le_bytes())?;
        self.w.write_all(&(ts as u32).to_le_bytes())?;
        self.w.write_all(&(p.data.len() as u32).to_le_bytes())?;
        self.w.write_all(&p.orig_len.max(p.data.len() as u32).to_le_bytes())?;
        self.w.write_all(&p.data)?;
        self.w.write_all(&vec![0u8; padded - p.data.len()])?;
        self.w.write_all(&total.to_le_bytes())
    }
    fn finish(&mut self) -> std::io::Result<()> {
        self.w.flush()
    }
}

pub fn make_writer<'a, W: Write + Send + 'a>(w: W, format: &str, dlt: u32) -> std::io::Result<Box<dyn PacketSink + Send + 'a>> {
    if format == "pcap" {
        Ok(Box::new(PcapWriter::new(w, dlt)?))
    } else {
        Ok(Box::new(PcapNgWriter::new(w, dlt)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn sample() -> Vec<RawPacket> {
        vec![
            RawPacket { ts_us: 1_700_000_000_123_456, orig_len: 60, data: (0..60).collect() },
            RawPacket { ts_us: 1_700_000_001_000_001, orig_len: 1500, data: vec![7; 61] },
            RawPacket { ts_us: 1_700_000_002_000_000, orig_len: 0, data: vec![] },
        ]
    }

    fn roundtrip(format: &str) {
        let mut buf = Vec::new();
        {
            let mut w = make_writer(&mut buf, format, DLT_EN10MB).unwrap();
            for p in sample() {
                w.write_packet(&p).unwrap();
            }
            w.finish().unwrap();
        }
        let mut got = Vec::new();
        let s = read_capture(Cursor::new(buf), |dlt, p| {
            assert_eq!(dlt, DLT_EN10MB);
            got.push(p);
        })
        .unwrap();
        assert_eq!(s.packets, 3);
        assert!(!s.truncated_tail);
        assert_eq!(got, sample());
    }

    #[test]
    fn pcap_roundtrip() {
        roundtrip("pcap");
    }

    #[test]
    fn pcapng_roundtrip() {
        roundtrip("pcapng");
    }

    #[test]
    fn pcap_known_good_reference_bytes() {
        // Hand-assembled big-endian, nanosecond-resolution capture with one 4-byte packet.
        let mut f = Vec::new();
        f.extend_from_slice(&PCAP_MAGIC_NANOS.to_be_bytes());
        f.extend_from_slice(&[0, 2, 0, 4]);
        f.extend_from_slice(&[0; 8]);
        f.extend_from_slice(&65535u32.to_be_bytes());
        f.extend_from_slice(&1u32.to_be_bytes());
        f.extend_from_slice(&10u32.to_be_bytes()); // sec
        f.extend_from_slice(&500_000_000u32.to_be_bytes()); // nsec
        f.extend_from_slice(&4u32.to_be_bytes());
        f.extend_from_slice(&1514u32.to_be_bytes());
        f.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        let mut got = vec![];
        let s = read_capture(Cursor::new(f), |_, p| got.push(p)).unwrap();
        assert_eq!(s.format, "pcap");
        assert_eq!(got[0].ts_us, 10_500_000);
        assert_eq!(got[0].orig_len, 1514);
        assert_eq!(got[0].data, [0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn truncated_tail_is_reported_not_fatal() {
        let mut buf = Vec::new();
        {
            let mut w = make_writer(&mut buf, "pcap", 1).unwrap();
            w.write_packet(&sample()[0]).unwrap();
            w.write_packet(&sample()[1]).unwrap();
        }
        buf.truncate(buf.len() - 10);
        let mut n = 0;
        let s = read_capture(Cursor::new(buf), |_, _| n += 1).unwrap();
        assert_eq!(n, 1);
        assert!(s.truncated_tail);
    }

    #[test]
    fn garbage_and_oversize_records_are_rejected() {
        assert!(read_capture(Cursor::new(vec![]), |_, _| {}).is_err());
        assert!(read_capture(Cursor::new(b"not a capture file".to_vec()), |_, _| {}).is_err());
        let mut f = Vec::new();
        f.extend_from_slice(&PCAP_MAGIC_MICROS.to_le_bytes());
        f.extend_from_slice(&[2, 0, 4, 0]);
        f.extend_from_slice(&[0; 8]);
        f.extend_from_slice(&65535u32.to_le_bytes());
        f.extend_from_slice(&1u32.to_le_bytes());
        f.extend_from_slice(&[0; 8]);
        f.extend_from_slice(&u32::MAX.to_le_bytes()); // absurd incl_len
        f.extend_from_slice(&u32::MAX.to_le_bytes());
        assert!(read_capture(Cursor::new(f), |_, _| {}).is_err());
    }

    #[test]
    fn fuzzed_prefixes_never_panic() {
        let mut buf = Vec::new();
        for fmt in ["pcap", "pcapng"] {
            buf.clear();
            let mut w = make_writer(&mut buf, fmt, 1).unwrap();
            for p in sample() {
                w.write_packet(&p).unwrap();
            }
            drop(w);
            for cut in 0..buf.len() {
                let _ = read_capture(Cursor::new(buf[..cut].to_vec()), |_, _| {});
            }
            for i in 0..buf.len() {
                let mut c = buf.clone();
                c[i] ^= 0xff;
                let _ = read_capture(Cursor::new(c), |_, _| {});
            }
        }
    }

    #[test]
    fn pcapng_nanosecond_resolution_is_honoured() {
        let mut buf = Vec::new();
        // SHB
        buf.extend_from_slice(&PCAPNG_SHB_TYPE.to_le_bytes());
        buf.extend_from_slice(&28u32.to_le_bytes());
        buf.extend_from_slice(&PCAPNG_BYTE_ORDER_MAGIC.to_le_bytes());
        buf.extend_from_slice(&[1, 0, 0, 0]);
        buf.extend_from_slice(&(-1i64).to_le_bytes());
        buf.extend_from_slice(&28u32.to_le_bytes());
        // IDB with if_tsresol = 9
        buf.extend_from_slice(&PCAPNG_IDB_TYPE.to_le_bytes());
        buf.extend_from_slice(&32u32.to_le_bytes());
        buf.extend_from_slice(&[1, 0, 0, 0]);
        buf.extend_from_slice(&65535u32.to_le_bytes());
        buf.extend_from_slice(&[9, 0, 1, 0, 9, 0, 0, 0]);
        buf.extend_from_slice(&[0; 4]);
        buf.extend_from_slice(&32u32.to_le_bytes());
        // EPB, 2.5 s in nanoseconds
        let ticks: u64 = 2_500_000_000;
        buf.extend_from_slice(&PCAPNG_EPB_TYPE.to_le_bytes());
        buf.extend_from_slice(&36u32.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&((ticks >> 32) as u32).to_le_bytes());
        buf.extend_from_slice(&(ticks as u32).to_le_bytes());
        buf.extend_from_slice(&4u32.to_le_bytes());
        buf.extend_from_slice(&4u32.to_le_bytes());
        buf.extend_from_slice(&[1, 2, 3, 4]);
        buf.extend_from_slice(&36u32.to_le_bytes());
        let mut got = vec![];
        read_capture(Cursor::new(buf), |_, p| got.push(p)).unwrap();
        assert_eq!(got[0].ts_us, 2_500_000);
    }
}
