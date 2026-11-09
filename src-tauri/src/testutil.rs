//! Byte-exact packet builders used by unit and integration tests. Checksums are left zero
//! because the decoder deliberately does not validate them (NIC offload makes them unreliable).

pub const ETH_SRC: [u8; 6] = [0x02, 0, 0, 0, 0, 0x01];
pub const ETH_DST: [u8; 6] = [0x02, 0, 0, 0, 0, 0x02];

pub fn eth(ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&ETH_DST);
    v.extend_from_slice(&ETH_SRC);
    v.extend_from_slice(&ethertype.to_be_bytes());
    v.extend_from_slice(payload);
    v
}

pub struct Ip4 {
    pub src: [u8; 4],
    pub dst: [u8; 4],
    pub proto: u8,
    pub ttl: u8,
    pub id: u16,
    /// Raw flags+fragment-offset field.
    pub frag: u16,
}

impl Ip4 {
    pub fn new(src: [u8; 4], dst: [u8; 4], proto: u8) -> Self {
        Ip4 { src, dst, proto, ttl: 64, id: 0x1234, frag: 0x4000 }
    }
    pub fn build(&self, payload: &[u8]) -> Vec<u8> {
        let total = 20 + payload.len();
        let mut v = vec![0x45, 0];
        v.extend_from_slice(&(total as u16).to_be_bytes());
        v.extend_from_slice(&self.id.to_be_bytes());
        v.extend_from_slice(&self.frag.to_be_bytes());
        v.push(self.ttl);
        v.push(self.proto);
        v.extend_from_slice(&[0, 0]);
        v.extend_from_slice(&self.src);
        v.extend_from_slice(&self.dst);
        v.extend_from_slice(payload);
        v
    }
}

#[derive(Clone)]
pub struct Tcp {
    pub sport: u16,
    pub dport: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
    pub options: Vec<u8>,
    pub payload: Vec<u8>,
}

impl Tcp {
    pub fn new(sport: u16, dport: u16, seq: u32, ack: u32, flags: u8, len: usize) -> Self {
        Tcp { sport, dport, seq, ack, flags, window: 65535, options: vec![], payload: vec![0x41; len] }
    }
    pub fn build(&self) -> Vec<u8> {
        let mut opts = self.options.clone();
        while opts.len() % 4 != 0 {
            opts.push(1);
        }
        let doff = ((20 + opts.len()) / 4) as u8;
        let mut v = Vec::new();
        v.extend_from_slice(&self.sport.to_be_bytes());
        v.extend_from_slice(&self.dport.to_be_bytes());
        v.extend_from_slice(&self.seq.to_be_bytes());
        v.extend_from_slice(&self.ack.to_be_bytes());
        v.push(doff << 4);
        v.push(self.flags);
        v.extend_from_slice(&self.window.to_be_bytes());
        v.extend_from_slice(&[0, 0, 0, 0]);
        v.extend_from_slice(&opts);
        v.extend_from_slice(&self.payload);
        v
    }
}

pub const SYN: u8 = 0x02;
pub const ACK: u8 = 0x10;
pub const FIN: u8 = 0x01;
pub const RST: u8 = 0x04;
pub const PSH: u8 = 0x08;

pub fn tcp_frame(src: [u8; 4], dst: [u8; 4], t: &Tcp) -> Vec<u8> {
    eth(0x0800, &Ip4::new(src, dst, 6).build(&t.build()))
}

pub fn udp_payload_frame(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let mut u = Vec::new();
    u.extend_from_slice(&sport.to_be_bytes());
    u.extend_from_slice(&dport.to_be_bytes());
    u.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    u.extend_from_slice(&[0, 0]);
    u.extend_from_slice(payload);
    eth(0x0800, &Ip4::new(src, dst, 17).build(&u))
}

pub fn icmp_frame(src: [u8; 4], dst: [u8; 4], typ: u8, code: u8, rest: [u8; 4], body: &[u8]) -> Vec<u8> {
    let mut m = vec![typ, code, 0, 0];
    m.extend_from_slice(&rest);
    m.extend_from_slice(body);
    eth(0x0800, &Ip4::new(src, dst, 1).build(&m))
}

pub fn dns_message(id: u16, response: bool, rcode: u8, name: &str, qtype: u16, answers: u16) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&id.to_be_bytes());
    let flags: u16 = if response { 0x8180 | rcode as u16 } else { 0x0100 };
    v.extend_from_slice(&flags.to_be_bytes());
    v.extend_from_slice(&1u16.to_be_bytes());
    v.extend_from_slice(&answers.to_be_bytes());
    v.extend_from_slice(&[0, 0, 0, 0]);
    for label in name.split('.') {
        v.push(label.len() as u8);
        v.extend_from_slice(label.as_bytes());
    }
    v.push(0);
    v.extend_from_slice(&qtype.to_be_bytes());
    v.extend_from_slice(&1u16.to_be_bytes());
    for _ in 0..answers {
        // pointer to the question name, type A, class IN, ttl 60, rdlen 4
        v.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 2, 3, 4]);
    }
    v
}

pub fn arp_frame(op: u16, spa: [u8; 4], tpa: [u8; 4]) -> Vec<u8> {
    let mut a = vec![0, 1, 8, 0, 6, 4];
    a.extend_from_slice(&op.to_be_bytes());
    a.extend_from_slice(&ETH_SRC);
    a.extend_from_slice(&spa);
    a.extend_from_slice(&[0; 6]);
    a.extend_from_slice(&tpa);
    eth(0x0806, &a)
}

pub fn ipv6_header(next: u8, payload: &[u8], hop: u8) -> Vec<u8> {
    let mut v = vec![0x60, 0, 0, 0];
    v.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    v.push(next);
    v.push(hop);
    let mut src = [0u8; 16];
    src[0] = 0x20;
    src[1] = 0x01;
    src[15] = 1;
    let mut dst = src;
    dst[15] = 2;
    v.extend_from_slice(&src);
    v.extend_from_slice(&dst);
    v.extend_from_slice(payload);
    v
}

pub fn tcp6_frame(t: &Tcp) -> Vec<u8> {
    eth(0x86DD, &ipv6_header(6, &t.build(), 60))
}
