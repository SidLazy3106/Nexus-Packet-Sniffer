#!/usr/bin/env python3
"""Generate samples/nexus-demo.pcap: a synthetic, deterministic capture for trying NEXUS.

Only reserved documentation addresses are used (RFC 5737 IPv4: 192.0.2.0/24, 198.51.100.0/24,
203.0.113.0/24; RFC 3849 IPv6: 2001:db8::/32) and locally administered MAC addresses, so the file
contains no real network data. It contains ordinary traffic plus a few deliberate conditions
(retransmissions, duplicate ACKs, reordering, refused connections, slow and failing DNS, an ICMP
unreachable, a traffic burst) so every NEXUS screen has something real to show.

    py -3 samples/make_sample_capture.py
"""
import random
import struct
import sys
from pathlib import Path

rng = random.Random(20261109)  # fixed seed: the same file every run

CLIENT, GATEWAY, RESOLVER = "192.0.2.10", "192.0.2.1", "192.0.2.53"
WEB, API, FILES, CLOSED, DEADDNS = "198.51.100.20", "198.51.100.45", "203.0.113.80", "192.0.2.77", "192.0.2.99"
C6, S6 = "2001:db8::10", "2001:db8:1::443"
MAC = {
    CLIENT: "02:00:00:00:00:10", GATEWAY: "02:00:00:00:00:01", RESOLVER: "02:00:00:00:00:53",
    CLOSED: "02:00:00:00:00:77", C6: "02:00:00:00:00:10",
}
GW_MAC = MAC[GATEWAY]
SYN, FIN, RST, PSH, ACK = 0x02, 0x01, 0x04, 0x08, 0x10

packets = []  # (ts_seconds, frame bytes)


def mac(s):
    return bytes(int(x, 16) for x in s.split(":"))


def ip4_bytes(a):
    return bytes(int(x) for x in a.split("."))


def ip6_bytes(a):
    import ipaddress
    return ipaddress.IPv6Address(a).packed


def eth(dst, src, etype, payload):
    return mac(dst) + mac(src) + struct.pack("!H", etype) + payload


def ipv4(src, dst, proto, payload, ttl=64):
    total = 20 + len(payload)
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, rng.randrange(65536), 0x4000, ttl, proto, 0, ip4_bytes(src), ip4_bytes(dst))
    return hdr + payload


def ipv6(src, dst, nxt, payload, hop=60):
    return struct.pack("!IHBB16s16s", 0x60000000, len(payload), nxt, hop, ip6_bytes(src), ip6_bytes(dst)) + payload


def tcp(sport, dport, seq, ack, flags, payload=b"", window=64240, options=b""):
    while len(options) % 4:
        options += b"\x01"
    off = (20 + len(options)) // 4
    return struct.pack("!HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF, off << 4, flags, window, 0, 0) + options + payload


def udp(sport, dport, payload):
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def frame_for(src, dst, l4, proto):
    if ":" in src:
        return eth(GW_MAC if src == C6 else MAC[C6], MAC.get(src, "02:00:00:00:99:99"), 0x86DD, ipv6(src, dst, proto, l4))
    s_mac = MAC.get(src, "02:00:00:00:99:99")
    d_mac = MAC.get(dst, GW_MAC)
    if src == CLIENT:
        d_mac = MAC.get(dst, GW_MAC)
    else:
        d_mac = MAC[CLIENT] if dst == CLIENT else d_mac
        s_mac = MAC.get(src, GW_MAC)
    return eth(d_mac, s_mac, 0x0800, ipv4(src, dst, proto, l4))


def emit(ts, src, dst, l4, proto):
    packets.append((ts, frame_for(src, dst, l4, proto)))


def tls_like(n):
    return bytes([0x17, 0x03, 0x03, (n >> 8) & 0xFF, n & 0xFF]) + bytes(rng.randrange(256) for _ in range(max(0, n - 5)))


class Flow:
    """A TCP conversation with correct sequence/ack bookkeeping."""

    def __init__(self, c, s, sport, dport, t0, rtt=0.020):
        self.c, self.s, self.sp, self.dp, self.t, self.rtt = c, s, sport, dport, t0, rtt
        self.cseq, self.sseq = rng.randrange(1 << 20, 1 << 30), rng.randrange(1 << 20, 1 << 30)
        self.proto = 6

    def send(self, frm_client, flags, payload=b"", seq=None, ack=None, dt=0.0, opts=b""):
        self.t += dt
        if frm_client:
            a = self.cseq if seq is None else seq
            k = self.sseq if ack is None else ack
            emit(self.t, self.c, self.s, tcp(self.sp, self.dp, a, k, flags, payload, options=opts), 6)
        else:
            a = self.sseq if seq is None else seq
            k = self.cseq if ack is None else ack
            emit(self.t, self.s, self.c, tcp(self.dp, self.sp, a, k, flags, payload, options=opts), 6)

    def handshake(self, synack_delay=None):
        mss = struct.pack("!BBH", 2, 4, 1460) + b"\x04\x02" + struct.pack("!BBB", 3, 3, 7)
        self.send(True, SYN, opts=mss)
        self.cseq += 1
        self.send(False, SYN | ACK, dt=self.rtt if synack_delay is None else synack_delay, opts=mss)
        self.sseq += 1
        self.send(True, ACK, dt=0.001)

    def request(self, n_req, n_resp, think=0.030):
        req = tls_like(n_req)
        self.send(True, PSH | ACK, req, dt=0.004)
        self.cseq += len(req)
        self.send(False, ACK, dt=self.rtt)
        sent = 0
        first = True
        while sent < n_resp:
            chunk = min(1448, n_resp - sent)
            data = tls_like(chunk)
            self.send(False, PSH | ACK, data, dt=(think if first else 0.0004))
            first = False
            self.sseq += chunk
            sent += chunk
            if sent % (2 * 1448) == 0 or sent >= n_resp:
                self.send(True, ACK, dt=self.rtt * 0.5)

    def close(self):
        self.send(True, FIN | ACK, dt=0.010)
        self.cseq += 1
        self.send(False, FIN | ACK, dt=self.rtt)
        self.sseq += 1
        self.send(True, ACK, dt=0.001)


def dns_name(name):
    return b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"


def dns_query(txid, name, qtype=1):
    return struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + dns_name(name) + struct.pack("!HH", qtype, 1)


def dns_response(txid, name, rcode=0, answers=1, qtype=1):
    flags = 0x8180 | rcode
    body = struct.pack("!HHHHHH", txid, flags, 1, answers if rcode == 0 else 0, 0, 0) + dns_name(name) + struct.pack("!HH", qtype, 1)
    if rcode == 0:
        for _ in range(answers):
            body += b"\xc0\x0c" + struct.pack("!HHIH", qtype, 1, 300, 4) + bytes([198, 51, 100, rng.randrange(1, 250)])
    return body


def dns_exchange(t, name, delay=0.018, rcode=0, answer=True, server=RESOLVER, sport=None):
    txid, sport = rng.randrange(65536), sport or rng.randrange(40000, 60000)
    emit(t, CLIENT, server, udp(sport, 53, dns_query(txid, name)), 17)
    if answer:
        emit(t + delay, server, CLIENT, udp(53, sport, dns_response(txid, name, rcode)), 17)


def arp(ts, op, spa, tpa, sha, tha="00:00:00:00:00:00", dst_mac="ff:ff:ff:ff:ff:ff"):
    body = struct.pack("!HHBBH", 1, 0x0800, 6, 4, op) + mac(sha) + ip4_bytes(spa) + mac(tha) + ip4_bytes(tpa)
    packets.append((ts, eth(dst_mac if op == 1 else tha, sha, 0x0806, body)))


def icmp(ts, src, dst, typ, code, rest, body=b""):
    emit(ts, src, dst, struct.pack("!BBHI", typ, code, 0, rest) + body, 1)


def main():
    t = 1_794_000_000.0  # an arbitrary fixed start

    # --- link layer: ARP ---
    arp(t, 1, CLIENT, GATEWAY, MAC[CLIENT])
    arp(t + 0.002, 2, GATEWAY, CLIENT, MAC[GATEWAY], tha=MAC[CLIENT])
    arp(t + 31.0, 1, CLIENT, CLIENT, MAC[CLIENT])  # gratuitous

    # --- DNS: normal, slow, errors, unanswered ---
    for i, name in enumerate(["example.org", "api.example.org", "files.example.org", "cdn.example.org", "docs.example.org"]):
        dns_exchange(t + 0.5 + i * 7.3, name, delay=0.012 + 0.004 * i)
    dns_exchange(t + 22.0, "slow-resolver.example.org", delay=0.92)
    for i, typo in enumerate(["exmaple.org", "wwww.example.org", "exampel.org", "api.exmple.org", "docs.exampel.org", "cdn.exmaple.org"]):
        dns_exchange(t + 40.0 + i * 3.1, typo, delay=0.019, rcode=3)
    for i in range(3):
        dns_exchange(t + 58.0 + i * 1.2, "lost.example.org", answer=False, server=DEADDNS)

    # --- ordinary HTTPS-like conversations ---
    for i in range(22):
        host = WEB if i % 3 else API
        f = Flow(CLIENT, host, 50000 + i, 443, t + 1.0 + i * 3.9, rtt=0.016 + 0.002 * (i % 5))
        f.handshake()
        f.request(rng.randrange(300, 700), rng.randrange(1500, 24000))
        if i % 4 == 0:
            f.request(rng.randrange(200, 500), rng.randrange(800, 6000))
        f.close()

    # --- a slow handshake (the server answers after 420 ms) ---
    f = Flow(CLIENT, API, 51100, 443, t + 12.0, rtt=0.030)
    f.handshake(synack_delay=0.42)
    f.request(480, 5200)
    f.close()

    # --- a lossy flow: timeout retransmissions and duplicate ACKs with a fast retransmit ---
    f = Flow(CLIENT, WEB, 51200, 443, t + 26.0, rtt=0.024)
    f.handshake()
    req = tls_like(520)
    f.send(True, PSH | ACK, req, dt=0.004)
    first_seq = f.cseq
    f.cseq += len(req)
    f.send(True, PSH | ACK, req, seq=first_seq, dt=0.21)          # RTO retransmission
    f.send(False, ACK, dt=0.024)
    base = f.sseq
    segs = [tls_like(1448) for _ in range(8)]
    for k, seg in enumerate(segs):
        if k == 2:
            f.sseq += len(seg)                                     # segment 2 never reaches the capture in order
            continue
        f.send(False, PSH | ACK, seg, seq=base + k * 1448, dt=0.0005)
        f.sseq = base + (k + 1) * 1448
    for _ in range(4):                                             # receiver keeps asking for the missing bytes
        f.send(True, ACK, ack=base + 2 * 1448, dt=0.002)
    f.send(False, PSH | ACK, segs[2], seq=base + 2 * 1448, dt=0.004)  # fast retransmit
    f.send(True, ACK, ack=base + 8 * 1448, dt=0.025)
    f.close()

    # --- a flow with mild reordering ---
    f = Flow(CLIENT, FILES, 51300, 80, t + 34.0, rtt=0.019)
    f.handshake()
    f.send(True, PSH | ACK, tls_like(300), dt=0.003)
    f.cseq += 300
    base = f.sseq
    order = [0, 2, 1, 3, 4]
    for k in order:
        f.send(False, PSH | ACK, tls_like(1448), seq=base + k * 1448, dt=0.0006)
    f.sseq = base + 5 * 1448
    f.send(True, ACK, dt=0.02)
    f.close()

    # --- refused connections: nothing listens on 192.0.2.77:8080 ---
    for i in range(4):
        tt = t + 46.0 + i * 2.5
        sp = 52000 + i
        seq = rng.randrange(1 << 20, 1 << 30)
        emit(tt, CLIENT, CLOSED, tcp(sp, 8080, seq, 0, SYN), 6)
        emit(tt + 0.002, CLOSED, CLIENT, tcp(8080, sp, 0, seq + 1, RST | ACK), 6)

    # --- an abrupt reset mid-connection ---
    f = Flow(CLIENT, API, 52100, 443, t + 52.0, rtt=0.018)
    f.handshake()
    f.request(400, 3000)
    f.send(False, RST | ACK, dt=0.05)

    # --- ICMP: echo with measured RTT, and a port-unreachable error ---
    for i in range(4):
        icmp(t + 8.0 + i, CLIENT, GATEWAY, 8, 0, (0x1234 << 16) | i, b"abcdefghijklmnop")
        icmp(t + 8.0 + i + 0.004, GATEWAY, CLIENT, 0, 0, (0x1234 << 16) | i, b"abcdefghijklmnop")
    orig = ipv4(CLIENT, CLOSED, 17, udp(53123, 5000, b"x" * 8))[:28]
    icmp(t + 49.0, CLOSED, CLIENT, 3, 3, 0, orig)

    # --- IPv6: neighbour discovery, a flow with a retransmitted SYN ---
    ns = struct.pack("!BBHI", 135, 0, 0, 0) + ip6_bytes("2001:db8::1")
    packets.append((t + 3.0, eth("33:33:ff:00:00:01", MAC[C6], 0x86DD, ipv6(C6, "ff02::1:ff00:1", 58, ns, hop=255))))
    f = Flow(C6, S6, 53000, 443, t + 15.0, rtt=0.030)
    mss = struct.pack("!BBH", 2, 4, 1440)
    f.send(True, SYN, opts=mss)
    f.send(True, SYN, seq=f.cseq, dt=1.0, opts=mss)                # SYN retransmission
    f.cseq += 1
    f.send(False, SYN | ACK, dt=0.032, opts=mss)
    f.sseq += 1
    f.send(True, ACK, dt=0.001)
    f.request(350, 4200)
    f.close()
    # frames for IPv6 flows carry the right addresses through frame_for()

    # --- a short DHCP renewal ---
    dhcp = bytearray(240)
    dhcp[0] = 1
    dhcp[4:8] = struct.pack("!I", 0xCAFEBABE)
    dhcp[28:34] = mac(MAC[CLIENT])
    dhcp[236:240] = bytes([0x63, 0x82, 0x53, 0x63])
    dhcp += bytes([53, 1, 3, 255])
    packets.append((t + 20.0, eth("ff:ff:ff:ff:ff:ff", MAC[CLIENT], 0x0800, ipv4(CLIENT, "255.255.255.255", 17, udp(68, 67, bytes(dhcp))))))

    # --- a bulk download: a burst of full-size segments (about 1.9 MB in 1.6 s) ---
    f = Flow(CLIENT, FILES, 51400, 80, t + 70.0, rtt=0.019)
    f.handshake()
    f.send(True, PSH | ACK, tls_like(260), dt=0.003)
    f.cseq += 260
    for k in range(1300):
        f.send(False, ACK, tls_like(1448), dt=0.0012)
        f.sseq += 1448
        if k % 2 == 1:
            f.send(True, ACK, dt=0.0001)
    f.close()

    # --- quiet tail so the charts have a calm ending ---
    for i, name in enumerate(["example.org", "docs.example.org"]):
        dns_exchange(t + 84.0 + i * 3.0, name, delay=0.015)
    f = Flow(CLIENT, WEB, 51500, 443, t + 88.0, rtt=0.017)
    f.handshake()
    f.request(420, 2600)
    f.close()

    packets.sort(key=lambda p: p[0])
    out = Path(__file__).with_name("nexus-demo.pcap")
    with open(out, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts, data in packets:
            sec = int(ts)
            fh.write(struct.pack("<IIII", sec, int((ts - sec) * 1_000_000), len(data), len(data)))
            fh.write(data)
    print(f"wrote {out} ({len(packets)} packets, {out.stat().st_size / 1024:.0f} KiB)")


if __name__ == "__main__":
    sys.exit(main())
