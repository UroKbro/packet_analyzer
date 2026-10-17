"""Unit tests. Run with:  python -m unittest discover -s tests -v"""
import base64
import io
import json
import os
import re
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pktanalyzer import (craft, diff, dns, explain, filters, hosts, hunt, report, scoring, timeline,  # noqa: E402
                         tls, x509)
from pktanalyzer.analyzer import Analyzer, info                    # noqa: E402
from pktanalyzer.craft import ACK, FIN, PSH, RST, SYN               # noqa: E402
from pktanalyzer.decoder import Decoder, inet_checksum              # noqa: E402
from pktanalyzer.export import export_all                           # noqa: E402
from pktanalyzer.flows import seq_diff                              # noqa: E402
from pktanalyzer.http import HttpStreamParser                       # noqa: E402
from pktanalyzer.pcap import LINKTYPE_ETHERNET, Frame, PcapWriter, open_capture  # noqa: E402

A, B = "10.0.0.1", "10.0.0.2"
MA, MB = "02:00:00:00:00:01", "02:00:00:00:00:02"


def eth_tcp(src, dst, sport, dport, seq, ack, flags, payload=b"", **kw):
    seg = craft.tcp(src, dst, sport, dport, seq, ack, flags, payload, **kw)
    return craft.ethernet(MA, MB, 0x0800, craft.ipv4(src, dst, 6, seg))


def decode(frame, ts=1.0):
    return Decoder().decode(1, ts, frame, LINKTYPE_ETHERNET)


class TestPcap(unittest.TestCase):
    def test_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "x.pcap")
            with PcapWriter(path) as w:
                w.write(1.5, b"\x01" * 60)
                w.write(2.25, b"\x02" * 70, orig_len=1500)
            frames = list(open_capture(path))
        self.assertEqual(len(frames), 2)
        self.assertAlmostEqual(frames[0].ts, 1.5)
        self.assertEqual(frames[1].orig_len, 1500)
        self.assertEqual(frames[1].data, b"\x02" * 70)

    def test_pcapng(self):
        def block(btype, body):
            body += b"\x00" * (-len(body) % 4)
            n = len(body) + 12
            return struct.pack("<II", btype, n) + body + struct.pack("<I", n)
        shb = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
        tsresol = struct.pack("<HHB3x", 9, 1, 9) + struct.pack("<HH", 0, 0)  # nanoseconds
        idb = block(1, struct.pack("<HHI", 1, 0, 65535) + tsresol)
        pkt = eth_tcp(A, B, 1, 2, 0, 0, SYN)
        ts = 1_700_000_000_123_456_789
        epb = block(6, struct.pack("<IIIII", 0, ts >> 32, ts & 0xFFFFFFFF, len(pkt), len(pkt)) + pkt)
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "x.pcapng")
            with open(path, "wb") as f:
                f.write(shb + idb + epb)
            frames = list(open_capture(path))
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0].data, pkt)
        self.assertAlmostEqual(frames[0].ts, 1_700_000_000.123456789, places=5)


class TestDecoder(unittest.TestCase):
    def test_tcp_layers_and_checksums(self):
        p = decode(eth_tcp(A, B, 1234, 80, 100, 0, SYN, options=craft.tcp_mss_options(1460, 7)))
        self.assertEqual([l.name for l in p.layers], ["ethernet", "ipv4", "tcp"])
        self.assertEqual(p.ip["src"], A)
        tcp = p.layer("tcp")
        self.assertTrue(tcp["flags.syn"])
        self.assertFalse(tcp["flags.ack"])
        self.assertEqual(tcp["mss"], 1460)
        self.assertEqual(tcp["wscale"], 7)
        self.assertTrue(tcp["checksum_ok"])
        self.assertTrue(p.ip["checksum_ok"])
        self.assertEqual(p.warnings, [])

    def test_bad_checksum_flagged(self):
        frame = bytearray(eth_tcp(A, B, 1234, 80, 100, 0, ACK, b"hello"))
        frame[-1] ^= 0xFF
        p = decode(bytes(frame))
        self.assertFalse(p.layer("tcp")["checksum_ok"])
        self.assertIn("bad TCP checksum", p.warnings)

    def test_checksum_function(self):
        hdr = craft.ipv4(A, B, 17, b"")
        self.assertEqual(inet_checksum(hdr), 0)

    def test_vlan_and_udp_dns(self):
        q = craft.dns_query(0x1234, "example.org")
        ip = craft.ipv4(A, B, 17, craft.udp(A, B, 5555, 53, q))
        frame = craft.mac(MB) + craft.mac(MA) + struct.pack("!HHH", 0x8100, (3 << 13) | 42, 0x0800) + ip
        p = decode(frame)
        self.assertEqual([l.name for l in p.layers], ["ethernet", "vlan", "ipv4", "udp", "dns"])
        self.assertEqual(p.layer("vlan")["id"], 42)
        self.assertEqual(p.layer("dns")["qname"], "example.org")
        self.assertIn("Standard query 0x1234 A example.org", info(p))

    def test_ipv6(self):
        src, dst = "2001:db8::1", "2001:db8::2"
        frame = craft.ethernet(MA, MB, 0x86DD, craft.ipv6(src, dst, 17, craft.udp(src, dst, 1000, 2000, b"hi")))
        p = decode(frame)
        self.assertEqual(p.ip["src"], src)
        self.assertTrue(p.layer("udp")["checksum_ok"])
        self.assertEqual(p.payload, b"hi")

    def test_arp(self):
        p = decode(craft.ethernet(MA, "ff:ff:ff:ff:ff:ff", 0x0806, craft.arp(1, MA, A, "00:00:00:00:00:00", B)))
        self.assertEqual(p.protocol, "ARP")
        self.assertEqual(info(p), f"Who has {B}? Tell {A}")

    def test_truncated_frame_does_not_crash(self):
        frame = eth_tcp(A, B, 1, 2, 0, 0, SYN)
        p = decode(frame[:30])
        self.assertTrue(any("truncated" in w for w in p.warnings))

    def test_fragment_reassembly(self):
        d = Decoder()
        payload = craft.udp(A, B, 9, 9, bytes(range(256)) * 8)  # 2056 bytes
        f1 = craft.ethernet(MA, MB, 0x0800, craft.ipv4(A, B, 17, payload[:1480], ident=7, df=False, mf=True,
                                                       total_len=1500))
        f2 = craft.ethernet(MA, MB, 0x0800, craft.ipv4(A, B, 17, payload[1480:], ident=7, df=False,
                                                       frag_offset=1480, total_len=20 + len(payload) - 1480))
        p1 = d.decode(1, 1.0, f1, LINKTYPE_ETHERNET)
        p2 = d.decode(2, 1.1, f2, LINKTYPE_ETHERNET)
        self.assertIsNone(p1.layer("udp"))
        self.assertEqual(p2.layer("udp")["sport"], 9)
        self.assertEqual(len(p2.payload), 2048)
        self.assertTrue(p2.layer("udp")["checksum_ok"])

    def test_overlapping_fragments_warn(self):
        d = Decoder()
        data = bytes(64)
        d.decode(1, 1.0, craft.ethernet(MA, MB, 0x0800, craft.ipv4(A, B, 17, data[:32], ident=9, df=False, mf=True)),
                 LINKTYPE_ETHERNET)
        p = d.decode(2, 1.0, craft.ethernet(MA, MB, 0x0800, craft.ipv4(A, B, 17, data[:32], ident=9, df=False,
                                                                       frag_offset=16)), LINKTYPE_ETHERNET)
        self.assertTrue(any("overlapping" in w for w in p.warnings))


class TestDNS(unittest.TestCase):
    def test_compression(self):
        msg = craft.dns_response(1, "a.example.com", [(1, bytes([1, 2, 3, 4])), (5, b"\x03www\xc0\x0e")])
        m = dns.parse(msg)
        self.assertEqual(m["answers"][0]["data"], "1.2.3.4")
        self.assertEqual(m["answers"][0]["name"], "a.example.com")
        self.assertEqual(m["answers"][1]["data"], "www.example.com")

    def test_pointer_loop_rejected(self):
        msg = struct.pack("!HHHHHH", 1, 0, 1, 0, 0, 0) + b"\xc0\x0c" + b"\x00\x01\x00\x01"
        with self.assertRaises(dns.DNSError):
            dns.parse(msg)


class TestHTTP(unittest.TestCase):
    def test_content_length_across_segments(self):
        p = HttpStreamParser()
        out = p.feed(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n01234", 1.0)
        self.assertEqual(out, [])
        out = p.feed(b"56789HTTP/1.1 204 No Content\r\n\r\n", 2.0)
        self.assertEqual([m["status"] for m in out], [200, 204])
        self.assertEqual(out[0]["body"], b"0123456789")

    def test_chunked(self):
        p = HttpStreamParser()
        out = p.feed(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5\r\npedia\r\n", 1.0)
        self.assertEqual(out, [])
        out = p.feed(b"0\r\n\r\n", 1.1)
        self.assertEqual(out[0]["body"], b"Wikipedia")

    def test_not_http(self):
        p = HttpStreamParser()
        p.feed(b"\x16\x03\x01\x00\x10binarybinary", 1.0)
        self.assertTrue(p.dead)


class TestFlows(unittest.TestCase):
    def run_frames(self, frames):
        an = Analyzer()
        for i, f in enumerate(frames):
            an.feed(Frame(1.0 + i * 0.01, f, LINKTYPE_ETHERNET, len(f)))
        return an

    def test_seq_wraparound(self):
        self.assertEqual(seq_diff(5, 0xFFFFFFFE), 7)
        self.assertEqual(seq_diff(0xFFFFFFFE, 5), -7)

    def test_handshake_reorder_and_teardown(self):
        isn_c, isn_s = 0xFFFFFFF0, 5000  # client ISN wraps around during the transfer
        req = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"
        body = b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nabcdef"
        frames = [
            eth_tcp(A, B, 4000, 80, isn_c, 0, SYN),
            eth_tcp(B, A, 80, 4000, isn_s, isn_c + 1, SYN | ACK),
            eth_tcp(A, B, 4000, 80, isn_c + 1, isn_s + 1, ACK),
            # request split in two, second half arrives first
            eth_tcp(A, B, 4000, 80, (isn_c + 1 + 10) & 0xFFFFFFFF, isn_s + 1, PSH | ACK, req[10:]),
            eth_tcp(A, B, 4000, 80, isn_c + 1, isn_s + 1, ACK, req[:10]),
            eth_tcp(A, B, 4000, 80, isn_c + 1, isn_s + 1, ACK, req[:10]),  # duplicate
            eth_tcp(B, A, 80, 4000, isn_s + 1, (isn_c + 1 + len(req)) & 0xFFFFFFFF, PSH | ACK, body),
            eth_tcp(A, B, 4000, 80, (isn_c + 1 + len(req)) & 0xFFFFFFFF, isn_s + 1 + len(body), FIN | ACK),
            eth_tcp(B, A, 80, 4000, isn_s + 1 + len(body), (isn_c + 2 + len(req)) & 0xFFFFFFFF, FIN | ACK),
            eth_tcp(A, B, 4000, 80, (isn_c + 2 + len(req)) & 0xFFFFFFFF, isn_s + 2 + len(body), ACK),
        ]
        an = self.run_frames(frames)
        self.assertEqual(len(an.flows), 1)
        f = an.flows[0]
        self.assertEqual(f.client, (A, 4000))
        self.assertEqual(f.state, "CLOSED")
        self.assertAlmostEqual(f.rtt, 0.02, places=6)
        self.assertEqual(bytes(f.c2s.stream), req)
        self.assertEqual(f.c2s.out_of_order, 1)
        self.assertEqual(f.c2s.retransmissions, 1)
        self.assertEqual(f.http[0]["request"]["uri"], "/")
        self.assertEqual(f.http[0]["response"]["body"], b"abcdef")
        self.assertEqual([s for _, s in f.history],
                         ["SYN_SENT", "SYN_RECEIVED", "ESTABLISHED", "FIN_WAIT", "CLOSING", "CLOSED"])

    def test_refused(self):
        an = self.run_frames([eth_tcp(A, B, 4000, 23, 1, 0, SYN), eth_tcp(B, A, 23, 4000, 0, 2, RST | ACK)])
        self.assertEqual(an.flows[0].state, "REFUSED")

    def test_midstream_roles(self):
        an = self.run_frames([eth_tcp(B, A, 443, 50000, 10, 20, ACK, b"x" * 10)])
        f = an.flows[0]
        self.assertEqual(f.server, (B, 443))
        self.assertTrue(f.midstream)


class TestFilters(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.path = os.path.join(cls.tmp.name, "sample.pcap")
        craft.write_sample(cls.path)
        cls.an = Analyzer()
        for _ in cls.an.run(open_capture(cls.path)):
            pass

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def count(self, expr):
        pred = filters.compile_filter(expr)
        return sum(1 for p in self.an.packets if pred(p))

    def test_basic(self):
        total = len(self.an.packets)
        self.assertEqual(self.count(""), total)
        self.assertEqual(self.count("tcp") + self.count("not tcp"), total)
        self.assertEqual(self.count("arp"), 3)
        self.assertEqual(self.count("dns"), 11)

    def test_fields_and_shorthands(self):
        self.assertEqual(self.count("dns.qname contains example"), 4)
        self.assertEqual(self.count('http.method == "GET"'), 3)
        self.assertEqual(self.count("tcp.flags.syn and not tcp.flags.ack and dst port 22"), 1)
        self.assertEqual(self.count("tcp.port == 80 && ip.src == 93.184.216.34"),
                         self.count("tcp and src host 93.184.216.34 and port 80"))
        self.assertGreater(self.count("ip.addr == 10.0.0.0/24"), 50)
        self.assertEqual(self.count("tcp.dport in {4444 31337}"), 2 + 7)  # 2 scan probes + 7 reverse-shell c2s
        self.assertEqual(self.count("http.user_agent matches '^sqlmap'"), 1)
        self.assertEqual(self.count("frame.len > 1400"), self.count("frame.len >= 1401"))
        self.assertEqual(self.count("alerts"), len({a.packet for a in self.an.alerts}))
        self.assertEqual(self.count("(udp or icmp) and not dns"), self.count("udp or icmp") - 11)

    def test_errors(self):
        for bad in ("tcp and", "(tcp", "foo", "port abc", "ip.src ==", "http.uri matches '('"):
            with self.assertRaises(filters.FilterError, msg=bad):
                filters.compile_filter(bad)


class TestDetectionAndExport(unittest.TestCase):
    def test_sample_alerts(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "s.pcap")
            craft.write_sample(path)
            an = Analyzer()
            for _ in an.run(open_capture(path)):
                pass
            rules = {a.rule for a in an.alerts}
            for expected in ("port-scan", "xmas-scan", "null-scan", "arp-spoof", "dns-tunneling", "scanner-ua",
                             "cleartext-credentials", "path-traversal", "suspicious-port"):
                self.assertIn(expected, rules)
            out = os.path.join(d, "export")
            written = export_all(an, out)
            for name in ("flows.json", "flows.csv", "packets.jsonl", "alerts.json", "dns.json", "http.json",
                         "packets.pcap", "streams/"):
                self.assertIn(name, written)
            with open(written["flows.json"]) as f:
                flows = json.load(f)
            self.assertEqual(len(flows), len(an.flows))
            self.assertEqual(len(list(open_capture(written["packets.pcap"]))), an.count)
            self.assertTrue(any(n.endswith(".html") for n in os.listdir(written["streams/"])))

    def test_syn_flood(self):
        an = Analyzer()
        for i in range(250):
            f = eth_tcp(f"198.51.100.{i % 250}", B, 1024 + i, 80, i, 0, SYN)
            an.feed(Frame(1.0 + i * 0.001, f, LINKTYPE_ETHERNET, len(f)))
        self.assertIn("syn-flood", {a.rule for a in an.alerts})


class TestTLS(unittest.TestCase):
    def test_real_openssl_certificate(self):
        with open(os.path.join(os.path.dirname(__file__), "data", "selfsigned_rsa2048.der"), "rb") as f:
            c = x509.parse_certificate(f.read())
        self.assertEqual(c["subject_cn"], "example.test")
        self.assertEqual(c["subject_o"], "Test Org")
        self.assertTrue(c["self_signed"])
        self.assertEqual(c["key_alg"], "RSA")
        self.assertEqual(c["key_bits"], 2048)
        self.assertEqual(c["sig_alg"], "sha256WithRSAEncryption")
        self.assertEqual(c["sans"], ["example.test", "*.example.test", "10.1.2.3"])
        # matches `openssl x509 -fingerprint -sha256`
        self.assertTrue(c["sha256"].startswith("80:9F:8A:AF:37:28:4D:F6"))
        self.assertTrue(x509.name_matches("www.example.test", c))
        self.assertFalse(x509.name_matches("a.b.example.test", c))
        self.assertFalse(x509.name_matches("example.org", c))

    def test_crafted_chain_split_across_records(self):
        leaf = craft.make_certificate({"CN": "x.test"}, {"CN": "CA"}, 0, 2e9, ["x.test"], key_bits=1024)
        flight = craft.tls_server_hello(0xC030) + craft.tls_certificate_msg([leaf, leaf]) + craft.tls_handshake(14, b"")
        records = craft.tls_record(22, flight[:300]) + craft.tls_record(22, flight[300:])
        p = tls.TlsStreamParser()
        msgs = []
        for i in range(0, len(records), 97):  # deliver in awkward slices like TCP segments
            msgs += p.feed(records[i:i + 97])
        self.assertEqual([m["type"] for m in msgs], ["ServerHello", "Certificate", "ServerHelloDone"])
        self.assertEqual(msgs[0]["cipher"], "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384")
        self.assertEqual(len(msgs[1]["certs"]), 2)
        self.assertEqual(msgs[1]["certs"][0]["key_bits"], 1024)
        self.assertTrue(tls.is_weak_cipher("TLS_RSA_WITH_RC4_128_SHA"))
        self.assertFalse(tls.is_weak_cipher("TLS_AES_128_GCM_SHA256"))

    def test_sample_sessions(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "s.pcap")
            craft.write_sample(path)
            an = Analyzer()
            for _ in an.run(open_capture(path)):
                pass
        by_sni = {f.tls_sni: f for f in an.flows if f.tls_sni}
        self.assertEqual(by_sni["github.com"].tls["version"], "TLS 1.3")
        good = by_sni["api.example.com"].tls
        self.assertEqual(good["cipher"], "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
        self.assertEqual(len(good["certs"]), 2)
        self.assertTrue(good["certs"][1]["is_ca"])
        bad_rules = {a.rule for a in an.alerts if a.src == "203.0.113.50"}
        self.assertEqual(bad_rules, {"tls-old-version", "tls-weak-cipher", "tls-expired-cert", "tls-self-signed",
                                     "tls-name-mismatch", "tls-handshake-failed"})
        self.assertFalse(any(a.src == "198.51.100.20" for a in an.alerts))


class TestTimeline(unittest.TestCase):
    def test_sample_story(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "s.pcap")
            craft.write_sample(path)
            an = Analyzer()
            for _ in an.run(open_capture(path)):
                pass
        events = timeline.build(an)
        self.assertEqual(events, sorted(events, key=lambda e: e.ts))
        kinds = {e.kind for e in events}
        self.assertTrue({"handshake", "dns", "http", "tls", "retrans", "reset", "alert"} <= kinds)
        dns_ev = next(e for e in events if e.kind == "dns" and "example.com" in e.title)
        self.assertAlmostEqual(dns_ev.duration, 0.012, places=4)
        http_ev = next(e for e in events if e.kind == "http" and "/index.html" in e.title)
        self.assertIn("200", http_ev.detail)
        scan = next(e for e in events if e.kind == "reset" and e.count > 1)
        self.assertEqual(scan.count, 20)
        self.assertIn("ports 21, 22", scan.detail)
        # filtering by host and flow
        self.assertTrue(all("10.0.0.66" in (e.src, e.dst) for e in timeline.build(an, host="10.0.0.66")))
        self.assertTrue(all(e.flow == 2 for e in timeline.build(an, flow_id=2)))
        self.assertGreater(len(timeline.build(an, collapse=False)), len(events))


class TestScoring(unittest.TestCase):
    def test_sample_ranking(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "s.pcap")
            craft.write_sample(path)
            an = Analyzer()
            for _ in an.run(open_capture(path)):
                pass
        ranked = scoring.score_flows(an)
        top = {f.server[1] for f in ranked[:2]}
        self.assertEqual(top, {4444, 8080})  # reverse shell and the sqlmap request
        shell = next(f for f in ranked if f.server[1] == 4444 and "ack" in f.handshake)
        self.assertEqual(shell.risk.level, "HIGH")
        self.assertTrue(any("backdoor port 4444" in r for r in shell.risk.reasons))
        self.assertTrue(any("whoami" in r for r in shell.risk.reasons))
        normal = next(f for f in ranked if f.server == ("140.82.112.3", 443))
        self.assertEqual(normal.risk.score, 0)
        self.assertEqual(normal.risk.level, "NONE")

    def test_entropy_and_upload(self):
        self.assertLess(scoring.byte_entropy(b"a" * 100), 0.01)
        self.assertGreater(scoring.byte_entropy(bytes(range(256)) * 4), 7.99)
        isn_c, isn_s = 100, 900
        frames = [eth_tcp(A, B, 5000, 7000, isn_c, 0, SYN), eth_tcp(B, A, 7000, 5000, isn_s, isn_c + 1, SYN | ACK),
                  eth_tcp(A, B, 5000, 7000, isn_c + 1, isn_s + 1, ACK)]
        random_data = os.urandom(1400)
        seq = isn_c + 1
        for _ in range(60):  # ~84 KB of random bytes uploaded to an unregistered port
            frames.append(eth_tcp(A, B, 5000, 7000, seq, isn_s + 1, ACK, random_data))
            seq += len(random_data)
        an = Analyzer()
        for i, fr in enumerate(frames):
            an.feed(Frame(1.0 + i * 0.001, fr, LINKTYPE_ETHERNET, len(fr)))
        f = scoring.score_flows(an)[0]
        text = " ".join(f.risk.reasons)
        self.assertIn("high-entropy payload", text)
        self.assertIn("upload-heavy", text)


class TestHosts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "s.pcap")
            craft.write_sample(path)
            cls.an = Analyzer()
            for _ in cls.an.run(open_capture(path)):
                pass
        cls.hosts = {h.addr: h for h in hosts.profile(cls.an)}

    def test_roles_and_services(self):
        h = self.hosts
        self.assertIn("scanner", h["10.0.0.66"].roles)
        self.assertEqual(h["10.0.0.66"].mac, "de:ad:be:ef:00:66")
        self.assertIn("gateway", h["10.0.0.1"].roles)
        self.assertIn("DNS server", h["10.0.0.1"].roles)
        victim = h["10.0.0.23"]
        self.assertEqual(victim.open_ports, [22, 8080])          # answered the scan / served sqlmap
        self.assertIn(21, victim.closed_ports)
        self.assertNotIn(8080, victim.closed_ports)
        self.assertTrue(any("evil-c2" in d for d in victim.domains))
        self.assertIn("login.paypa1-secure.com", victim.sni)
        self.assertEqual(victim.os, "Linux")
        phish = h["203.0.113.50"]
        self.assertEqual(phish.name, "login.paypa1-secure.com")  # learned from the DNS answer
        self.assertIn("external", phish.roles)
        self.assertTrue(phish.routed)
        self.assertEqual(phish.alerts_caused["high"], 3)
        self.assertEqual(phish.max_risk, 100)
        # most interesting hosts come first
        self.assertEqual(hosts.profile(self.an)[0].addr, "10.0.0.66")
        json.dumps([x.to_dict() for x in self.hosts.values()])

    def test_os_guess(self):
        self.assertEqual(hosts.initial_ttl(57), 64)
        self.assertEqual(hosts.initial_ttl(116), 128)
        self.assertEqual(hosts.guess_os(128, dict(window=64240, options="mss,ws,sack")), "Windows")
        self.assertEqual(hosts.guess_os(64, dict(window=65535, options="mss,ts,ws")), "macOS/iOS/BSD")
        self.assertEqual(hosts.guess_os(64, dict(window=1024, options="")), "? (crafted SYNs)")
        self.assertEqual(hosts.guess_os(250, None), "network device")

    def test_dhcp_hostname(self):
        cmac = "02:00:00:00:00:aa"
        an = Analyzer()
        frames = [
            craft.ethernet(cmac, "ff:ff:ff:ff:ff:ff", 0x0800, craft.ipv4("0.0.0.0", "255.255.255.255", 17, craft.udp(
                "0.0.0.0", "255.255.255.255", 68, 67, craft.dhcp(1, 3, cmac, hostname="nk-laptop")))),
            craft.ethernet(cmac, MB, 0x0800, craft.ipv4("192.168.1.40", "192.168.1.1", 17, craft.udp(
                "192.168.1.40", "192.168.1.1", 5000, 53, craft.dns_query(1, "example.com")))),
        ]
        for i, fr in enumerate(frames):
            an.feed(Frame(1.0 + i, fr, LINKTYPE_ETHERNET, len(fr)))
        prof = {h.addr: h for h in hosts.profile(an)}
        self.assertEqual(prof["192.168.1.40"].name, "nk-laptop")
        self.assertEqual(prof["192.168.1.40"].names["nk-laptop"], "dhcp")


class TestDiff(unittest.TestCase):
    @staticmethod
    def _analyze(path):
        an = Analyzer(keep_packets=False)
        for _ in an.run(open_capture(path)):
            pass
        return an

    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory()
        cls.before = os.path.join(cls.dir.name, "before.pcap")
        cls.after = os.path.join(cls.dir.name, "after.pcap")
        craft.write_sample(cls.before, baseline=True)
        craft.write_sample(cls.after)
        cls.d = diff.diff_files(cls.before, cls.after, cls._analyze)

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    def test_changes_found(self):
        d = self.d
        self.assertEqual([(x["name"], x["before"], x["after"]) for x in d["dns_changed"]],
                         [("github.com", ["140.82.112.4"], ["140.82.112.3"])])
        self.assertIn("login.paypa1-secure.com", [x["name"] for x in d["dns_new"]])
        rules = {x["rule"] for x in d["new_alerts"]}
        self.assertTrue({"port-scan", "arp-spoof", "tls-expired-cert", "suspicious-port"} <= rules)
        self.assertFalse(d["resolved_alerts"])
        scan = d["new_conversations"][0]
        self.assertEqual((scan["client"], scan["server"], len(scan["ports"])), ("10.0.0.66", "10.0.0.23", 20))
        self.assertIn("retransmissions 0 → 1", [c for x in d["changed_conversations"] for c in x["changes"]])
        self.assertEqual(d["port_changes"], [dict(host="10.0.0.23", opened=[22, 8080], closed=[])])
        self.assertEqual([x["sni"] for x in d["tls_changed"]], ["github.com"])  # same cert for api.example.com
        self.assertEqual([x["sni"] for x in d["tls_new"]], ["login.paypa1-secure.com"])
        self.assertIn("10.0.0.66", [h["host"] for h in d["new_hosts"]])
        self.assertIn("140.82.112.4", [h["host"] for h in d["missing_hosts"]])
        self.assertTrue(d["headline"][0].startswith("16 new alert(s)"))
        json.dumps(d, default=str)

    def test_reverse_and_identical(self):
        back = diff.diff_files(self.after, self.before, self._analyze)
        self.assertEqual(len(back["resolved_alerts"]), len(self.d["new_alerts"]))
        self.assertFalse(back["new_alerts"])
        same = diff.diff_files(self.before, self.before, self._analyze)
        self.assertEqual(same["headline"], ["No significant differences."])
        for k in ("new_conversations", "missing_conversations", "changed_conversations", "dns_changed", "tls_changed",
                  "new_hosts", "port_changes", "protocols", "bandwidth"):
            self.assertFalse(same[k], k)


class TestHunt(unittest.TestCase):
    @staticmethod
    def _analyze(path):
        an = Analyzer(keep_packets=False)
        for _ in an.run(open_capture(path)):
            pass
        return an

    @classmethod
    def setUpClass(cls):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "c2.pcap")
            craft.write_c2_sample(path)
            cls.an = cls._analyze(path)
        cls.findings = cls.an.finish()

    def test_c2_sample(self):
        by_kind = {x.kind: x for x in self.findings}
        self.assertEqual(set(by_kind), {"beaconing", "exfiltration", "dns-exfiltration"})
        b = by_kind["beaconing"]
        self.assertIn("198.51.100.77:443", b.target)
        self.assertIn("sync.cdn-telemetry.example", b.target)
        self.assertEqual(len(b.series), 11)  # one of the 12 check-ins was skipped and must not break the rhythm
        self.assertGreaterEqual(b.score, 80)
        self.assertTrue(any("missed" in e for e in b.evidence))
        self.assertEqual(by_kind["exfiltration"].target, "203.0.113.99:8080")
        self.assertEqual(by_kind["dns-exfiltration"].target, "data-drop.example")
        # NTP is perfectly periodic but harmless; browsing is irregular
        self.assertFalse([x for x in self.findings if "129.6.15.28" in x.target or "93.184.216" in x.target])
        rules = [a.rule for a in self.an.alerts]
        self.assertEqual(rules.count("beaconing"), 1)
        self.an.finish()  # idempotent
        self.assertEqual([a.rule for a in self.an.alerts].count("beaconing"), 1)
        scoring.score_flows(self.an)
        exfil_flow = self.an.tracker.by_id[by_kind["exfiltration"].flows[0]]
        self.assertGreaterEqual(exfil_flow.risk.score, 40)  # the hunt's alert feeds the flow's risk

    def test_no_false_positives_on_attack_sample(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "s.pcap")
            craft.write_sample(path)
            self.assertEqual(self._analyze(path).finish(), [])

    def test_periodicity(self):
        import random
        rng = random.Random(1)
        regular = [i * 30 + rng.uniform(-1, 1) for i in range(15)]
        p = hunt.periodicity(regular)
        self.assertAlmostEqual(p["period"], 30, delta=1.5)
        self.assertLess(p["cv"], 0.1)
        self.assertGreaterEqual(hunt.beacon_score(p, [500] * 15, 15), 80)
        irregular = sorted(rng.uniform(0, 3000) for _ in range(15))
        q = hunt.periodicity(irregular)
        self.assertTrue(q is None or hunt.beacon_score(q, [], 15) < 60 or q["consistent"] < 0.6)
        self.assertIsNone(hunt.periodicity([0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6]))  # streaming, not beaconing
        self.assertIsNone(hunt.periodicity([0, 60, 120]))                      # too few to judge

    def test_dns_beacon_and_base_domain(self):
        self.assertEqual(hunt.base_domain("a.b.evil.co.uk"), "evil.co.uk")
        self.assertEqual(hunt.base_domain("x.y.example.com."), "example.com")
        an = Analyzer()
        for i in range(10):
            q = craft.dns_query(i, "check.update-svc.example")
            fr = craft.ethernet(MA, MB, 0x0800, craft.ipv4(A, B, 17, craft.udp(A, B, 30000 + i, 53, q)))
            an.feed(Frame(1000.0 + i * 300 + (i % 3), fr, LINKTYPE_ETHERNET, len(fr)))
        found = hunt.find_beacons(an)
        self.assertEqual([(x.kind, x.target) for x in found], [("beaconing", "check.update-svc.example")])

    def test_rules_explained(self):
        self.assertFalse(set(hunt.RULE_FOR.values()) - set(explain.RULES))


class TestExplorer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "s.pcap")
            craft.write_sample(path)
            cls.an = Analyzer()
            for _ in cls.an.run(open_capture(path)):
                pass

    def setUp(self):
        from rich.console import Console
        from pktanalyzer.explorer import Explorer
        self.con = Console(width=110, height=30, file=io.StringIO(), color_system=None)
        self.ex = Explorer(self.an, "s.pcap", self.con)

    def screen(self, w=110, h=30):
        with self.con.capture() as cap:
            self.con.print(self.ex.render(w, h))
        return cap.get()

    def keys(self, *ks):
        for k in ks:
            self.assertTrue(self.ex.handle_key(k), k)

    def test_navigation_and_details(self):
        self.assertIn("Where to go next", self.screen())
        self.keys("2", "j", "j", "j", "enter")
        self.assertEqual(self.ex.stack[-1].item.number, 4)
        self.assertIn("packet #4", self.screen())
        self.keys("n")
        self.assertEqual(self.ex.stack[-1].item.number, 5)
        self.keys("f")
        self.assertEqual(self.ex.stack[-1].kind, "flow")
        self.assertIn("Conversation ladder", self.screen())
        self.keys("esc", "esc")
        self.assertFalse(self.ex.stack)
        self.assertEqual(self.ex.state.cursor, 4)
        self.keys("G")
        self.assertEqual(self.ex.state.cursor, len(self.ex.packets) - 1)
        self.keys("5", "enter")
        self.assertIn("Why it matters", self.screen())
        self.keys("f")
        self.assertEqual(self.ex.stack[-1].kind, "flow")
        self.keys("tab")
        self.assertEqual(self.ex.tab_name, "Timeline")
        self.keys("btab", "btab")
        self.assertEqual(self.ex.tab_name, "Hosts")
        self.keys("enter")
        self.assertIn("Conversations of", self.screen())
        self.keys("?")
        self.assertIn("Keyboard shortcuts", self.screen())
        self.keys("x")
        self.assertFalse(self.ex.show_help)
        self.assertIn("No beaconing", (self.keys("7"), self.screen())[1])
        self.assertFalse(self.ex.handle_key("q"))

    def test_filters_and_sort(self):
        self.keys("2", "/", *"dns", "enter")
        self.assertTrue(self.ex.state.items)
        self.assertTrue(all(p.has("dns") for p in self.ex.state.items))
        self.assertIn("matches for", self.screen())
        n = len(self.ex.state.items)
        self.keys("/", *"tcp and (", "enter")
        self.assertTrue(self.ex.message.startswith("Filter error"))
        self.assertEqual((self.ex.state.query, len(self.ex.state.items)), ("dns", n))  # bad filter keeps the last
        self.keys("c")
        self.assertEqual(len(self.ex.state.items), len(self.ex.packets))
        self.keys("/", *"nope", "esc")
        self.assertEqual(self.ex.state.query, "")
        self.keys("4", "/", *"scanner", "enter")
        self.assertEqual([h.addr for h in self.ex.state.items], ["10.0.0.66"])
        self.keys("3", "s")
        risks = [f.risk.score for f in self.ex.state.items]
        self.assertEqual(risks, sorted(risks, reverse=True))

    def test_every_view_fits(self):
        for w, h in ((80, 24), (140, 45)):
            for tab in "1234567":
                self.keys(tab)
                lines = self.screen(w, h).rstrip("\n").split("\n")
                self.assertEqual(len(lines), h, (tab, w))
                self.assertTrue(all(len(line) <= w for line in lines), (tab, w))
                if tab != "1" and self.ex.state.items:
                    self.keys("enter", "pgdn", "G")
                    self.assertEqual(len(self.screen(w, h).rstrip("\n").split("\n")), h)
                    self.keys("esc")

    def test_decode_keys(self):
        from pktanalyzer.explorer import decode_keys
        self.assertEqual(decode_keys("\x1b[A\x1b[B\x1b[5~\x1b[6~\x1b[Z\x1b\r\tq/"),
                         ["up", "down", "pgup", "pgdn", "btab", "esc", "enter", "tab", "q", "/"])
        self.assertEqual(decode_keys("\x1bOH\x7f"), ["home", "backspace"])


class TestReport(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "s.pcap")
            craft.write_sample(path)
            cls.an = Analyzer()
            for _ in cls.an.run(open_capture(path)):
                pass

    def test_every_rule_explained(self):
        import inspect
        from pktanalyzer import anomalies
        raised = set(re.findall(r'_fire\([^,]+, "[a-z]+", "([a-z0-9-]+)"', inspect.getsource(anomalies)))
        self.assertGreater(len(raised), 20)
        self.assertFalse(raised - set(explain.RULES))
        groups = explain.group(self.an.alerts)
        self.assertEqual(sum(g["count"] for g in groups), len(self.an.alerts))
        self.assertEqual(groups[0]["severity"], "high")
        self.assertEqual(len({g["rule"] for g in groups}), len(groups))

    def test_html(self):
        html = report.build_report(self.an, "sample.pcap")
        self.assertTrue(html.startswith("<!doctype html>"))
        for needle in ("Executive summary", "Port scan", "Why it matters", "login.paypa1-secure.com", "10.0.0.66",
                       "<svg", "data:application/json;base64,"):
            self.assertIn(needle, html)
        self.assertNotIn("<script", html.lower())  # the report is static and safe to open anywhere
        # embedded exports decode to valid JSON
        blobs = re.findall(r'data:application/json;base64,([A-Za-z0-9+/=]+)', html)
        self.assertGreaterEqual(len(blobs), 4)
        alerts = json.loads(base64.b64decode(blobs[0]))
        self.assertEqual(len(alerts), len(self.an.alerts))

    def test_escaping(self):
        original = self.an.alerts[0].message
        self.an.alerts[0].message = "<img src=x onerror=alert(1)>"
        try:
            html = report.build_report(self.an, "<b>x</b>.pcap")
        finally:
            self.an.alerts[0].message = original
        self.assertNotIn("<img src=x", html)
        self.assertNotIn("<b>x</b>", html)


class TestCLI(unittest.TestCase):
    def test_commands_run(self):
        from pktanalyzer import cli, ui
        from rich.console import Console
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "s.pcap")
            buf = io.StringIO()
            ui.console = cli.con = Console(file=buf, width=120)
            self.assertEqual(cli.main(["sample", path]), 0)
            for args in (["read", path], ["read", path, "-f", "http", "-v", "-x"], ["show", path, "8"],
                         ["stats", path], ["flows", path, "--sort", "bytes"], ["follow", path, "2"],
                         ["alerts", path], ["alerts", path, "--explain"], ["timeline", path], ["risk", path],
                         ["tls", path, "--certs"], ["flows", path, "--sort", "risk"],
                         ["timeline", path, "-k", "dns,http", "--host", "10.0.0.23"],
                         ["hosts", path], ["hosts", path, "10.0.0.23"], ["hosts", path, "--all", "-n", "3"],
                         ["sample", "--baseline", os.path.join(d, "b.pcap")],
                         ["diff", os.path.join(d, "b.pcap"), path, "--json", os.path.join(d, "d.json")],
                         ["sample", "--c2", os.path.join(d, "c2.pcap")], ["hunt", os.path.join(d, "c2.pcap")],
                         ["hunt", path], [path], ["explore", path], ["demo"], ["demo", "--c2"],
                         ["report", path, "-o", os.path.join(d, "r.html")],
                         ["export", path, "-o", os.path.join(d, "ex")]):
                self.assertEqual(cli.main(args), 0, args)
            self.assertEqual(cli.main(["read", path, "-f", "tcp and ("]), 2)
            self.assertEqual(cli.main([]), 0)
            out = buf.getvalue()
            self.assertIn("GET", out)
            self.assertIn("Port scan", out)
            self.assertIn("pktanalyzer demo", out)    # the welcome screen
            self.assertIn("interactive terminal", out)  # explore falls back to a summary when piped


if __name__ == "__main__":
    unittest.main()
