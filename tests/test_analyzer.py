"""Unit tests. Run with:  python -m unittest discover -s tests -v"""
import io
import json
import os
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pktanalyzer import craft, dns, filters, timeline                       # noqa: E402
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
        self.assertEqual(self.count("dns"), 7)

    def test_fields_and_shorthands(self):
        self.assertEqual(self.count("dns.qname contains example"), 2)
        self.assertEqual(self.count('http.method == "GET"'), 3)
        self.assertEqual(self.count("tcp.flags.syn and not tcp.flags.ack and dst port 22"), 1)
        self.assertEqual(self.count("tcp.port == 80 && ip.src == 93.184.216.34"),
                         self.count("tcp and src host 93.184.216.34 and port 80"))
        self.assertGreater(self.count("ip.addr == 10.0.0.0/24"), 50)
        self.assertEqual(self.count("tcp.dport in {4444 31337}"), 2 + 7)  # 2 scan probes + 7 reverse-shell c2s
        self.assertEqual(self.count("http.user_agent matches '^sqlmap'"), 1)
        self.assertEqual(self.count("frame.len > 1400"), self.count("frame.len >= 1401"))
        self.assertEqual(self.count("alerts"), len({a.packet for a in self.an.alerts}))
        self.assertEqual(self.count("(udp or icmp) and not dns"), self.count("udp or icmp") - 7)

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
                         ["alerts", path], ["timeline", path], ["timeline", path, "-k", "dns,http", "--host", "10.0.0.23"],
                         ["export", path, "-o", os.path.join(d, "ex")]):
                self.assertEqual(cli.main(args), 0, args)
            self.assertEqual(cli.main(["read", path, "-f", "tcp and ("]), 2)
            out = buf.getvalue()
            self.assertIn("GET", out)
            self.assertIn("Port scan", out)


if __name__ == "__main__":
    unittest.main()
