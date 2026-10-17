"""Heuristics that flag suspicious traffic as it is decoded.

Each rule looks at one packet (plus the flow it belongs to and some sliding-window
state) and may raise an :class:`Alert`. Alerts are rate-limited per (rule, source)
so a flood produces one clear warning instead of thousands.
"""
from __future__ import annotations

import math
from collections import Counter, defaultdict, deque
from dataclasses import dataclass

from . import tls as tlsmod
from . import x509
from .flows import Flow
from .packet import Packet

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}
SUSPICIOUS_PORTS = {23: "Telnet", 135: "MS-RPC", 139: "NetBIOS", 445: "SMB", 1337: "leet",
                    3389: "RDP", 4444: "Metasploit default", 5554: "Sasser", 6667: "IRC (botnet C2)",
                    12345: "NetBus", 31337: "Back Orifice"}
SCANNER_AGENTS = ("sqlmap", "nikto", "nmap", "masscan", "zgrab", "gobuster", "dirbuster", "wpscan",
                  "acunetix", "nessus", "hydra", "nuclei")
CLEARTEXT_LOGIN = {21: "FTP", 23: "Telnet", 110: "POP3", 143: "IMAP"}


@dataclass
class Alert:
    ts: float
    severity: str
    rule: str
    message: str
    src: str = ""
    dst: str = ""
    packet: int | None = None
    flow: int | None = None

    def to_dict(self) -> dict:
        return dict(ts=self.ts, severity=self.severity, rule=self.rule, message=self.message,
                    src=self.src, dst=self.dst, packet=self.packet, flow=self.flow)


def _short(s: str, n: int = 60) -> str:
    return s if len(s) <= n else s[:n - 1] + "…"


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


class AnomalyDetector:
    def __init__(self, scan_ports: int = 15, scan_window: float = 10.0, syn_flood_rate: int = 200,
                 cooldown: float = 30.0, checksum_alerts: bool = False):
        self.scan_ports = scan_ports
        self.scan_window = scan_window
        self.syn_flood_rate = syn_flood_rate
        self.cooldown = cooldown
        self.checksum_alerts = checksum_alerts
        self.alerts: list[Alert] = []
        self._last_fired: dict[tuple, float] = {}
        self._syn_targets: dict[str, deque] = defaultdict(deque)      # src -> (ts, dst, port)
        self._host_sweep: dict[tuple, deque] = defaultdict(deque)    # (src, port) -> (ts, dst)
        self._syn_rate: dict[str, deque] = defaultdict(deque)         # dst -> ts
        self._udp_unreach: dict[str, deque] = defaultdict(deque)      # scanner -> ts
        self._arp_table: dict[str, str] = {}
        self._nxdomain: dict[str, deque] = defaultdict(deque)
        self._dns_ids: dict[tuple, float] = {}

    def _fire(self, pkt: Packet, severity: str, rule: str, message: str, key: str = "",
              src: str | None = None, dst: str | None = None) -> Alert | None:
        k = (rule, key or pkt.src)
        last = self._last_fired.get(k)
        if last is not None and pkt.ts - last < self.cooldown:
            return None
        self._last_fired[k] = pkt.ts
        alert = Alert(pkt.ts, severity, rule, message, src if src is not None else pkt.src,
                      dst if dst is not None else pkt.dst, pkt.number, pkt.flow_id)
        self.alerts.append(alert)
        pkt.alerts.append(alert)
        return alert

    def process(self, pkt: Packet, flow: Flow | None) -> list[Alert]:
        before = len(self.alerts)
        for w in pkt.warnings:
            if "fragment" in w:
                self._fire(pkt, "high", "ip-fragment", w.capitalize())
            elif "checksum" in w and self.checksum_alerts:
                self._fire(pkt, "low", "bad-checksum", w.capitalize())
            elif "malformed" in w:
                self._fire(pkt, "medium", "malformed", w.capitalize())
        ip = pkt.ip
        if ip is not None:
            if ip["src"] == ip["dst"] and pkt.sport is not None and pkt.sport == pkt.dport:
                self._fire(pkt, "high", "land-attack", "Source and destination address/port are identical (LAND attack)")
            if ip.get("ttl", 64) <= 1 and pkt.layer("tcp"):
                self._fire(pkt, "low", "low-ttl", f"TCP packet with TTL {ip['ttl']} (traceroute or evasion)")
        tcp = pkt.layer("tcp")
        if tcp is not None:
            self._tcp(pkt, tcp, flow)
        if pkt.layer("udp") is not None and pkt.dport in SUSPICIOUS_PORTS:
            self._fire(pkt, "low", "suspicious-port",
                       f"UDP to port {pkt.dport} ({SUSPICIOUS_PORTS[pkt.dport]})", key=f"{pkt.src}>{pkt.dport}")
        icmp = pkt.layer("icmp")
        if icmp is not None:
            self._icmp(pkt, icmp)
        d = pkt.layer("dns")
        if d is not None:
            self._dns(pkt, d)
        h = pkt.layer("http")
        if h is not None:
            self._http(pkt, h)
        a = pkt.layer("arp")
        if a is not None:
            self._arp(pkt, a)
        return self.alerts[before:]

    # -- flow-level events (raised by the tracker after stream reassembly) ----
    def flow_event(self, pkt: Packet | None, flow: Flow, kind: str, data) -> None:
        if pkt is None or kind != "tls":
            return
        ends = dict(src=flow.server[0], dst=flow.client[0])  # the server is the one presenting the problem
        where = f"{flow.server[0]}:{flow.server[1]}"
        name = flow.tls_sni or where
        if data["type"] == "ServerHello":
            version, cipher = data.get("hello_version"), data.get("cipher", "")
            if version in tlsmod.OLD_VERSIONS:
                self._fire(pkt, "medium", "tls-old-version", f"{name} negotiated {version} (deprecated)",
                           key=f"ver|{where}", **ends)
            if cipher and tlsmod.is_weak_cipher(cipher):
                self._fire(pkt, "high", "tls-weak-cipher", f"{name} chose weak cipher {cipher}",
                           key=f"cipher|{where}", **ends)
        elif data["type"] == "Certificate" and data.get("certs"):
            leaf = data["certs"][0]
            if "error" in leaf:
                self._fire(pkt, "low", "tls-bad-cert", f"Unparsable certificate from {where}: {leaf['error']}",
                           key=f"cert|{where}", **ends)
                return
            cn = leaf["subject_cn"] or leaf["subject"]
            if pkt.ts > leaf["not_after"]:
                days = int((pkt.ts - leaf["not_after"]) // 86400)
                self._fire(pkt, "high", "tls-expired-cert", f"Certificate for {cn} expired {days} days before this "
                           f"connection ({where})", key=f"exp|{where}", **ends)
            elif pkt.ts < leaf["not_before"]:
                self._fire(pkt, "medium", "tls-cert-not-yet-valid", f"Certificate for {cn} is not valid yet ({where})",
                           key=f"nyv|{where}", **ends)
            if leaf["self_signed"] and len(data["certs"]) == 1:
                self._fire(pkt, "medium", "tls-self-signed", f"Self-signed certificate {cn} presented by {where}",
                           key=f"self|{where}", **ends)
            if flow.tls_sni and not x509.name_matches(flow.tls_sni, leaf):
                names = ", ".join(leaf["sans"][:3]) or cn
                self._fire(pkt, "high", "tls-name-mismatch",
                           f"Certificate for {names} does not cover requested name {flow.tls_sni}",
                           key=f"name|{where}", **ends)
            if leaf["key_alg"] == "RSA" and leaf["key_bits"] and leaf["key_bits"] < 2048:
                self._fire(pkt, "medium", "tls-weak-key", f"{cn} uses a {leaf['key_bits']}-bit RSA key",
                           key=f"key|{where}", **ends)
            if leaf["sig_alg"].startswith(("md5", "sha1", "ecdsa-with-SHA1")):
                self._fire(pkt, "low", "tls-weak-signature", f"{cn} is signed with {leaf['sig_alg']}",
                           key=f"sig|{where}", **ends)
        elif data["type"] == "Alert" and data["level"] == "fatal":
            cert_problem = "certificate" in data["description"] or data["description"] in ("unknown_ca",)
            self._fire(pkt, "medium" if cert_problem else "low", "tls-handshake-failed",
                       f"TLS fatal alert {data['description']} on {name}", key=f"alert|{where}", **ends)

    # -- TCP ------------------------------------------------------------------
    def _tcp(self, pkt: Packet, tcp, flow: Flow | None) -> None:
        f = tcp["flags"]
        syn, ack, fin, rst, psh, urg = (tcp["flags.syn"], tcp["flags.ack"], tcp["flags.fin"],
                                        tcp["flags.rst"], tcp["flags.psh"], tcp["flags.urg"])
        if f & 0x3F == 0:
            self._fire(pkt, "high", "null-scan", "TCP packet with no flags set (NULL scan)")
        elif fin and psh and urg and not ack:
            self._fire(pkt, "high", "xmas-scan", "TCP FIN+PSH+URG (Xmas scan)")
        elif fin and not ack and not syn and not rst and (flow is None or flow.state in ("NEW", "ESTABLISHED")
                                                          and flow.packets <= 1):
            self._fire(pkt, "medium", "fin-scan", "Lone TCP FIN with no connection (FIN scan)")
        if syn and fin:
            self._fire(pkt, "high", "syn-fin", "TCP SYN+FIN set together (invalid, used for OS fingerprinting/evasion)")
        if syn and rst:
            self._fire(pkt, "high", "syn-rst", "TCP SYN+RST set together (invalid)")
        if syn and not ack:
            now = pkt.ts
            dst, port = pkt.dst, pkt.dport
            # vertical scan: one source, many ports on one or more hosts
            q = self._syn_targets[pkt.src]
            q.append((now, dst, port))
            while q and now - q[0][0] > self.scan_window:
                q.popleft()
            ports = {(d, p) for _, d, p in q}
            if len(ports) >= self.scan_ports:
                hosts = {d for d, _ in ports}
                where = hosts.pop() if len(hosts) == 1 else f"{len(hosts) + 1} hosts"
                self._fire(pkt, "high", "port-scan",
                           f"Port scan: {len(ports)} ports probed on {where} in {self.scan_window:.0f}s",
                           dst=where)
            # horizontal sweep: one source, same port, many hosts
            hq = self._host_sweep[(pkt.src, port)]
            hq.append((now, dst))
            while hq and now - hq[0][0] > self.scan_window:
                hq.popleft()
            if len({d for _, d in hq}) >= self.scan_ports:
                self._fire(pkt, "high", "host-sweep",
                           f"Host sweep: port {port} probed on {len({d for _, d in hq})} hosts",
                           key=f"{pkt.src}:{port}", dst="many")
            # SYN flood: many SYNs per second at one destination
            rq = self._syn_rate[dst]
            rq.append(now)
            while rq and now - rq[0] > 1.0:
                rq.popleft()
            if len(rq) >= self.syn_flood_rate:
                self._fire(pkt, "high", "syn-flood", f"SYN flood: {len(rq)} SYNs/s to {dst}", key=dst, src="many")
        if syn and ack and flow is not None and flow.server[1] in SUSPICIOUS_PORTS and pkt.direction == "s2c":
            port = flow.server[1]
            self._fire(pkt, "high" if port in (4444, 6667, 31337, 12345) else "low", "suspicious-port",
                       f"Connection accepted on port {port} ({SUSPICIOUS_PORTS[port]}): "
                       f"{flow.client[0]} -> {flow.server[0]}", key=f"{flow.client[0]}>{flow.server[0]}:{port}",
                       src=flow.client[0], dst=flow.server[0])
        if flow is not None and pkt.payload and flow.server[1] in CLEARTEXT_LOGIN and pkt.direction == "c2s":
            text = pkt.payload[:64].upper()
            if text.startswith((b"USER ", b"PASS ")) or b" LOGIN " in text:
                self._fire(pkt, "medium", "cleartext-credentials",
                           f"Credentials sent in cleartext over {CLEARTEXT_LOGIN[flow.server[1]]}",
                           key=f"{pkt.src}>{pkt.dst}")
        if flow is not None and pkt.note == "retransmission" and flow.c2s and flow.s2c:
            total = flow.c2s.retransmissions + flow.s2c.retransmissions
            if total == 10:
                self._fire(pkt, "low", "retransmissions",
                           f"Flow {flow.id} has {total} retransmissions (loss or congestion)", key=f"flow{flow.id}")

    def _icmp(self, pkt: Packet, icmp) -> None:
        if icmp["type"] == 3 and icmp["code"] == 3 and icmp.get("orig_proto") == "UDP":
            # Port-unreachable replies reveal a UDP scan coming from the original sender
            scanner = icmp.get("orig_src", pkt.dst)
            q = self._udp_unreach[scanner]
            q.append(pkt.ts)
            while q and pkt.ts - q[0] > self.scan_window:
                q.popleft()
            if len(q) >= self.scan_ports:
                self._fire(pkt, "high", "udp-scan", f"UDP scan: {len(q)} closed ports answered {scanner}",
                           key=scanner, src=scanner, dst=pkt.src)
        if icmp["type"] == 8 and len(pkt.payload) > 1000:
            self._fire(pkt, "medium", "large-icmp", f"Oversized ICMP echo ({len(pkt.payload)} bytes payload)")

    def _dns(self, pkt: Packet, d) -> None:
        qname = d.get("qname") or ""
        if not d["response"]:
            labels = qname.split(".")
            longest = max(labels, key=len) if labels else ""
            if len(qname) > 100 or len(longest) > 50 or (len(longest) >= 24 and shannon_entropy(longest) > 3.8):
                self._fire(pkt, "medium", "dns-tunneling",
                           f"DNS query with long/high-entropy name (possible tunneling): {_short(qname)}",
                           key=pkt.src + "|" + ".".join(labels[-2:]))
            if d.get("qtype") in ("TXT", "NULL") and len(qname) > 40:
                self._fire(pkt, "low", "dns-txt", f"Long TXT query (tunneling tools favour TXT): {_short(qname)}",
                           key=pkt.src + "|txt")
            self._dns_ids[(pkt.src, pkt.dst, d["id"])] = pkt.ts
        else:
            if (pkt.dst, pkt.src, d["id"]) not in self._dns_ids and len(self._dns_ids) > 0:
                self._fire(pkt, "medium", "dns-unsolicited",
                           f"DNS response 0x{d['id']:04x} with no matching query (spoofing/cache poisoning?)",
                           key=f"{pkt.src}>{pkt.dst}")
            if d["rcode_name"] == "NXDOMAIN":
                q = self._nxdomain[pkt.dst]
                q.append(pkt.ts)
                while q and pkt.ts - q[0] > 60:
                    q.popleft()
                if len(q) >= 20:
                    self._fire(pkt, "medium", "nxdomain-burst",
                               f"{len(q)} NXDOMAIN answers to {pkt.dst} in 60s (DGA malware or misconfiguration)",
                               key=pkt.dst, src=pkt.dst, dst=pkt.src)

    def _http(self, pkt: Packet, h) -> None:
        if h["type"] != "request":
            return
        ua = h.get("user_agent", "").lower()
        for tool in SCANNER_AGENTS:
            if tool in ua:
                self._fire(pkt, "medium", "scanner-ua", f"HTTP request from scanning tool ({h['user_agent']})")
                break
        auth = h.get("authorization", "")
        if auth.lower().startswith("basic "):
            self._fire(pkt, "medium", "cleartext-credentials",
                       f"HTTP Basic credentials sent unencrypted to {h.get('host', pkt.dst)}",
                       key=f"{pkt.src}>{pkt.dst}")
        uri = h["uri"].lower()
        if "../" in uri or "..%2f" in uri or "%2e%2e" in uri:
            self._fire(pkt, "high", "path-traversal", f"Path traversal attempt: {h['uri'][:80]}")
        if any(s in uri for s in ("union%20select", "union+select", "' or ", "%27%20or", "or%201=1", "<script")):
            self._fire(pkt, "high", "injection", f"SQL injection / XSS pattern in URI: {h['uri'][:80]}")

    def _arp(self, pkt: Packet, a) -> None:
        if a.get("op") != 2 and not a.get("gratuitous"):
            return
        ip, mac = a["sender_ip"], a["sender_mac"]
        old = self._arp_table.get(ip)
        if old and old != mac:
            self._fire(pkt, "high", "arp-spoof", f"ARP: {ip} moved from {old} to {mac} (possible ARP spoofing)",
                       key=ip, src=mac, dst=ip)
        self._arp_table[ip] = mac
