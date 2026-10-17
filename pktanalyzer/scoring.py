"""Per-conversation risk scoring.

Each flow gets a 0-100 score built from independent pieces of evidence (alerts
on the flow, a scanning source, backdoor ports, shell commands in cleartext,
loss, malformed packets, lopsided byte counts, high-entropy payloads). Every
piece adds points and a human-readable reason, so a score is always explained.
"""
from __future__ import annotations

import ipaddress
import math
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from .anomalies import SUSPICIOUS_PORTS
from .flows import WELL_KNOWN, Flow

if TYPE_CHECKING:
    from .analyzer import Analyzer

BACKDOOR_PORTS = {4444, 5554, 6667, 12345, 31337, 1337}
SCANNER_RULES = {"port-scan", "host-sweep", "udp-scan", "xmas-scan", "null-scan", "fin-scan", "syn-fin"}
ALERT_POINTS = {"high": 40, "medium": 20, "low": 8}
SHELL_MARKERS = (b"whoami", b"/bin/sh", b"/bin/bash", b"bash -i", b"cmd.exe", b"powershell", b"/etc/passwd",
                 b"/etc/shadow", b"uname -a", b"nc -e", b"| nc ", b"wget http", b"curl http", b"chmod +x")
TLS_PORTS = {443, 465, 853, 993, 995, 8443}


@dataclass
class Risk:
    score: int
    level: str
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return dict(score=self.score, level=self.level, reasons=self.reasons)


def level_for(score: int) -> str:
    return "HIGH" if score >= 70 else "MEDIUM" if score >= 40 else "LOW" if score >= 15 else "NONE"


# Documentation ranges count as public: they stand in for internet hosts in examples and test captures.
DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")]


def is_private(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if any(a in n for n in DOC_NETS if n.version == a.version):
        return False
    return a.is_private or a.is_link_local or a.is_loopback


def byte_entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte (0 = constant, 8 = indistinguishable from random)."""
    if not data:
        return 0.0
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in Counter(data).values())


def score_flow(f: Flow, flow_alerts: list, scanners: set[str]) -> Risk:
    points: list[tuple[int, str]] = []

    # 1. alerts raised on this conversation
    seen_rules = set()
    for a in sorted(flow_alerts, key=lambda a: ALERT_POINTS[a.severity], reverse=True):
        if a.rule in seen_rules:
            continue
        seen_rules.add(a.rule)
        points.append((ALERT_POINTS[a.severity], f"alert: {a.rule}"))

    # 2. the client is a host that has been scanning
    if f.client[0] in scanners and not seen_rules & SCANNER_RULES:
        points.append((25, f"source {f.client[0]} is scanning"))

    # 3. ports
    port = f.server[1]
    established = "ack" in f.handshake or (f.proto != "tcp" and f.packets > 1) or (f.midstream and f.packets > 2)
    if port in BACKDOOR_PORTS:
        points.append((35 if established else 10,
                       f"backdoor port {port} ({SUSPICIOUS_PORTS.get(port, 'known malware port')})"
                       + ("" if established else ", not answered")))
    elif port in SUSPICIOUS_PORTS and established:
        points.append((10, f"sensitive service {SUSPICIOUS_PORTS[port]} on port {port}"))
    if established and f.proto == "tcp" and port not in WELL_KNOWN and port >= 1024 \
            and is_private(f.client[0]) and port not in BACKDOOR_PORTS and f.label in ("TCP",):
        points.append((5, f"outbound connection to unregistered port {port}"))
    if established and port in BACKDOOR_PORTS and is_private(f.client[0]):
        points.append((10, "outbound connection (victim calling out)"))

    # 4. payload content
    if f.proto == "tcp":
        sample = bytes(f.c2s.stream[:8192]) + bytes(f.s2c.stream[:8192])
        hits = [m.decode() for m in SHELL_MARKERS if m in sample]
        if hits:
            points.append((25, f"shell commands in cleartext ({', '.join(hits[:3])})"))
        biggest = max((f.c2s.stream, f.s2c.stream), key=len)
        if len(biggest) >= 512 and port not in TLS_PORTS and f.label not in ("TLS",):
            h = byte_entropy(bytes(biggest[:16384]))
            if h > 7.2:
                points.append((15, f"high-entropy payload ({h:.2f} bits/byte) on a non-TLS port"))

        # 5. transport health
        sent = f.c2s.packets + f.s2c.packets
        retrans = f.c2s.retransmissions + f.s2c.retransmissions
        if sent >= 10 and retrans / sent > 0.05:
            pct = retrans / sent * 100
            points.append((20 if pct > 20 else 10, f"{pct:.0f}% retransmissions"))
        # 6. lopsided upload
        up, down = f.c2s.stream_total, f.s2c.stream_total
        if up > 64 * 1024 and up > 10 * max(down, 1):
            points.append((15, f"upload-heavy: {up // 1024} KB sent vs {down // 1024} KB received"))

    # 7. malformed packets
    if f.malformed:
        points.append((min(25, 10 + f.malformed), f"{f.malformed} malformed packet(s)"))

    score = min(100, sum(p for p, _ in points))
    reasons = [f"{r} (+{p})" for p, r in sorted(points, key=lambda p: -p[0])]
    return Risk(score, level_for(score), reasons)


def score_flows(an: Analyzer) -> list[Flow]:
    """Score every flow (stored on ``flow.risk``) and return them riskiest first."""
    by_flow = defaultdict(list)
    scanners = set()
    for a in an.alerts:
        if a.flow is not None:
            by_flow[a.flow].append(a)
        if a.rule in SCANNER_RULES:
            scanners.add(a.src)
    for f in an.flows:
        f.risk = score_flow(f, by_flow.get(f.id, []), scanners)
    return sorted(an.flows, key=lambda f: (-f.risk.score, f.first_ts))
