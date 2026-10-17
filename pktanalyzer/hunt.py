"""Behavioural hunting: beaconing and data exfiltration.

These patterns only show up across many packets or conversations, so they run
once over the finished analysis instead of packet by packet.

Beaconing: malware checks in with its controller on a timer. For every
client -> destination pair (and every client -> DNS name) we collect the times
of its connections, or of its data packets inside one long connection, and
measure how regular the gaps are (a robust coefficient of variation that
tolerates an occasional missed check-in) and how similar the sizes are.

Exfiltration: data leaving the network. We look for upload-heavy destinations
(many more bytes out than in), high-entropy uploads on non-TLS ports, repeated
HTTP uploads, long-lived encrypted sessions, data smuggled in DNS query names
and oversized ICMP payloads.
"""
from __future__ import annotations

import math
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass, field

from .anomalies import Alert, shannon_entropy
from .scoring import TLS_PORTS, byte_entropy, is_private

MIN_BEACONS = 6              # check-ins needed before a rhythm means anything
MIN_INTERVAL = 1.0           # seconds; faster than this is streaming, not beaconing
MERGE_GAP = 1.0              # events closer than this are one check-in
BENIGN_PERIODIC_PORTS = {123, 67, 68, 137, 138, 1900, 5353, 5355}  # NTP, DHCP, NetBIOS, SSDP, mDNS, LLMNR
EXFIL_MIN_BYTES = 256 * 1024  # outbound volume worth a look
EXFIL_RATIO = 4.0            # bytes out per byte in
LONG_SESSION = 600.0         # seconds
DNS_MIN_NAMES = 15           # unique subdomains under one domain
DNS_MIN_BYTES = 600          # bytes of subdomain text under one domain
ICMP_MIN_BYTES = 32 * 1024


@dataclass
class Finding:
    kind: str                # beaconing, exfiltration, dns-exfiltration, long-session, icmp-tunnel
    score: int               # 0-100
    client: str
    target: str
    summary: str
    evidence: list = field(default_factory=list)
    flows: list = field(default_factory=list)
    first_ts: float = 0.0
    last_ts: float = 0.0
    series: list = field(default_factory=list)   # (ts, size) points for beacons, to draw

    @property
    def severity(self) -> str:
        return "high" if self.score >= 70 else "medium" if self.score >= 45 else "low"

    def to_dict(self) -> dict:
        return dict(kind=self.kind, score=self.score, severity=self.severity, client=self.client, target=self.target,
                    summary=self.summary, evidence=self.evidence, flows=self.flows, first_ts=self.first_ts,
                    last_ts=self.last_ts)


# -- beaconing ---------------------------------------------------------------
def _merge(events: list[tuple[float, int]]) -> list[tuple[float, int]]:
    out: list[list] = []
    for ts, size in sorted(events):
        if out and ts - out[-1][2] < MERGE_GAP:
            out[-1][1] += size
            out[-1][2] = ts
        else:
            out.append([ts, size, ts])
    return [(ts, size) for ts, size, _ in out]


def periodicity(times: list[float]) -> dict | None:
    """How clock-like a series of event times is. None when there's too little to judge."""
    if len(times) < MIN_BEACONS:
        return None
    gaps = [b - a for a, b in zip(times, times[1:])]
    period = statistics.median(gaps)
    if period < MIN_INTERVAL:
        return None
    # a skipped check-in shows up as a gap of 2-3 periods; fold those back onto one period
    folded = []
    for g in gaps:
        k = max(1, round(g / period))
        folded.append(g / k if k <= 3 else g)
    mad = statistics.median(abs(g - period) for g in folded)
    cv = 1.4826 * mad / period
    consistent = sum(1 for g in folded if abs(g - period) <= 0.2 * period) / len(folded)
    return dict(period=period, cv=cv, consistent=consistent, gaps=gaps, missed=sum(1 for g in gaps
                                                                                  if round(g / period) >= 2))


def _size_cv(sizes: list[int]) -> float:
    if len(sizes) < 2:
        return 0.0
    mean = statistics.fmean(sizes)
    return statistics.pstdev(sizes) / mean if mean else 0.0


def beacon_score(p: dict, sizes: list[int], n: int) -> int:
    rhythm = max(0.0, 1 - p["cv"] / 0.5) * 45
    consistency = p["consistent"] * 25
    size = max(0.0, 1 - _size_cv(sizes)) * 15 if any(sizes) else 7.5
    count = min(1.0, n / 20) * 15
    return round(rhythm + consistency + size + count)


def _fmt_period(s: float) -> str:
    if s >= 3600:
        return f"{s / 3600:.1f} h"
    if s >= 90:
        return f"{s / 60:.1f} min"
    return f"{s:.1f} s"


def find_beacons(an) -> list[Finding]:
    found = []
    by_dest: dict[tuple, list] = defaultdict(list)
    for f in an.flows:
        if f.proto in ("tcp", "udp") and f.server[1] not in BENIGN_PERIODIC_PORTS and f.server[1] != 53:
            by_dest[(f.client[0], f.server[0], f.server[1], f.proto)].append(f)
    for (client, server, port, proto), flows in by_dest.items():
        starts = _merge([(f.first_ts, f.bytes) for f in flows])
        inner = _merge([(e.ts, e.length) for f in flows for e in f.events if e.direction == "c2s" and e.length])
        events = starts if len(starts) >= len(inner) else inner
        how = "connections" if events is starts else "data packets inside the connection"
        p = periodicity([t for t, _ in events])
        if p is None:
            continue
        sizes = [s for _, s in events]
        score = beacon_score(p, sizes, len(events))
        if score < 60 or p["consistent"] < 0.6:
            continue
        name = next((f.tls_sni for f in flows if f.tls_sni), "") or \
            next((tx["request"].get("host", "") for f in flows for tx in f.http if tx.get("request")), "")
        target = f"{server}:{port}" + (f" ({name})" if name else "")
        ev = [f"{len(events)} {how} every {_fmt_period(p['period'])} (jitter {p['cv'] * 100:.0f}%, "
              f"{p['consistent'] * 100:.0f}% of gaps on schedule)",
              f"sizes {min(sizes):,}-{max(sizes):,} bytes (variation {_size_cv(sizes) * 100:.0f}%)"]
        if p["missed"]:
            ev.append(f"{p['missed']} missed check-in(s) tolerated")
        if not is_private(server):
            ev.append("destination is on the internet")
        found.append(Finding("beaconing", score, client, target,
                             f"{client} checks in with {target} every {_fmt_period(p['period'])}",
                             ev, sorted(f.id for f in flows), events[0][0], events[-1][0], events))
    # DNS: the same name looked up on a timer (a resolver hides the real destination)
    lookups: dict[tuple, list] = defaultdict(list)
    for f in an.flows:
        for d in f.dns:
            if not d["response"] and d["qname"]:
                lookups[(f.client[0], d["qname"].rstrip(".").lower())].append((d["ts"], f.id))
    for (client, name), hits in lookups.items():
        events = _merge([(ts, 0) for ts, _ in hits])
        p = periodicity([t for t, _ in events])
        if p is None:
            continue
        score = beacon_score(p, [], len(events))
        if score < 60 or p["consistent"] < 0.6:
            continue
        found.append(Finding("beaconing", score, client, name,
                             f"{client} looks up {name} every {_fmt_period(p['period'])}",
                             [f"{len(events)} lookups every {_fmt_period(p['period'])} (jitter {p['cv'] * 100:.0f}%)"],
                             sorted({fid for _, fid in hits}), events[0][0], events[-1][0], events))
    return found


# -- exfiltration ------------------------------------------------------------
def _payload(f, direction: str) -> int:
    if f.proto == "tcp":
        return (f.c2s if direction == "c2s" else f.s2c).stream_total
    return sum(e.length for e in f.events if e.direction == direction)


def _human(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return str(n)


def base_domain(name: str) -> str:
    labels = name.rstrip(".").lower().split(".")
    if len(labels) >= 3 and len(labels[-1]) <= 3 and len(labels[-2]) <= 3:  # co.uk, com.au
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def find_exfil(an) -> list[Finding]:
    found = []
    by_dest: dict[tuple, list] = defaultdict(list)
    for f in an.flows:
        if f.proto in ("tcp", "udp") and f.server[1] != 53:
            by_dest[(f.client[0], f.server[0])].append(f)
    for (client, server), flows in by_dest.items():
        up = sum(_payload(f, "c2s") for f in flows)
        down = sum(_payload(f, "s2c") for f in flows)
        ports = sorted({f.server[1] for f in flows})
        tls = any(f.label == "TLS" or f.server[1] in TLS_PORTS for f in flows)
        duration = max(f.last_ts for f in flows) - min(f.first_ts for f in flows)
        name = next((f.tls_sni for f in flows if f.tls_sni), "")
        target = f"{server}:{','.join(map(str, ports[:3]))}" + (f" ({name})" if name else "")
        points, ev = 0, []
        ratio = up / max(down, 1)
        if up >= EXFIL_MIN_BYTES and ratio >= EXFIL_RATIO:
            points += 40 + min(20, int(math.log2(up / EXFIL_MIN_BYTES + 1) * 6))
            ev.append(f"{_human(up)} sent vs {_human(down)} received ({ratio:.0f}:1)")
        uploads = [tx["request"] for f in flows for tx in f.http
                   if tx.get("request") and tx["request"]["method"] in ("POST", "PUT")]
        body = sum(r.get("body_len") or r.get("content_length") or 0 for r in uploads)
        if uploads and body >= 64 * 1024:
            points += 15 if len(uploads) >= 3 else 10
            ev.append(f"{len(uploads)} HTTP upload(s) carrying {_human(body)}")
        if not tls and up >= 64 * 1024:
            sample = b"".join(bytes(f.c2s.stream[:16384]) for f in flows if f.proto == "tcp")[:65536]
            h = byte_entropy(sample)
            if h > 7.5:
                points += 20
                ev.append(f"upload looks encrypted or compressed ({h:.2f} bits/byte) on a non-TLS port")
        if tls and duration >= LONG_SESSION and up >= 32 * 1024 and up > 1.5 * down:
            points += 20
            ev.append(f"encrypted session open for {_fmt_period(duration)} sending more than it receives")
        if not points:
            continue
        if not is_private(server):
            points += 10
            ev.append("destination is on the internet")
        else:
            points -= 10
        kind = "exfiltration" if up >= EXFIL_MIN_BYTES or body >= 64 * 1024 else "long-session"
        found.append(Finding(kind, min(100, points), client, target,
                             f"{client} sent {_human(up)} to {target}", ev, sorted(f.id for f in flows),
                             min(f.first_ts for f in flows), max(f.last_ts for f in flows)))

    # DNS: data encoded into the labels of many unique names under one domain
    names: dict[tuple, dict] = defaultdict(lambda: dict(subs=set(), qtypes=Counter(), flows=set(), ts=[]))
    for f in an.flows:
        for d in f.dns:
            if d["response"] or not d["qname"]:
                continue
            q = d["qname"].rstrip(".").lower()
            base = base_domain(q)
            sub = q[:-len(base)].rstrip(".")
            if not sub:
                continue
            rec = names[(f.client[0], base)]
            rec["subs"].add(sub)
            rec["qtypes"][d["qtype"]] += 1
            rec["flows"].add(f.id)
            rec["ts"].append(d["ts"])
    for (client, base), rec in names.items():
        subs = rec["subs"]
        text = sum(len(s) for s in subs)
        if len(subs) < DNS_MIN_NAMES or text < DNS_MIN_BYTES:
            continue
        ent = statistics.fmean(shannon_entropy(s.replace(".", "")) for s in subs)
        longest = max(len(s) for s in subs)
        points = 40 + min(25, len(subs) // 4) + (15 if ent > 3.5 else 0) + (10 if longest > 40 else 0)
        txt = sum(n for t, n in rec["qtypes"].items() if t in ("TXT", "NULL", "CNAME", "MX"))
        ev = [f"{len(subs)} unique subdomains of {base} carrying {_human(text)} of text",
              f"average label entropy {ent:.2f} bits/char, longest {longest} chars"]
        if txt:
            ev.append(f"{txt} of {sum(rec['qtypes'].values())} queries ask for TXT/NULL/CNAME/MX records")
            points += 10
        found.append(Finding("dns-exfiltration", min(100, points), client, base,
                             f"{client} pushed {_human(text)} into DNS names under {base}", ev,
                             sorted(rec["flows"]), min(rec["ts"]), max(rec["ts"])))

    # ICMP: bulk payload in echo requests
    for f in an.flows:
        if f.proto not in ("icmp", "icmpv6"):
            continue
        up = sum(e.length for e in f.events if e.direction == "c2s")
        if up >= ICMP_MIN_BYTES:
            found.append(Finding("icmp-tunnel", 60 if up < 4 * ICMP_MIN_BYTES else 80, f.client[0], f.server[0],
                                 f"{f.client[0]} sent {_human(up)} inside ICMP to {f.server[0]}",
                                 [f"{len([e for e in f.events if e.direction == 'c2s'])} packets, average "
                                  f"{up // max(1, len(f.events)):,} bytes of payload"], [f.id], f.first_ts, f.last_ts))
    return found


def detect(an) -> list[Finding]:
    return sorted(find_beacons(an) + find_exfil(an), key=lambda x: (-x.score, x.first_ts))


RULE_FOR = {"beaconing": "beaconing", "exfiltration": "exfiltration", "long-session": "long-encrypted-session",
            "dns-exfiltration": "dns-exfiltration", "icmp-tunnel": "icmp-tunnel"}


def to_alerts(findings: list[Finding]) -> list[Alert]:
    out = []
    for x in findings:
        if x.score < 45:
            continue
        flow = x.flows[0] if x.flows else None
        dst = x.target.split(" ")[0].rsplit(":", 1)[0] if ":" in x.target.split(" ")[0] else x.target
        out.append(Alert(x.first_ts, x.severity, RULE_FOR[x.kind], f"{x.summary} ({x.evidence[0]})",
                         x.client, dst, None, flow))
    return out
