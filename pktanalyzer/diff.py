"""Compare two captures: what appeared, what disappeared and what changed.

Each capture is reduced to a snapshot keyed by things that stay stable between
captures (a conversation is client IP -> server IP:port, not the ephemeral
source port; a DNS record is name + type). Two snapshots are then compared
section by section: conversations, DNS answers, retransmissions and RTT, alerts,
TLS certificates, hosts and open ports, protocol mix and bandwidth.
"""
from __future__ import annotations

import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass, field

from . import hosts as host_profiles
from .scoring import score_flows

GROUP_PORTS = 5      # more new ports than this between one pair of hosts is reported as one line
MIN_BYTES = 10_000   # ignore byte changes smaller than this
RTT_JUMP = 1.5       # median handshake RTT must grow by this factor (and 10 ms) to be reported


@dataclass
class Snapshot:
    path: str
    packets: int
    bytes: int
    duration: float
    flows: int
    protocols: Counter
    talkers: Counter
    convs: dict = field(default_factory=dict)    # (proto, client, server, port) -> aggregate
    dns: dict = field(default_factory=dict)      # (qname, qtype) -> {answers, rcodes, queries, clients}
    alerts: dict = field(default_factory=dict)   # (rule, src, dst) -> {count, severity, message}
    tls: dict = field(default_factory=dict)      # sni -> {server, version, cipher, sha256, subject, issuer}
    hosts: dict = field(default_factory=dict)    # addr -> Host
    retrans: int = 0
    segments: int = 0

    @property
    def rate(self) -> float:
        """Average bandwidth in bytes per second."""
        return self.bytes / self.duration if self.duration > 0 else float(self.bytes)

    @property
    def retrans_pct(self) -> float:
        return self.retrans / self.segments * 100 if self.segments else 0.0


def snapshot(an, path: str = "") -> Snapshot:
    score_flows(an)
    s = Snapshot(path, an.count, an.bytes, (an.last_ts or 0) - (an.first_ts or 0), len(an.flows),
                 Counter(an.top_protocol), Counter(an.talkers))
    for f in an.flows:
        key = (f.proto, f.client[0], f.server[0], f.server[1])
        c = s.convs.setdefault(key, dict(label=f.label, flows=0, packets=0, bytes=0, retrans=0, segments=0,
                                         rtts=[], states=Counter(), max_risk=0))
        c["flows"] += 1
        c["packets"] += f.packets
        c["bytes"] += f.bytes
        c["states"][f.state] += 1
        c["max_risk"] = max(c["max_risk"], f.risk.score if f.risk else 0)
        if f.label not in ("TCP", "UDP"):
            c["label"] = f.label
        if f.proto == "tcp":
            r = f.c2s.retransmissions + f.s2c.retransmissions
            n = f.c2s.packets + f.s2c.packets
            c["retrans"] += r
            c["segments"] += n
            s.retrans += r
            s.segments += n
            if f.rtt is not None:
                c["rtts"].append(f.rtt)
        for d in f.dns:
            if not d["qname"]:
                continue
            k = (d["qname"].rstrip(".").lower(), d["qtype"])
            rec = s.dns.setdefault(k, dict(answers=set(), rcodes=Counter(), queries=0, clients=set()))
            if d["response"]:
                rec["rcodes"][d["rcode"]] += 1
                rec["answers"].update(str(a) for a in d["answers"])
            else:
                rec["queries"] += 1
                rec["clients"].add(f.client[0])
        if f.tls_sni and f.tls:
            t = f.tls
            leaf = (t.get("certs") or [{}])[0]
            s.tls[f.tls_sni] = dict(server=f"{f.server[0]}:{f.server[1]}", version=t.get("version"),
                                    cipher=t.get("cipher"), sha256=leaf.get("sha256"),
                                    subject=leaf.get("subject_cn"), issuer=leaf.get("issuer_cn"),
                                    not_after=leaf.get("not_after"))
    for a in an.alerts:
        k = (a.rule, a.src, a.dst)
        rec = s.alerts.setdefault(k, dict(count=0, severity=a.severity, message=a.message))
        rec["count"] += 1
    s.hosts = {h.addr: h for h in host_profiles.profile(an)}
    return s


def _conv_str(key: tuple, label: str) -> str:
    proto, client, server, port = key
    return f"{client} → {server}:{port}/{proto} ({label})"


def _group_new(keys: list, side: dict) -> list[dict]:
    """New/missing conversations; a burst of ports between one host pair (a scan) becomes one entry."""
    by_pair = defaultdict(list)
    for k in keys:
        by_pair[(k[0], k[1], k[2])].append(k)
    out = []
    for (proto, client, server), ks in by_pair.items():
        if len(ks) > GROUP_PORTS:
            ports = sorted(k[3] for k in ks)
            out.append(dict(client=client, server=server, proto=proto, ports=ports,
                            flows=sum(side[k]["flows"] for k in ks), bytes=sum(side[k]["bytes"] for k in ks),
                            max_risk=max(side[k]["max_risk"] for k in ks),
                            text=f"{client} → {server}: {len(ports)} {proto} ports"))
            continue
        for k in ks:
            c = side[k]
            out.append(dict(client=client, server=server, proto=proto, ports=[k[3]], label=c["label"],
                            flows=c["flows"], bytes=c["bytes"], max_risk=c["max_risk"], text=_conv_str(k, c["label"])))
    return sorted(out, key=lambda e: (-e["max_risk"], -e["bytes"]))


def compare(a: Snapshot, b: Snapshot) -> dict:
    d: dict = dict(before=a.path, after=b.path)

    d["summary"] = [
        ("Packets", a.packets, b.packets), ("Bytes", a.bytes, b.bytes),
        ("Duration (s)", round(a.duration, 3), round(b.duration, 3)),
        ("Bandwidth (B/s)", round(a.rate), round(b.rate)), ("Conversations", a.flows, b.flows),
        ("Hosts", len(a.hosts), len(b.hosts)), ("Alerts", sum(x["count"] for x in a.alerts.values()),
                                                 sum(x["count"] for x in b.alerts.values())),
        ("TCP retransmissions", a.retrans, b.retrans), ("Retransmission rate (%)", round(a.retrans_pct, 2),
                                                        round(b.retrans_pct, 2)),
    ]

    # conversations
    new = [k for k in b.convs if k not in a.convs]
    gone = [k for k in a.convs if k not in b.convs]
    d["new_conversations"] = _group_new(new, b.convs)
    d["missing_conversations"] = _group_new(gone, a.convs)
    changed = []
    for k in a.convs.keys() & b.convs.keys():
        x, y = a.convs[k], b.convs[k]
        notes = []
        if abs(y["bytes"] - x["bytes"]) >= MIN_BYTES and (y["bytes"] >= 2 * x["bytes"] or x["bytes"] >= 2 * y["bytes"]):
            notes.append(f"bytes {x['bytes']:,} → {y['bytes']:,}")
        if y["retrans"] > x["retrans"]:
            notes.append(f"retransmissions {x['retrans']} → {y['retrans']}")
        if x["rtts"] and y["rtts"]:
            r0, r1 = statistics.median(x["rtts"]), statistics.median(y["rtts"])
            if r1 > r0 * RTT_JUMP and r1 - r0 > 0.010:
                notes.append(f"RTT {r0 * 1000:.1f} → {r1 * 1000:.1f} ms")
        if y["max_risk"] >= x["max_risk"] + 20:
            notes.append(f"risk {x['max_risk']} → {y['max_risk']}")
        if notes:
            changed.append(dict(text=_conv_str(k, y["label"]), changes=notes, max_risk=y["max_risk"]))
    d["changed_conversations"] = sorted(changed, key=lambda c: -c["max_risk"])

    # DNS
    dns_changed, dns_new, dns_gone = [], [], []
    for k in a.dns.keys() & b.dns.keys():
        x, y = a.dns[k], b.dns[k]
        if x["answers"] and y["answers"] and x["answers"] != y["answers"]:
            dns_changed.append(dict(name=k[0], qtype=k[1], before=sorted(x["answers"]), after=sorted(y["answers"])))
        elif set(x["rcodes"]) != set(y["rcodes"]) and y["rcodes"]:
            dns_changed.append(dict(name=k[0], qtype=k[1], before=sorted(x["rcodes"]), after=sorted(y["rcodes"])))
    for k in b.dns.keys() - a.dns.keys():
        y = b.dns[k]
        dns_new.append(dict(name=k[0], qtype=k[1], answers=sorted(y["answers"]) or sorted(y["rcodes"]),
                            clients=sorted(y["clients"])))
    for k in a.dns.keys() - b.dns.keys():
        dns_gone.append(dict(name=k[0], qtype=k[1]))
    d["dns_changed"], d["dns_new"], d["dns_missing"] = dns_changed, sorted(dns_new, key=lambda r: r["name"]), \
        sorted(dns_gone, key=lambda r: r["name"])

    # alerts
    from .anomalies import SEVERITY_ORDER
    new_alerts = [dict(rule=k[0], src=k[1], dst=k[2], **v) for k, v in b.alerts.items() if k not in a.alerts]
    resolved = [dict(rule=k[0], src=k[1], dst=k[2], **v) for k, v in a.alerts.items() if k not in b.alerts]
    more = [dict(rule=k[0], src=k[1], dst=k[2], before=a.alerts[k]["count"], after=v["count"],
                 severity=v["severity"]) for k, v in b.alerts.items()
            if k in a.alerts and v["count"] > a.alerts[k]["count"]]
    by_sev = lambda r: (SEVERITY_ORDER[r["severity"]], r["rule"])
    d["new_alerts"], d["resolved_alerts"], d["increased_alerts"] = sorted(new_alerts, key=by_sev), \
        sorted(resolved, key=by_sev), sorted(more, key=by_sev)

    # TLS
    tls_changed = []
    for sni in a.tls.keys() & b.tls.keys():
        x, y = a.tls[sni], b.tls[sni]
        notes = [f"{f} {x[f]} → {y[f]}" for f in ("server", "version", "cipher", "issuer") if x[f] != y[f]]
        if x["sha256"] and y["sha256"] and x["sha256"] != y["sha256"]:
            notes.append("certificate changed")
        if notes:
            tls_changed.append(dict(sni=sni, changes=notes))
    d["tls_changed"] = tls_changed
    d["tls_new"] = [dict(sni=k, **b.tls[k]) for k in sorted(b.tls.keys() - a.tls.keys())]

    # hosts
    d["new_hosts"] = [_host_brief(b.hosts[h]) for h in b.hosts if h not in a.hosts]
    d["missing_hosts"] = [_host_brief(a.hosts[h]) for h in a.hosts if h not in b.hosts]
    port_changes = []
    for addr in a.hosts.keys() & b.hosts.keys():
        x, y = set(a.hosts[addr].open_ports), set(b.hosts[addr].open_ports)
        if x != y:
            port_changes.append(dict(host=addr, opened=sorted(y - x), closed=sorted(x - y)))
    d["port_changes"] = port_changes

    # protocol mix (share of packets, percentage points) and bandwidth per host (bytes/s)
    proto = []
    for p in set(a.protocols) | set(b.protocols):
        pa = a.protocols[p] / a.packets * 100 if a.packets else 0
        pb = b.protocols[p] / b.packets * 100 if b.packets else 0
        if abs(pb - pa) >= 2 or (p not in a.protocols) or (p not in b.protocols):
            proto.append(dict(protocol=p, before=round(pa, 1), after=round(pb, 1), delta=round(pb - pa, 1),
                              status="new" if p not in a.protocols else "gone" if p not in b.protocols else ""))
    d["protocols"] = sorted(proto, key=lambda r: -abs(r["delta"]))
    bw = []
    da, db = max(a.duration, 1e-9), max(b.duration, 1e-9)
    for h in set(a.talkers) | set(b.talkers):
        ra, rb = a.talkers[h] / da, b.talkers[h] / db
        if abs(b.talkers[h] - a.talkers[h]) >= 1000 and (rb >= 2 * ra or ra >= 2 * rb):
            bw.append(dict(host=h, before=round(ra), after=round(rb), before_bytes=a.talkers[h],
                           after_bytes=b.talkers[h]))
    d["bandwidth"] = sorted(bw, key=lambda r: -abs(r["after"] - r["before"]))[:15]

    d["headline"] = headline(d)
    return d


def _host_brief(h) -> dict:
    return dict(host=h.addr, name=h.name, roles=h.roles, open_ports=h.open_ports,
                alerts=sum(h.alerts_caused.values()))


def headline(d: dict) -> list[str]:
    """The few changes worth reading first."""
    lines = []
    high = [x for x in d["new_alerts"] if x["severity"] == "high"]
    if d["new_alerts"]:
        rules = Counter(x["rule"] for x in d["new_alerts"])
        lines.append(f"{len(d['new_alerts'])} new alert(s) ({len(high)} high): "
                     + ", ".join(f"{r}" + (f" ×{n}" if n > 1 else "") for r, n in rules.most_common(6)))
    if d["dns_changed"]:
        lines.append("DNS answers changed for " + ", ".join(x["name"] for x in d["dns_changed"][:5]))
    if d["tls_changed"]:
        lines.append("TLS changed for " + ", ".join(x["sni"] for x in d["tls_changed"][:5]))
    opened = [p for p in d["port_changes"] if p["opened"]]
    if opened:
        lines.append("Newly open ports: " + "; ".join(f"{p['host']} {', '.join(map(str, p['opened']))}"
                                                      for p in opened[:4]))
    if d["new_hosts"]:
        lines.append(f"{len(d['new_hosts'])} new host(s): " + ", ".join(h["host"] for h in d["new_hosts"][:6]))
    s = {m: (x, y) for m, x, y in d["summary"]}
    r0, r1 = s["Retransmission rate (%)"]
    if r1 > r0 + 1:
        lines.append(f"Retransmission rate rose from {r0:.1f}% to {r1:.1f}%")
    b0, b1 = s["Bandwidth (B/s)"]
    if b0 and (b1 > 2 * b0 or b1 < b0 / 2):
        lines.append(f"Average bandwidth went from {b0:,} to {b1:,} B/s")
    if not lines:
        lines.append("No significant differences.")
    return lines


def diff_files(before: str, after: str, analyze) -> dict:
    """``analyze(path)`` returns an Analyzer that has consumed the file."""
    return compare(snapshot(analyze(before), before), snapshot(analyze(after), after))
