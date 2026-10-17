"""Self-contained HTML incident report.

One file, no external assets: inline CSS, inline SVG charts and the JSON
exports embedded as download links, so it can be emailed or attached to a
ticket as-is.
"""
from __future__ import annotations

import base64
import json
import os
from collections import Counter, defaultdict
from datetime import datetime, timezone
from html import escape

from . import __version__, explain, hosts as host_profiles, timeline
from .analyzer import Analyzer
from .export import _safe, packet_dict
from .scoring import score_flows

KIND_COLOR = {"handshake": "#3aa0c8", "dns": "#b06ad6", "http": "#3fae5a", "tls": "#d6a531", "retrans": "#c9b23a",
              "reset": "#d65a5a", "close": "#8a8f98", "alert": "#e0453a"}
SEV_COLOR = {"high": "#e0453a", "medium": "#e08a2e", "low": "#c9b23a"}
RISK_COLOR = {"HIGH": "#e0453a", "MEDIUM": "#e08a2e", "LOW": "#c9b23a", "NONE": "#8a8f98"}

CSS = """
:root{--bg:#f6f7f9;--card:#fff;--text:#1d2129;--muted:#5f6670;--line:#e3e6ea;--accent:#2f7fc1;--chip:#eef1f4}
@media (prefers-color-scheme:dark){:root{--bg:#121417;--card:#1b1e23;--text:#e6e8eb;--muted:#9aa2ad;--line:#2b3037;
--accent:#5aa9e6;--chip:#252a31}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);
font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
header{padding:28px 32px 12px;max-width:1240px;margin:auto}h1{margin:0 0 4px;font-size:24px}
.sub{color:var(--muted)}nav{max-width:1240px;margin:auto;padding:0 32px 8px;display:flex;flex-wrap:wrap;gap:6px}
nav a{color:var(--muted);text-decoration:none;padding:3px 10px;border-radius:99px;background:var(--chip);font-size:13px}
nav a:hover{color:var(--text)}main{max-width:1240px;margin:auto;padding:8px 32px 48px}
section{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:18px 22px;margin:16px 0}
h2{font-size:17px;margin:0 0 12px}h3{font-size:15px;margin:0}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:10px;margin-bottom:16px}
.kpi{background:var(--chip);border-radius:8px;padding:10px 14px}.kpi b{display:block;font-size:22px}
.kpi span{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.04em}
.verdict{font-size:16px;font-weight:600;margin:4px 0 8px}ul{margin:6px 0 0;padding-left:20px}li{margin:3px 0}
table{width:100%;border-collapse:collapse;font-size:13px}th{text-align:left;color:var(--muted);font-weight:600;
border-bottom:1px solid var(--line);padding:6px 8px;white-space:nowrap}td{border-bottom:1px solid var(--line);
padding:6px 8px;vertical-align:top;overflow-wrap:break-word}tr:last-child td{border-bottom:0}td.num{text-align:right;white-space:nowrap}
code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12.5px}
.badge{display:inline-block;padding:1px 8px;border-radius:99px;font-size:12px;font-weight:600;color:#fff;
white-space:nowrap}.chip{display:inline-block;background:var(--chip);border-radius:4px;padding:0 6px;margin:1px 2px 1px 0;
font-size:12px}.muted{color:var(--muted)}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(340px,100%),1fr));gap:12px}
.card{min-width:0;overflow-wrap:anywhere;border:1px solid var(--line);border-left:4px solid var(--c);border-radius:8px;padding:12px 14px}
.card p{margin:6px 0}.card .lbl{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.04em}
.bar{height:10px;border-radius:3px;background:var(--accent);display:inline-block;vertical-align:middle}
.meter{display:inline-block;width:80px;height:8px;background:var(--chip);border-radius:4px;overflow:hidden;
vertical-align:middle;margin-right:6px}.meter i{display:block;height:100%}
details summary{cursor:pointer;color:var(--accent);margin:8px 0}svg text{fill:var(--muted);font-size:11px}
.two{display:grid;grid-template-columns:1fr 1fr;gap:20px}@media (max-width:900px){.two{grid-template-columns:1fr}}
a.dl{display:inline-block;margin:4px 8px 4px 0;padding:6px 12px;border-radius:6px;background:var(--chip);
color:var(--text);text-decoration:none}a.dl:hover{background:var(--line)}
td.wrap{overflow-wrap:anywhere;min-width:120px}
footer{color:var(--muted);text-align:center;font-size:12px;padding-bottom:24px}
"""


def _e(x) -> str:
    return escape(str(x)) if x is not None else ""


def _ts(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} GB"


def _badge(text: str, color: str) -> str:
    return f'<span class="badge" style="background:{color}">{_e(text)}</span>'


def _ep(addr: tuple) -> str:
    return f"{addr[0]}:{addr[1]}" if addr[1] else addr[0]


def _data_link(name: str, obj) -> str:
    payload = base64.b64encode(json.dumps(obj, indent=2, default=str).encode()).decode()
    return f'<a class="dl" download="{name}" href="data:application/json;base64,{payload}">⬇ {name}</a>'


# -- analysis helpers -------------------------------------------------------------
def suspicious_hosts(an: Analyzer) -> list[dict]:
    hosts: dict[str, dict] = defaultdict(lambda: dict(alerts=Counter(), rules=set(), max_risk=0, flows=set(),
                                                      as_target=Counter()))
    for a in an.alerts:
        if a.src and a.src not in ("many",):
            h = hosts[a.src]
            h["alerts"][a.severity] += 1
            h["rules"].add(a.rule)
            if a.flow is not None:
                h["flows"].add(a.flow)
        if a.dst and a.dst not in ("many",) and "hosts" not in a.dst:
            hosts[a.dst]["as_target"][a.severity] += 1
    for f in an.flows:
        if f.risk and f.risk.score:
            for ip in (f.client[0], f.server[0]):
                if ip in hosts:
                    hosts[ip]["max_risk"] = max(hosts[ip]["max_risk"], f.risk.score)
    out = []
    for ip, h in hosts.items():
        score = h["alerts"]["high"] * 10 + h["alerts"]["medium"] * 4 + h["alerts"]["low"] + h["max_risk"] / 10
        if not h["alerts"] and not h["as_target"]:
            continue
        out.append(dict(ip=ip, high=h["alerts"]["high"], medium=h["alerts"]["medium"], low=h["alerts"]["low"],
                        targeted=sum(h["as_target"].values()), rules=sorted(h["rules"]), max_risk=h["max_risk"],
                        flows=sorted(h["flows"]), weight=score))
    return sorted(out, key=lambda h: (-h["weight"], -h["targeted"]))


def executive_summary(an: Analyzer, groups: list[dict], hosts: list[dict], risky: list) -> tuple[str, list[str]]:
    sev = Counter(a.severity for a in an.alerts)
    if sev["high"]:
        verdict = f"⚠ High-severity activity detected: {sev['high']} high, {sev['medium']} medium and {sev['low']} low alerts."
    elif sev["medium"]:
        verdict = f"Suspicious activity detected: {sev['medium']} medium and {sev['low']} low alerts."
    elif sev["low"]:
        verdict = f"Minor findings only: {sev['low']} low-severity alerts."
    else:
        verdict = "✓ No suspicious activity detected in this capture."
    points = []
    for g in groups[:6]:
        src = ", ".join(g["sources"][:2]) + (f" +{len(g['sources']) - 2}" if len(g["sources"]) > 2 else "")
        tgt = ", ".join(t for t in g["targets"][:2] if t)
        line = f"<b>{_e(g['title'])}</b> from {_e(src)}"
        if tgt and tgt != src:
            line += f" against {_e(tgt)}"
        line += f" ({g['count']}×)" if g["count"] > 1 else ""
        points.append(line + f" {_badge(g['severity'], SEV_COLOR[g['severity']])}")
    attackers = [h for h in hosts if h["high"]]
    if attackers:
        points.append("Most active suspicious host" + ("s: " if len(attackers) > 1 else ": ")
                      + ", ".join(f"<code>{_e(h['ip'])}</code> ({h['high']} high)" for h in attackers[:3]))
    for f in risky[:3]:
        if f.risk.score >= 70:
            points.append(f"Riskiest conversation: flow {f.id} <code>{_e(_ep(f.client))} → {_e(_ep(f.server))}</code> "
                          f"scored {f.risk.score}/100 ({_e(f.risk.reasons[0].rsplit(' (+', 1)[0])})")
            break
    tls_bad = [f for f in an.flows if f.tls.get("certs") and any(a.flow == f.id and a.rule.startswith("tls-")
                                                                 for a in an.alerts)]
    if tls_bad:
        points.append(f"{len(tls_bad)} TLS session(s) presented a problematic certificate: "
                      + ", ".join(_e(f.tls_sni or f.server[0]) for f in tls_bad[:3]))
    return verdict, points


# -- charts ---------------------------------------------------------------------
def timeline_svg(events: list, t0: float, t1: float, width: int = 1100) -> str:
    kinds = [k for k in timeline.KINDS if any(e.kind == k for e in events)]
    if not kinds:
        return '<p class="muted">No events.</p>'
    left, right, lane_h, top = 90, 20, 26, 24
    h = top + lane_h * len(kinds) + 24
    span = max(t1 - t0, 1e-6)
    plot_w = width - left - right
    parts = [f'<svg viewBox="0 0 {width} {h}" width="100%" role="img" aria-label="Event timeline">']
    for i, k in enumerate(kinds):
        y = top + i * lane_h
        parts.append(f'<rect x="{left}" y="{y + 2}" width="{plot_w}" height="{lane_h - 4}" rx="4" '
                     f'fill="{KIND_COLOR[k]}" opacity="0.07"/>')
        parts.append(f'<text x="{left - 8}" y="{y + lane_h / 2 + 4}" text-anchor="end">{k}</text>')
    for j in range(6):
        x = left + plot_w * j / 5
        parts.append(f'<line x1="{x}" x2="{x}" y1="{top - 4}" y2="{h - 20}" stroke="currentColor" opacity="0.12"/>')
        parts.append(f'<text x="{x}" y="{h - 6}" text-anchor="middle">{span * j / 5:.2f}s</text>')
    for e in events:
        i = kinds.index(e.kind)
        x = left + (e.ts - t0) / span * plot_w
        y = top + i * lane_h + lane_h / 2
        r = 4 + min(6, e.count - 1) if e.count > 1 else 4
        tip = _e(f"{e.ts - t0:.3f}s {e.title} {e.detail}")
        parts.append(f'<circle cx="{x:.1f}" cy="{y}" r="{r}" fill="{KIND_COLOR[e.kind]}" opacity="0.85">'
                     f'<title>{tip}</title></circle>')
    parts.append("</svg>")
    return "".join(parts)


def bars(rows: list[tuple[str, float, str]], color: str = "var(--accent)") -> str:
    if not rows:
        return '<p class="muted">Nothing to show.</p>'
    peak = max(v for _, v, _ in rows) or 1
    out = ["<table>"]
    for label, value, text in rows:
        out.append(f'<tr><td class="mono">{_e(label)}</td><td style="width:55%"><span class="bar" '
                   f'style="width:{max(1, value / peak * 100):.1f}%;background:{color}"></span></td>'
                   f'<td class="num">{_e(text)}</td></tr>')
    out.append("</table>")
    return "".join(out)


# -- the report -------------------------------------------------------------------
def build_report(an: Analyzer, source: str) -> str:
    risky = score_flows(an)
    groups = explain.group(an.alerts)
    hosts = suspicious_hosts(an)
    events = timeline.build(an)
    t0, t1 = an.first_ts or 0.0, an.last_ts or 0.0
    sev = Counter(a.severity for a in an.alerts)
    verdict, points = executive_summary(an, groups, hosts, risky)
    tcp = [f for f in an.flows if f.proto == "tcp"]
    complete = sum(1 for f in tcp if "ack" in f.handshake)

    sections = []
    nav = []

    def section(anchor: str, title: str, body: str) -> None:
        nav.append(f'<a href="#{anchor}">{_e(title)}</a>')
        sections.append(f'<section id="{anchor}"><h2>{_e(title)}</h2>{body}</section>')

    top_risk = risky[0].risk if risky else None
    kpis = [("Packets", f"{an.count:,}"), ("Data", _bytes(an.bytes)), ("Duration", f"{t1 - t0:.2f}s"),
            ("Conversations", str(len(an.flows))), ("TCP handshakes", f"{complete}/{len(tcp)}"),
            ("Hosts", str(len(an.talkers)))]
    kpi_html = "".join(f'<div class="kpi"><b>{_e(v)}</b><span>{_e(k)}</span></div>' for k, v in kpis)
    alert_kpi = (f'<div class="kpi"><b><span style="color:{SEV_COLOR["high"]}">{sev["high"]}</span> / '
                 f'<span style="color:{SEV_COLOR["medium"]}">{sev["medium"]}</span> / '
                 f'<span style="color:{SEV_COLOR["low"]}">{sev["low"]}</span></b><span>Alerts high / med / low</span></div>')
    risk_kpi = (f'<div class="kpi"><b style="color:{RISK_COLOR[top_risk.level]}">{top_risk.score}/100</b>'
                f'<span>Highest flow risk</span></div>') if top_risk else ""
    summary = (f'<div class="kpis">{kpi_html}{alert_kpi}{risk_kpi}</div><div class="verdict">{_e(verdict)}</div>'
               + ("<ul>" + "".join(f"<li>{p}</li>" for p in points) + "</ul>" if points else ""))
    section("summary", "Executive summary", summary)

    rows = []
    for e in events[:400]:
        lat = f"{e.duration * 1000:.1f} ms" if e.duration is not None else ""
        color = SEV_COLOR["high"] if e.level == "bad" else SEV_COLOR["medium"] if e.level == "warn" else "inherit"
        rows.append(f'<tr><td class="num mono">{e.ts - t0:.4f}</td><td>{_badge(e.kind, KIND_COLOR[e.kind])}</td>'
                    f'<td style="color:{color}">{_e(e.title)}</td><td class="muted">{_e(e.detail)}</td>'
                    f'<td class="num">{lat}</td><td class="num">{_e(e.flow if e.flow is not None else "")}</td></tr>')
    more = f'<p class="muted">Showing 400 of {len(events)} events.</p>' if len(events) > 400 else ""
    section("timeline", "Timeline",
            timeline_svg(events, t0, t1) + f"<details open><summary>{len(events)} events</summary><table><tr>"
            "<th>Time (s)</th><th>Kind</th><th>Event</th><th>Detail</th><th>Latency</th><th>Flow</th></tr>"
            + "".join(rows) + "</table>" + more + "</details>")

    if groups:
        cards = []
        for g in groups:
            flows = ", ".join(f"#{x}" for x in g["flows"][:12]) + (" …" if len(g["flows"]) > 12 else "")
            examples = "".join(f"<li>{_e(x)}</li>" for x in g["examples"])
            cards.append(
                f'<div class="card" style="--c:{SEV_COLOR[g["severity"]]}"><h3>{_e(g["title"])} '
                f'{_badge(g["severity"], SEV_COLOR[g["severity"]])} <span class="muted">×{g["count"]}</span></h3>'
                f'<p><span class="lbl">Why it matters</span><br>{_e(g["why"])}</p>'
                f'<p><span class="lbl">Recommended action</span><br>{_e(g["action"])}</p>'
                f'<p><span class="lbl">Source</span> {" ".join(f"<span class=chip>{_e(s)}</span>" for s in g["sources"][:6])}'
                f' <span class="lbl">Target</span> {" ".join(f"<span class=chip>{_e(t)}</span>" for t in g["targets"][:6] if t)}</p>'
                + (f'<p><span class="lbl">Related flows</span> {flows}</p>' if flows else "")
                + f'<ul class="muted">{examples}</ul></div>')
        section("alerts", f"Alerts explained ({len(an.alerts)})", f'<div class="cards">{"".join(cards)}</div>')
    else:
        section("alerts", "Alerts explained", '<p class="muted">No alerts were raised.</p>')

    if hosts:
        rows = []
        for h in hosts[:30]:
            rules = " ".join(f"<span class=chip>{_e(r)}</span>" for r in h["rules"][:8])
            rows.append(f'<tr><td class="mono">{_e(h["ip"])}</td><td class="num" style="color:{SEV_COLOR["high"]}">'
                        f'{h["high"] or ""}</td><td class="num" style="color:{SEV_COLOR["medium"]}">{h["medium"] or ""}</td>'
                        f'<td class="num">{h["low"] or ""}</td><td class="num">{h["targeted"] or ""}</td>'
                        f'<td class="num">{h["max_risk"] or ""}</td><td>{rules}</td></tr>')
        section("hosts", "Suspicious hosts",
                "<table><tr><th>Host</th><th>High</th><th>Med</th><th>Low</th><th>Targeted by</th><th>Max flow risk</th>"
                "<th>Triggered rules</th></tr>" + "".join(rows) + "</table>"
                '<p class="muted">Alert counts are for alerts this host <i>caused</i>; "targeted by" counts alerts '
                "where it was the victim.</p>")

    profiles = host_profiles.profile(an)
    shown = [h for h in profiles if h.local or h.alerts_caused or h.services or h.max_risk][:40]
    if shown:
        rows = []
        for h in shown:
            ident = f'<span class="mono">{_e(h.addr)}</span>'
            if h.name:
                ident += f'<br>{_e(h.name)}'
            if h.mac and not h.routed:
                ident += f'<br><span class="mono muted">{_e(h.mac)}</span>'
            roles = " ".join(f'<span class="chip" style="{"color:" + SEV_COLOR["high"] if r == "scanner" else ""}">'
                             f'{_e(r)}</span>' for r in h.roles)
            ports = ", ".join(f'{_e(k.split("/")[0])}' + ("" if v["label"].startswith("port ") else
                                                          f' <span class="muted">{_e(v["label"])}</span>')
                              for k, v in sorted(h.services.items(), key=lambda kv: int(kv[0].split("/")[0]))[:8])
            lookups = "<br>".join(_e(d) for d, _ in h.domains.most_common(5))
            if len(h.domains) > 5:
                lookups += f'<br><span class="muted">+{len(h.domains) - 5} more</span>'
            extra = []
            if h.sni:
                extra.append("TLS: " + ", ".join(h.sni))
            if h.user_agents:
                extra.append("UA: " + ", ".join(h.user_agents))
            alerts = " ".join(f'<span class="badge" style="background:{SEV_COLOR[sev]}">{h.alerts_caused[sev]}</span>'
                              for sev in ("high", "medium", "low") if h.alerts_caused[sev])
            rows.append(f'<tr><td>{ident}</td><td>{_e(h.os)}</td><td>{roles}</td><td>{ports}</td>'
                        f'<td class="mono wrap">{lookups}</td><td class="muted wrap">{_e("; ".join(extra))}</td>'
                        f'<td class="num">{_bytes(h.bytes_sent)}<br><span class="muted">{_bytes(h.bytes_recv)}</span></td>'
                        f'<td>{alerts}</td></tr>')
        section("profiles", f"Host profiles ({len(shown)})",
                "<table><tr><th>Host</th><th>OS guess</th><th>Role</th><th>Open ports</th><th>DNS lookups</th>"
                "<th>TLS / HTTP clients</th><th>Sent / recv</th><th>Alerts</th></tr>" + "".join(rows) + "</table>"
                '<p class="muted">OS guesses come from the initial TTL and the TCP SYN window and options, and are '
                "approximate. Hosts behind a router show no MAC because their frames carry the router's.</p>")

    talkers = [(ip, b, _bytes(b)) for ip, b in an.talkers.most_common(12)]
    names = {"ethernet": "Ethernet", "ipv4": "IPv4", "ipv6": "IPv6", "arp": "ARP", "tcp": "TCP", "udp": "UDP",
             "icmp": "ICMP", "icmpv6": "ICMPv6", "dns": "DNS", "http": "HTTP", "tls": "TLS", "dhcp": "DHCP",
             "mdns": "mDNS", "vlan": "VLAN", "igmp": "IGMP"}
    protos = [(names.get(k, k), v, f"{v} pkts · {v / max(an.count, 1) * 100:.1f}%")
              for k, v in an.protocols.most_common() if k in names]
    section("traffic", "Top talkers & protocols",
            f'<div class="two"><div><h3>Bytes sent per host</h3>{bars(talkers)}</div>'
            f'<div><h3>Protocols</h3>{bars(protos, "#8a6fd1")}</div></div>')

    def flow_row(f) -> str:
        r = f.risk
        reasons = "; ".join(x.rsplit(" (+", 1)[0] for x in r.reasons[:4])
        return (f'<tr><td class="num">{f.id}</td><td class="mono">{_e(_ep(f.client))}</td>'
                f'<td class="mono">{_e(_ep(f.server))}</td><td>{_e(f.label)}</td><td>{_e(f.state)}</td>'
                f'<td class="num">{f.packets}</td><td class="num">{_bytes(f.bytes)}</td>'
                f'<td class="num">{f"{f.rtt * 1000:.1f} ms" if f.rtt is not None else ""}</td>'
                f'<td class="num" style="text-align:left"><span class="meter"><i style="width:{r.score}%;background:{RISK_COLOR[r.level]}"></i></span>'
                f'<b style="color:{RISK_COLOR[r.level]}">{r.score}</b></td><td class="muted">{_e(reasons)}</td></tr>')
    head = ("<tr><th>#</th><th>Client</th><th>Server</th><th>App</th><th>State</th><th>Pkts</th><th>Bytes</th>"
            "<th>RTT</th><th>Risk</th><th>Why</th></tr>")
    flagged = [f for f in risky if f.risk.score > 0]
    section("flows", "Conversations",
            "<h3>Highest risk</h3><table>" + head + "".join(flow_row(f) for f in flagged[:15]) + "</table>"
            + (f"<details><summary>All {len(an.flows)} conversations</summary><table>" + head
               + "".join(flow_row(f) for f in sorted(an.flows, key=lambda f: f.id)[:2000]) + "</table></details>"))

    dns_rows = []
    for f in an.flows:
        q = {}
        for d in f.dns:
            if not d["response"]:
                q[d["id"]] = d
                continue
            ans = ", ".join(map(str, d["answers"][:4])) or d["rcode"]
            lat = (d["ts"] - q[d["id"]]["ts"]) * 1000 if d["id"] in q else None
            dns_rows.append(f'<tr><td class="num mono">{d["ts"] - t0:.3f}</td><td class="mono">{_e(f.client[0])}</td>'
                            f'<td class="mono" style="word-break:break-all">{_e(d["qname"])}</td><td>{_e(d["qtype"])}</td>'
                            f'<td class="mono" style="{"color:" + SEV_COLOR["high"] if d["rcode"] != "NOERROR" else ""}">'
                            f'{_e(ans)}</td><td class="num">{f"{lat:.1f} ms" if lat is not None else ""}</td></tr>')
    http_rows = []
    for f in an.flows:
        for tx in f.http:
            req, resp = tx.get("request") or {}, tx.get("response") or {}
            st = resp.get("status")
            color = SEV_COLOR["high"] if st and st >= 400 else "inherit"
            lat = f"{(resp['ts'] - req['ts']) * 1000:.1f} ms" if req and resp else ""
            http_rows.append(f'<tr><td class="num">{f.id}</td><td>{_e(req.get("method", ""))}</td>'
                             f'<td class="mono">{_e(req.get("host", ""))}</td><td class="mono" style="word-break:break-all">'
                             f'{_e(req.get("uri", ""))}</td><td style="color:{color}">{_e(st or "—")}</td>'
                             f'<td>{_e(resp.get("content_type", ""))}</td><td class="num">'
                             f'{_bytes(resp.get("body_len", 0)) if resp else ""}</td><td class="num">{lat}</td>'
                             f'<td class="muted">{_e(req.get("user_agent", ""))}</td></tr>')
    section("dns", f"DNS activity ({len(dns_rows)} answers)",
            "<table><tr><th>Time (s)</th><th>Client</th><th>Query</th><th>Type</th><th>Answer</th><th>Latency</th></tr>"
            + "".join(dns_rows) + "</table>" if dns_rows else '<p class="muted">No DNS traffic.</p>')
    section("http", f"HTTP activity ({len(http_rows)} requests)",
            "<table><tr><th>Flow</th><th>Method</th><th>Host</th><th>URI</th><th>Status</th><th>Type</th><th>Size</th>"
            "<th>Time</th><th>User-Agent</th></tr>" + "".join(http_rows) + "</table>"
            if http_rows else '<p class="muted">No cleartext HTTP traffic.</p>')

    tls_rows = []
    for f in an.flows:
        if not (f.tls or f.tls_sni):
            continue
        certs = f.tls.get("certs") or []
        leaf = certs[0] if certs and "error" not in certs[0] else None
        cert = (f'{_e(leaf["subject_cn"] or leaf["subject"])}<br><span class="muted">by '
                f'{_e(leaf["issuer_cn"] or leaf["issuer"])}</span>') if leaf else (
            '<span class="muted">encrypted (TLS 1.3)</span>' if f.tls.get("version") == "TLS 1.3" else "—")
        rules = [a.rule for a in an.alerts if a.flow == f.id and a.rule.startswith("tls-")]
        finding = " ".join(_badge(r.replace("tls-", ""), SEV_COLOR["high"]) for r in rules) or _badge("ok", "#3fae5a")
        tls_rows.append(f'<tr><td class="num">{f.id}</td><td class="mono">{_e(_ep(f.server))}</td>'
                        f'<td>{_e(f.tls_sni or "")}</td><td>{_e(f.tls.get("version", ""))}</td>'
                        f'<td class="mono">{_e(f.tls.get("cipher", ""))}</td><td>{cert}</td>'
                        f'<td class="num">{_e(datetime.fromtimestamp(leaf["not_after"], timezone.utc).date()) if leaf else ""}</td>'
                        f'<td>{finding}</td></tr>')
    if tls_rows:
        section("tls", f"TLS sessions ({len(tls_rows)})",
                "<table><tr><th>Flow</th><th>Server</th><th>SNI</th><th>Version</th><th>Cipher</th><th>Certificate</th>"
                "<th>Expires</th><th>Findings</th></tr>" + "".join(tls_rows) + "</table>")

    exports = [
        _data_link("alerts.json", [a.to_dict() for a in an.alerts]),
        _data_link("flows.json", [_safe(f.to_dict()) for f in an.flows]),
        _data_link("timeline.json", [e.to_dict(t0) for e in events]),
        _data_link("hosts.json", [h.to_dict() for h in profiles]),
    ]
    if an.keep_packets and len(an.packets) <= 20000:
        exports.append(_data_link("packets.json", [packet_dict(p) for p in an.packets]))
    section("exports", "Exports", "<p>Data behind this report, embedded in the file:</p>" + "".join(exports))

    window = f"{_ts(t0)} → {_ts(t1)}" if an.first_ts else "empty capture"
    return (f'<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" '
            f'content="width=device-width,initial-scale=1"><title>Incident report · {_e(source)}</title>'
            f'<style>{CSS}</style></head><body><header><h1>Incident report · {_e(source)}</h1>'
            f'<div class="sub">{_e(window)} · generated {_ts(datetime.now(timezone.utc).timestamp())} '
            f'by pktanalyzer {__version__}</div></header><nav>{"".join(nav)}</nav><main>{"".join(sections)}</main>'
            f'<footer>Generated offline by pktanalyzer. Only analyse traffic you are authorised to capture.</footer>'
            f'</body></html>')


def write_report(an: Analyzer, source: str, path: str) -> str:
    html = build_report(an, source)
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    return path
