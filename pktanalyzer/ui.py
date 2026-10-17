"""Everything drawn on the terminal, built with ``rich``."""
from __future__ import annotations

import os
import time
from collections import Counter, deque
from datetime import datetime, timezone

from rich import box
from rich.console import Console, Group
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from . import timeline as TL
from .analyzer import Analyzer, info
from .anomalies import SEVERITY_ORDER, Alert
from .flows import Flow
from .packet import Packet
from .scoring import level_for

PROTO_STYLE = {
    "TCP": "cyan", "UDP": "dodger_blue1", "DNS": "magenta", "MDNS": "magenta", "HTTP": "green3",
    "TLS": "gold1", "ICMP": "orange1", "ICMPv6": "orange1", "ARP": "grey70", "IPv4": "steel_blue",
    "IPv6": "steel_blue", "DHCP": "plum2", "IGMP": "grey58",
}
LAYER_STYLE = {
    "ethernet": "grey62", "sll": "grey62", "loopback": "grey62", "vlan": "grey50", "arp": "grey70",
    "ipv4": "steel_blue1", "ipv6": "steel_blue1", "tcp": "cyan", "udp": "dodger_blue1",
    "icmp": "orange1", "icmpv6": "orange1", "igmp": "grey58", "dns": "magenta", "mdns": "magenta",
    "http": "green3", "tls": "gold1", "dhcp": "plum2",
}
RISK_STYLE = {"HIGH": "bold red", "MEDIUM": "dark_orange", "LOW": "yellow3", "NONE": "grey50"}
SEV_STYLE = {"high": "bold red", "medium": "dark_orange", "low": "yellow3"}
SEV_ICON = {"high": "●", "medium": "▲", "low": "◆"}
STATE_STYLE = {"ESTABLISHED": "green3", "CLOSED": "grey58", "FIN_WAIT": "yellow3", "CLOSING": "yellow3",
               "SYN_SENT": "cyan", "SYN_RECEIVED": "cyan", "RESET": "red", "REFUSED": "red3",
               "ACTIVE": "dodger_blue1", "NEW": "white"}
LAYER_TITLES = {
    "ethernet": "Ethernet II", "vlan": "802.1Q VLAN", "sll": "Linux cooked capture", "loopback": "Loopback",
    "arp": "Address Resolution Protocol", "ipv4": "Internet Protocol Version 4",
    "ipv6": "Internet Protocol Version 6", "tcp": "Transmission Control Protocol",
    "udp": "User Datagram Protocol", "icmp": "Internet Control Message Protocol", "icmpv6": "ICMPv6",
    "dns": "Domain Name System", "mdns": "Multicast DNS", "http": "Hypertext Transfer Protocol",
    "tls": "Transport Layer Security", "dhcp": "DHCP", "igmp": "IGMP",
}

console = Console(highlight=False)


def human_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} GB"


def fmt_time(ts: float, t0: float | None, absolute: bool = False) -> str:
    if absolute or t0 is None:
        return datetime.fromtimestamp(ts).strftime("%H:%M:%S.%f")
    return f"{ts - t0:.6f}"


def _cell(text: str, width: int) -> str:
    return text[: width - 1] + "…" if len(text) > width else text.ljust(width)


# -- packet list --------------------------------------------------------------
class PacketPrinter:
    """Streams one coloured line per packet, like tshark, with a header row."""

    def __init__(self, con: Console | None = None, absolute_time: bool = False):
        self.con = con or console
        self.t0: float | None = None
        self.absolute = absolute_time
        self._header_done = False

    def widths(self) -> tuple[int, int, int]:
        w = self.con.width
        addr = 22 if w >= 120 else 17 if w >= 100 else 15
        return 6, addr, max(20, w - (6 + 1 + 11 + 1 + addr * 2 + 2 + 7 + 6 + 2) - 1)

    def header(self) -> None:
        num, addr, inf = self.widths()
        t = Text(no_wrap=True, overflow="ellipsis")
        t.append(f"{'No.':>{num}} {'Time':<11} {'Source':<{addr}} {'Destination':<{addr}} {'Proto':<7}"
                 f"{'Len':>6}  Info", style="bold reverse")
        self.con.print(t)
        self._header_done = True

    def print(self, pkt: Packet) -> None:
        if not self._header_done:
            self.header()
        if self.t0 is None:
            self.t0 = pkt.ts
        self.con.print(packet_line(pkt, self.t0, self.widths(), self.absolute), no_wrap=True,
                       overflow="ellipsis", crop=True)
        for a in pkt.alerts:
            self.con.print(Text.assemble(("        ", ""), (f"{SEV_ICON[a.severity]} ", SEV_STYLE[a.severity]),
                                         (a.message, SEV_STYLE[a.severity])), no_wrap=True, crop=True)


def packet_line(pkt: Packet, t0: float | None, widths: tuple[int, int, int], absolute: bool = False) -> Text:
    num, addr, inf = widths
    proto = pkt.protocol
    style = PROTO_STYLE.get(proto, "white")
    tcp = pkt.layer("tcp")
    if tcp is not None and proto == "TCP":
        if tcp["flags.rst"]:
            style = "red3"
        elif tcp["flags.syn"] or tcp["flags.fin"]:
            style = "grey74"
    src, dst = pkt.src, pkt.dst
    if pkt.sport is not None and len(src) + len(str(pkt.sport)) < addr:
        src = f"{src}:{pkt.sport}" if ":" not in src else src
        dst = f"{dst}:{pkt.dport}" if ":" not in dst else dst
    t = Text(no_wrap=True, overflow="ellipsis")
    t.append(f"{pkt.number:>{num}} ", style="grey50")
    t.append(f"{fmt_time(pkt.ts, t0, absolute)[:11]:<11} ", style="grey50")
    t.append(_cell(src, addr) + " ", style="bold " + style if pkt.direction == "c2s" else style)
    t.append(_cell(dst, addr) + " ", style=style)
    t.append(f"{proto:<7}", style="bold " + style)
    t.append(f"{pkt.orig_len:>6}  ", style="grey62")
    t.append(_cell(info(pkt), inf), style=style)
    if pkt.warnings:
        t.append("  ⚠ " + "; ".join(pkt.warnings), style="bold red")
    return t


# -- packet details -----------------------------------------------------------
def _fmt_value(key: str, v) -> str:
    if isinstance(v, bool):
        return "Set" if v else "Not set"
    if isinstance(v, int) and key in ("checksum", "type", "flags", "id", "tos") and key != "id":
        return f"0x{v:04x}" if key == "checksum" else f"0x{v:02x} ({v})"
    if isinstance(v, int) and key == "id":
        return f"0x{v:04x} ({v})"
    if isinstance(v, dict):
        return ", ".join(f"{k}={x}" for k, x in v.items()) or "none"
    if isinstance(v, list):
        return ", ".join(str(x) for x in v) or "none"
    return str(v)


HIDDEN_FIELDS = {"headers", "questions", "answers", "authority", "additional", "answer_data", "first_line",
                 "options", "flags_str"}
HIDDEN_BY_LAYER = {"ethernet": {"type"}, "vlan": {"type"}, "ipv4": {"proto"}, "ipv6": {"proto", "next_header", "ttl"},
                   "tcp": {"flags"}, "dns": {"rcode"}}


def layer_tree(pkt: Packet) -> Tree:
    title = Text.assemble((f"Frame {pkt.number}: ", "bold"),
                          f"{pkt.orig_len} bytes on wire, {len(pkt.data)} captured",
                          ("  " + datetime.fromtimestamp(pkt.ts).isoformat(" "), "grey50"))
    root = Tree(title, guide_style="grey35")
    for layer in pkt.layers:
        style = LAYER_STYLE.get(layer.name, "white")
        head = Text(LAYER_TITLES.get(layer.name, layer.name.upper()), style="bold " + style)
        f = layer.fields
        if layer.name in ("ipv4", "ipv6"):
            head.append(f", Src: {f['src']}, Dst: {f['dst']}", style=style)
        elif layer.name in ("tcp", "udp"):
            head.append(f", Src Port: {f['sport']}, Dst Port: {f['dport']}", style=style)
            if layer.name == "tcp":
                head.append(f", Flags: [{f['flag_names']}]", style=style)
        elif layer.name == "ethernet":
            head.append(f", Src: {f['src']}, Dst: {f['dst']}", style=style)
        if layer.offset is not None:
            head.append(f"   [{layer.offset}:{layer.offset + (layer.length or 0)}]", style="grey42")
        node = root.add(head)
        for k, v in f.items():
            if k in HIDDEN_FIELDS or k.startswith("flags.") or k in HIDDEN_BY_LAYER.get(layer.name, ()):
                continue
            if k.endswith("checksum_ok"):
                if v is None:
                    continue
                node.add(Text.assemble(("checksum status: ", "grey62"),
                                       ("correct" if v else "INCORRECT", "green3" if v else "bold red")))
                continue
            node.add(Text.assemble((f"{k}: ", "grey62"), (_fmt_value(k, v), "white")))
        if layer.name == "tcp" and f.get("options"):
            node.add(Text.assemble(("options: ", "grey62"), _fmt_value("options", f["options"])))
        if layer.name in ("http",) and f.get("headers"):
            hn = node.add(Text("headers", style="grey62"))
            for hk, hv in f["headers"].items():
                hn.add(Text.assemble((f"{hk}: ", "green3"), hv))
        if layer.name in ("dns", "mdns"):
            for sec in ("questions", "answers", "authority", "additional"):
                if f.get(sec):
                    sn = node.add(Text(f"{sec} ({len(f[sec])})", style="grey62"))
                    for rr in f[sec]:
                        if sec == "questions":
                            sn.add(f"{rr['name']}  {rr['type']}")
                        else:
                            sn.add(Text.assemble(rr["name"], "  ", (rr["type"], "magenta"),
                                                 f"  ttl={rr['ttl']}  ", (str(rr["data"]), "bold")))
    if pkt.payload:
        root.add(Text(f"Payload: {len(pkt.payload)} bytes", style="bold white"))
    if pkt.note:
        root.add(Text(f"[{pkt.note}]", style="yellow3"))
    for w in pkt.warnings:
        root.add(Text(f"⚠ {w}", style="bold red"))
    for a in pkt.alerts:
        root.add(Text(f"{SEV_ICON[a.severity]} {a.rule}: {a.message}", style=SEV_STYLE[a.severity]))
    return root


def hexdump(pkt: Packet, limit: int = 512) -> Text:
    """Hex + ASCII dump with each byte coloured by the header it belongs to."""
    data = pkt.data[:limit]
    owner = ["grey85"] * len(data)  # bytes no header claims are payload
    for layer in pkt.layers:
        if layer.offset is None:
            continue
        end = layer.offset + (layer.length or 0)
        for i in range(layer.offset, min(end, len(data))):
            owner[i] = LAYER_STYLE.get(layer.name, "white")
    out = Text()
    for row in range(0, len(data), 16):
        out.append(f"{row:04x}  ", style="grey42")
        for i in range(row, row + 16):
            if i < len(data):
                out.append(f"{data[i]:02x}", style=owner[i])
                out.append(" " if i != row + 7 else "  ")
            else:
                out.append("   " if i != row + 7 else "    ")
        out.append(" ")
        for i in range(row, min(row + 16, len(data))):
            c = data[i]
            out.append(chr(c) if 32 <= c < 127 else "·", style=owner[i] if 32 <= c < 127 else "grey35")
        out.append("\n")
    if len(pkt.data) > limit:
        out.append(f"… {len(pkt.data) - limit} more bytes\n", style="grey50")
    legend = Text("  ")
    seen = []
    for layer in pkt.layers:
        if layer.offset is not None and layer.name not in seen:
            seen.append(layer.name)
            legend.append("■ ", style=LAYER_STYLE.get(layer.name, "white"))
            legend.append(layer.name + "  ", style="grey62")
    if pkt.payload_offset is not None and pkt.payload:
        legend.append("■ ", style="grey85")
        legend.append("payload", style="grey62")
    out.append_text(legend)
    return out


def packet_detail(pkt: Packet, show_hex: bool = True) -> Panel:
    parts = [layer_tree(pkt)]
    if show_hex:
        parts += [Text(""), hexdump(pkt)]
    proto = pkt.protocol
    return Panel(Group(*parts), title=f"[bold]#{pkt.number}[/] {proto}", title_align="left",
                 border_style=PROTO_STYLE.get(proto, "white"), box=box.ROUNDED)


# -- flows ----------------------------------------------------------------------
def flows_table(flows: list[Flow], limit: int | None = None, title: str = "Conversations") -> Table:
    t = Table(title=title, box=box.SIMPLE_HEAVY, header_style="bold", title_style="bold", expand=True,
              row_styles=["", "on grey11"])
    compact = console.width < 110
    t.add_column("ID", justify="right", style="grey62", no_wrap=True)
    t.add_column("Client", no_wrap=True)
    t.add_column("Server", no_wrap=True)
    t.add_column("App", style="bold", no_wrap=True)
    t.add_column("State", no_wrap=True)
    if not compact:
        t.add_column("Pkts", justify="right", no_wrap=True)
    t.add_column("Bytes", justify="right", no_wrap=True)
    if not compact:
        t.add_column("Dur", justify="right", no_wrap=True)
    t.add_column("RTT", justify="right", no_wrap=True)
    show_risk = any(getattr(f, "risk", None) for f in flows)
    if show_risk:
        t.add_column("Risk", justify="right", no_wrap=True)
    t.add_column("Notes", overflow="fold", ratio=1, min_width=12)
    for f in flows[:limit] if limit else flows:
        notes = []
        if f.tls_sni:
            notes.append(f"SNI {f.tls_sni}")
        if f.http:
            first = f.http[0].get("request") or {}
            notes.append(f"{len(f.http)} HTTP tx" + (f" {first.get('method', '')} {first.get('uri', '')}"
                                                      if first else ""))
        if f.dns:
            q = next((d for d in f.dns if d["qname"]), None)
            if q:
                notes.append(f"{q['qtype']} {q['qname']}" + (f" → {', '.join(map(str, q['answers'][:2]))}"
                                                             if q["answers"] else ""))
            resp = next((d for d in f.dns if d["response"]), None)
            if resp and not resp["answers"]:
                notes.append(resp["rcode"])
        if f.proto == "tcp":
            rt = f.c2s.retransmissions + f.s2c.retransmissions
            oo = f.c2s.out_of_order + f.s2c.out_of_order
            if rt:
                notes.append(f"{rt} retrans")
            if oo:
                notes.append(f"{oo} out-of-order")
            if f.midstream:
                notes.append("mid-stream")
            if f.syn_retries:
                notes.append(f"{f.syn_retries} SYN retries")
        app_style = PROTO_STYLE.get(f.label.upper().replace("HTTPS", "TLS"), "white")
        cells = [str(f.id), f"{f.client[0]}:{f.client[1]}" if f.client[1] else f.client[0],
                 f"{f.server[0]}:{f.server[1]}" if f.server[1] else f.server[0],
                 Text(f.label, style=app_style), Text(f.state, style=STATE_STYLE.get(f.state, "white"))]
        if not compact:
            cells.append(str(f.packets))
        cells.append(human_bytes(f.bytes))
        if not compact:
            cells.append(f"{f.duration:.3f}s")
        cells.append(f"{f.rtt * 1000:.1f}ms" if f.rtt is not None else "")
        if show_risk:
            cells.append(Text(str(f.risk.score) if f.risk.score else "·", style=RISK_STYLE[f.risk.level]))
        cells.append("; ".join(notes))
        t.add_row(*cells)
    return t


def _date(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d") if ts else "?"


def tls_findings(flow: Flow) -> list[tuple[str, str]]:
    """(label, style) badges for what's wrong (or right) with a TLS session."""
    from . import tls as tlsmod, x509
    t = flow.tls
    out = []
    if t.get("version") in tlsmod.OLD_VERSIONS:
        out.append((f"old {t['version']}", "dark_orange"))
    if t.get("cipher") and tlsmod.is_weak_cipher(t["cipher"]):
        out.append(("weak cipher", "bold red"))
    certs = t.get("certs") or []
    if certs and "error" not in certs[0]:
        leaf = certs[0]
        ts = flow.tls_ts or flow.first_ts
        if ts > leaf["not_after"]:
            out.append(("expired", "bold red"))
        if leaf["self_signed"] and len(certs) == 1:
            out.append(("self-signed", "dark_orange"))
        if flow.tls_sni and not x509.name_matches(flow.tls_sni, leaf):
            out.append(("name mismatch", "bold red"))
    for a in t.get("alerts", []):
        if a.startswith("fatal"):
            out.append((a, "red3"))
    if not out and (certs or t.get("version")):
        out.append(("ok", "green3"))
    return out


def tls_table(flows: list[Flow]) -> Table:
    t = Table(title="TLS sessions", box=box.SIMPLE_HEAVY, header_style="bold", expand=True, title_style="bold")
    t.add_column("Flow", justify="right", style="grey62", no_wrap=True)
    t.add_column("Server", no_wrap=True)
    t.add_column("SNI", overflow="fold")
    t.add_column("Version", no_wrap=True)
    t.add_column("Cipher", overflow="fold")
    t.add_column("Certificate", overflow="fold")
    t.add_column("Valid until", no_wrap=True)
    t.add_column("Findings", overflow="fold")
    for f in flows:
        tl = f.tls
        if not tl and not f.tls_sni:
            continue
        certs = tl.get("certs") or []
        leaf = certs[0] if certs and "error" not in certs[0] else None
        cert = Text()
        if leaf:
            cert.append(leaf["subject_cn"] or leaf["subject"], style="bold")
            cert.append(f"\nby {leaf['issuer_cn'] or leaf['issuer']}", style="grey62")
            if len(certs) > 1:
                cert.append(f" (+{len(certs) - 1} in chain)", style="grey50")
        elif tl.get("version") == "TLS 1.3":
            cert.append("encrypted (TLS 1.3)", style="grey50")
        else:
            cert.append("—", style="grey50")
        badges = Text()
        for label, style in tls_findings(f):
            badges.append(f"{label} ", style=style)
        t.add_row(str(f.id), f"{f.server[0]}:{f.server[1]}", f.tls_sni or "", tl.get("version", ""),
                  tl.get("cipher", ""), cert, _date(leaf["not_after"]) if leaf else "", badges)
    return t


def cert_panel(flow: Flow) -> Panel:
    """Everything the handshake revealed: versions, cipher and each certificate in the chain."""
    tl = flow.tls
    g = Table.grid(padding=(0, 2))
    g.add_column(style="grey62", no_wrap=True)
    g.add_column()
    if flow.tls_sni:
        g.add_row("SNI", flow.tls_sni)
    if tl.get("alpn"):
        g.add_row("ALPN offered", tl["alpn"])
    if tl.get("client_version"):
        g.add_row("Client offered", f"{tl['client_version']}" + (" + TLS 1.3" if tl.get("offers_tls13") else "")
                  + (f", {tl['offered_ciphers']} cipher suites" if tl.get("offered_ciphers") else ""))
    if tl.get("version"):
        g.add_row("Negotiated", f"{tl['version']}, {tl.get('cipher', '?')}")
    for i, c in enumerate(tl.get("certs") or []):
        if "error" in c:
            g.add_row(f"Cert #{i}", Text(c["error"], style="red3"))
            continue
        key = f"{c['key_alg']} {c['key_bits'] or ''}".strip() + (f" ({c['curve']})" if c.get("curve") else "")
        body = Text.assemble((c["subject"], "bold"), "\n", ("issuer   ", "grey62"), c["issuer"], "\n",
                             ("valid    ", "grey62"), f"{_date(c['not_before'])} → {_date(c['not_after'])}", "\n",
                             ("key      ", "grey62"), key, ("   sig ", "grey62"), c["sig_alg"], "\n",
                             ("serial   ", "grey62"), c["serial"])
        if c["sans"]:
            body.append("\nSANs     ", style="grey62")
            body.append(", ".join(c["sans"][:12]) + (" …" if len(c["sans"]) > 12 else ""))
        body.append("\nSHA-256  ", style="grey62")
        body.append(c["sha256"], style="grey50")
        g.add_row("Leaf cert" if i == 0 else ("CA cert" if c["is_ca"] else f"Cert #{i}"), body)
    for a in tl.get("alerts", []):
        g.add_row("TLS alert", Text(a, style="red3"))
    badges = Text()
    for label, style in tls_findings(flow):
        badges.append(f"{label}  ", style=style)
    if badges:
        g.add_row("Findings", badges)
    return Panel(g, title=f"TLS · flow {flow.id}", title_align="left", border_style="gold1")



def _alert_text(c) -> Text:
    t = Text()
    for sev in ("high", "medium", "low"):
        if c[sev]:
            t.append(f"{c[sev]}{sev[0].upper()} ", style=SEV_STYLE[sev])
    t.rstrip()
    return t


def _host_name(h) -> Text:
    t = Text(h.addr, style="bold" if h.local else "")
    if h.name:
        t.append(f"\n{h.name}", style="grey70")
    if h.mac and not h.routed:
        t.append(f"\n{h.mac}", style="grey50")
    return t


def hosts_table(hosts: list, limit: int | None = None, width: int | None = None) -> Table:
    width = width or console.width
    wide = width >= 110
    # rich can overshoot by a column or two when it has to squeeze many folding columns, so leave slack
    t = Table(title=f"Hosts ({len(hosts)})", box=box.SIMPLE_HEAVY, header_style="bold",
              expand=wide, width=None if wide else width - 3)
    t.add_column("Host", overflow="fold", min_width=18, max_width=25)
    if wide:
        t.add_column("OS guess", overflow="fold", max_width=14)
    t.add_column("Role", overflow="fold", max_width=24)
    t.add_column("Ports", style="green3", overflow="fold")
    if wide:
        t.add_column("Uses", overflow="fold", style="grey70", max_width=28)
    t.add_column("Sent / recv", justify="right", no_wrap=True)
    t.add_column("Alerts", max_width=9)
    t.add_column("Risk", justify="right", no_wrap=True, min_width=4)
    for h in hosts[:limit] if limit else hosts:
        roles = Text()
        for i, r in enumerate(h.roles):
            style = "bold red" if r == "scanner" else "grey50" if r in ("external", "passive") else "cyan"
            roles.append((", " if i else "") + r, style=style)
        uses = ", ".join(f"{k}" + (f"×{v}" if v > 1 else "") for k, v in h.uses.most_common(4))
        risk = h.max_risk
        name = _host_name(h)
        if not wide and h.os:
            name.append(f"\n{h.os}", style="grey62 italic")
        cells = [name] + ([h.os] if wide else []) + [roles, ", ".join(map(str, h.open_ports[:8]))] + \
            ([uses] if wide else [])
        t.add_row(*cells, f"{human_bytes(h.bytes_sent)}\n{human_bytes(h.bytes_recv)}", _alert_text(h.alerts_caused),
                  Text(str(risk) if risk else "", style=RISK_STYLE[level_for(risk)]))
    return t


def host_panel(h, t0: float | None = None) -> Panel:
    """Everything known about one address."""
    t0 = t0 or h.first_ts
    rows = Table.grid(padding=(0, 2))
    rows.add_column(style="grey62", no_wrap=True)
    rows.add_column(overflow="fold")

    def row(label, value):
        if value:
            rows.add_row(label, value)

    row("Names", ", ".join(f"{n} [grey50]({src})[/]" for n, src in list(h.names.items())[:6]))
    row("MAC", ", ".join(h.macs) + (" [grey50](router's MAC; host is off-link)[/]" if h.routed else ""))
    row("OS guess", h.os + (f" [grey50](TTL {h.syn['ttl']}, window {h.syn['window']}, "
                            f"options {h.syn['options'] or 'none'})[/]" if h.syn else ""))
    row("Role", ", ".join(h.roles))
    row("Seen", f"{h.first_ts - t0:.3f}s → {h.last_ts - t0:.3f}s")
    row("Traffic", f"sent {h.pkts_sent} pkts / {human_bytes(h.bytes_sent)}, "
                   f"received {h.pkts_recv} pkts / {human_bytes(h.bytes_recv)}, "
                   f"{h.flows_out} outbound and {h.flows_in} inbound conversations")
    if h.services:
        row("Services", "\n".join(f"[green3]{k}[/] {v['label']} [grey50]← {len(v['clients'])} client(s), "
                                  f"{v['flows']} conn, {human_bytes(v['bytes'])}[/]"
                                  for k, v in sorted(h.services.items(), key=lambda kv: int(kv[0].split('/')[0]))))
    if h.closed_ports:
        ports = sorted(h.closed_ports)
        row("Closed ports", ", ".join(map(str, ports[:20])) + (f" … (+{len(ports) - 20})" if len(ports) > 20 else ""))
    row("Uses", ", ".join(f"{k} ×{v}" for k, v in h.uses.most_common(10)))
    row("Peers", ", ".join(f"{p} [grey50]{human_bytes(b)}[/]" for p, b in h.peers.most_common(6)))
    if h.domains:
        row("DNS lookups", "\n".join(f"{d}" + (f" ×{n}" if n > 1 else "") for d, n in h.domains.most_common(10))
            + (f"\n[yellow3]{h.nxdomains} NXDOMAIN answer(s)[/]" if h.nxdomains else ""))
    row("TLS SNI", ", ".join(h.sni))
    row("HTTP hosts", ", ".join(h.http_hosts))
    row("User-Agents", "\n".join(h.user_agents))
    if h.alerts_caused or h.alerts_targeted:
        row("Alerts", Text.assemble("caused ", _alert_text(h.alerts_caused) or Text("none", style="grey50"),
                                    "  targeted by ", _alert_text(h.alerts_targeted) or Text("none", style="grey50")))
        row("Rules", ", ".join(sorted(h.rules)))
    if h.max_risk:
        row("Riskiest flow", Text(f"{h.max_risk}/100", style=RISK_STYLE[level_for(h.max_risk)]))
    border = "red3" if h.alerts_caused["high"] else "dark_orange" if h.alerts_caused else "grey50"
    title = f"[bold]{h.addr}[/]" + (f"  [grey62]{h.name}[/]" if h.name else "")
    return Panel(rows, title=title, title_align="left", border_style=border)

def risk_table(flows: list[Flow], limit: int | None = None, show_all: bool = False) -> Table:
    t = Table(title="Conversation risk", box=box.SIMPLE_HEAVY, header_style="bold", expand=True,
              title_style="bold")
    t.add_column("Risk", no_wrap=True)
    t.add_column("Flow", justify="right", style="grey62", no_wrap=True)
    t.add_column("Conversation", no_wrap=True)
    t.add_column("App", no_wrap=True)
    t.add_column("Reasons", ratio=1, overflow="fold")
    rows = [f for f in flows if show_all or f.risk.score > 0]
    for f in rows[:limit] if limit else rows:
        r = f.risk
        style = RISK_STYLE[r.level]
        meter = Text()
        meter.append(f"{r.score:>3}/100 ", style=style)
        meter.append(f"{r.level:<6} ", style=style)
        meter.append_text(bar(r.score, 100, 10, style.replace("bold ", "")))
        client = f"{f.client[0]}:{f.client[1]}" if f.client[1] else f.client[0]
        server = f"{f.server[0]}:{f.server[1]}" if f.server[1] else f.server[0]
        t.add_row(meter, str(f.id), f"{client} → {server}", Text(f.label, style=PROTO_STYLE.get(f.label.upper(), "white")),
                  Text("; ".join(r.reasons) or "nothing notable", style="white" if r.reasons else "grey50"))
    if not rows:
        t.add_row("", "", Text("No conversation scored above zero.", style="green3"), "", "")
    return t


def ladder(flow: Flow, width: int | None = None, limit: int = 200) -> Group:
    """Sequence (ladder) diagram of a conversation, one arrow per packet."""
    w = width or console.width
    left = f"{flow.client[0]}:{flow.client[1]}"
    right = f"{flow.server[0]}:{flow.server[1]}"
    lane = max(30, min(w - 40, 90))
    head = Text()
    head.append(" " * 12)
    head.append(_cell(left, lane // 2), style="bold cyan")
    head.append(right.rjust(lane - lane // 2 + 2), style="bold green3")
    lines = [head, Text(" " * 12 + "│" + " " * lane + "│", style="grey42")]
    t0 = flow.first_ts
    for ev in flow.events[:limit]:
        label = _event_label(flow, ev)
        style = "cyan" if ev.direction == "c2s" else "green3"
        if "R" in ev.flags:
            style = "red3"
        elif ev.note and ("retrans" in ev.note or "out-of-order" in ev.note):
            style = "yellow3"
        body = f" {label} "
        body = body[: lane - 4]
        pad = lane - 1 - len(body)
        lpad = pad // 2
        if ev.direction == "c2s":
            arrow = "─" * lpad + body + "─" * (pad - lpad) + "▶"
        else:
            arrow = "◀" + "─" * lpad + body + "─" * (pad - lpad)
        row = Text(f"{ev.ts - t0:>10.4f}  ", style="grey50", no_wrap=True, overflow="ellipsis")
        row.append("│", style="grey42")
        row.append(arrow, style=style)
        row.append("│", style="grey42")
        row.append(f" #{ev.number}", style="grey42")
        if ev.note:
            row.append(f" {ev.note}", style="yellow3")
        lines.append(row)
    if len(flow.events) > limit:
        lines.append(Text(f"            … {len(flow.events) - limit} more packets", style="grey50"))
    return Group(*lines)


def _event_label(flow: Flow, ev) -> str:
    if flow.proto != "tcp":
        return f"{flow.label} {ev.length}B"
    names = {"S": "SYN", "F": "FIN", "R": "RST", "P": "PSH", "U": "URG", "E": "ECE", "W": "CWR"}
    parts = [names[c] for c in ev.flags if c in names]
    if "." in ev.flags:
        parts.append("ACK")
    s = ",".join(parts) or "none"
    s += f" seq={ev.seq}"
    if "." in ev.flags:
        s += f" ack={ev.ack}"
    if ev.length:
        s += f" len={ev.length}"
    return s


def handshake_panel(flow: Flow) -> Panel:
    hs = flow.handshake
    t = Table.grid(padding=(0, 2))
    t.add_column(style="grey62")
    t.add_column()
    t.add_row("Connection", flow.key_str)
    t.add_row("State", Text(flow.state, style=STATE_STYLE.get(flow.state, "white")))
    if hs:
        t0 = hs.get("syn", flow.first_ts)
        steps = []
        for k, name in (("syn", "SYN"), ("synack", "SYN-ACK"), ("ack", "ACK")):
            if k in hs:
                steps.append(f"{name} +{(hs[k] - t0) * 1000:.2f}ms")
            else:
                steps.append(f"[red]{name} missing[/]")
        t.add_row("Handshake", "  →  ".join(steps))
    if flow.rtt is not None:
        hsd = flow.handshake
        t.add_row("RTT", f"{flow.rtt * 1000:.2f} ms  (server side {(hsd['synack'] - hsd['syn']) * 1000:.2f} ms, "
                         f"client side {(hsd['ack'] - hsd['synack']) * 1000:.2f} ms)")
    t.add_row("State history", " → ".join(s for _, s in flow.history) or "-")
    if getattr(flow, "risk", None):
        r = flow.risk
        t.add_row("Risk", Text.assemble((f"{r.score}/100 {r.level}", RISK_STYLE[r.level]),
                                        ("  " + "; ".join(r.reasons) if r.reasons else "", "grey70")))
    if flow.proto == "tcp":
        for name, ep in (("Client → Server", flow.c2s), ("Server → Client", flow.s2c)):
            t.add_row(name, f"{ep.packets} pkts, {human_bytes(ep.stream_total)} stream, "
                            f"{ep.retransmissions} retrans, {ep.out_of_order} out-of-order, ISN {ep.isn}")
    return Panel(t, title=f"Flow {flow.id} · {flow.label}", title_align="left", border_style="cyan")


def stream_view(flow: Flow, max_bytes: int = 4000) -> Group:
    """Follow-TCP-stream style text, client in cyan and server in green."""
    parts = []
    for name, ep, style in (("client → server", flow.c2s, "cyan"), ("server → client", flow.s2c, "green3")):
        if ep is None or not ep.stream:
            continue
        data = bytes(ep.stream[:max_bytes])
        text = data.decode("utf-8", "replace") if _printable(data) else _hex_preview(data)
        more = f"\n… {ep.stream_total - max_bytes} more bytes" if ep.stream_total > max_bytes else ""
        parts.append(Panel(Text(text + more, style=style), title=name, title_align="left", border_style=style))
    return Group(*parts) if parts else Group(Text("No reassembled payload in this flow.", style="grey50"))


def _printable(data: bytes) -> bool:
    if not data:
        return True
    ok = sum(1 for c in data[:512] if 32 <= c < 127 or c in (9, 10, 13))
    return ok / min(len(data), 512) > 0.85


def _hex_preview(data: bytes) -> str:
    return "\n".join(data[i:i + 32].hex(" ") for i in range(0, min(len(data), 512), 32))


def http_table(flows: list[Flow]) -> Table:
    t = Table(title="HTTP transactions", box=box.SIMPLE_HEAVY, header_style="bold", expand=True)
    for c in ("Flow", "Method", "Host", "URI", "Status", "Type", "Size", "Time"):
        t.add_column(c, overflow="fold", justify="right" if c in ("Size", "Time", "Flow") else "left")
    for f in flows:
        for tx in f.http:
            req, resp = tx.get("request") or {}, tx.get("response") or {}
            status = resp.get("status")
            st = "green3" if status and status < 300 else "yellow3" if status and status < 400 else "red3"
            elapsed = f"{(resp['ts'] - req['ts']) * 1000:.1f}ms" if req and resp else ""
            t.add_row(str(f.id), req.get("method", ""), req.get("host", ""), req.get("uri", ""),
                      Text(str(status or "—"), style=st), resp.get("content_type", ""),
                      human_bytes(resp.get("body_len", 0)) if resp else "", elapsed)
    return t


def dns_table(flows: list[Flow]) -> Table:
    """DNS answers with identical repeats folded into one row and a count, mDNS shown in plain words."""
    t = Table(title="DNS", box=box.SIMPLE_HEAVY, header_style="bold", expand=True)
    for c in ("Flow", "ID", "Query", "Type", "Result"):
        t.add_column(c, overflow="fold")
    t.add_column("Seen", justify="right", no_wrap=True)
    rows: dict[tuple, list] = {}
    for f in flows:
        for d in f.dns:
            if not d["response"]:
                continue
            if d.get("meaning"):
                key = ("mdns", d["meaning"])
                cells = ("(mDNS announcement)", "", d["meaning"].removeprefix("mDNS: "), "green3")
            else:
                res = ", ".join(map(str, d["answers"])) or d["rcode"]
                key = (d["qname"], d["qtype"], res)
                cells = (d["qname"] or "", d["qtype"] or "", res, "red3" if d["rcode"] != "NOERROR" else "magenta")
            row = rows.get(key)
            if row is None:
                rows[key] = [[f.id], d["id"], cells, 1]
            else:
                row[3] += 1
                if f.id not in row[0]:
                    row[0].append(f.id)
    for ids, ident, (q, qt, res, style), n in rows.values():
        fl = ", ".join(map(str, ids[:3])) + (" …" if len(ids) > 3 else "")
        t.add_row(fl, f"0x{ident:04x}", q, qt, Text(res, style=style), Text(f"×{n}", style="bold yellow3") if n > 1
                  else "")
    return t


# -- alerts and statistics ----------------------------------------------------
def alerts_table(alerts: list[Alert], t0: float | None = None, limit: int | None = None) -> Table:
    t = Table(title=f"Alerts ({len(alerts)})", box=box.SIMPLE_HEAVY, header_style="bold", expand=True)
    t.add_column("Sev")
    t.add_column("Time", justify="right", style="grey62")
    t.add_column("Rule", style="bold")
    t.add_column("Source")
    t.add_column("Message", overflow="fold")
    t.add_column("Pkt", justify="right", style="grey62")
    ordered = sorted(alerts, key=lambda a: (SEVERITY_ORDER[a.severity], a.ts))
    for a in ordered[:limit] if limit else ordered:
        t.add_row(Text(f"{SEV_ICON[a.severity]} {a.severity}", style=SEV_STYLE[a.severity]),
                  f"{a.ts - t0:.3f}" if t0 is not None else fmt_time(a.ts, None, True),
                  a.rule, a.src, a.message, str(a.packet or ""))
    return t



def alert_explanations(groups: list[dict], t0: float | None = None) -> Group:
    """One panel per alert rule: what fired, why it matters and what to do next."""
    panels = []
    for g in groups:
        style = SEV_STYLE[g["severity"]]
        hosts = ", ".join(g["sources"][:4]) + (f" (+{len(g['sources']) - 4})" if len(g["sources"]) > 4 else "")
        body = Text.assemble(("Why it matters  ", "grey62"), (g["why"] + "\n", ""),
                             ("What to do      ", "grey62"), (g["action"] + "\n", "green3"),
                             ("Sources         ", "grey62"), (hosts, "bold"))
        if g["flows"]:
            body.append(Text.assemble(("   flows ", "grey62"), (", ".join(map(str, g["flows"][:6])), "cyan")))
        for ex in g["examples"]:
            body.append(Text(f"\n  • {ex}", style="grey70"))
        first = f"first at {g['first'] - t0:.3f}s" if t0 is not None else ""
        title = Text.assemble((f"{SEV_ICON[g['severity']]} {g['title']}", style), (f"  ×{g['count']}  ", "bold"),
                              (f"{g['rule']}  {first}", "grey50"))
        panels.append(Panel(body, title=title, title_align="left", border_style=style.replace("bold ", "")))
    return Group(*panels)

def bar(value: float, total: float, width: int = 24, style: str = "cyan") -> Text:
    frac = value / total if total else 0
    full = int(frac * width)
    rem = frac * width - full
    partial = " ▏▎▍▌▋▊▉"[int(rem * 8)] if full < width else ""
    return Text("█" * full + partial, style=style) + Text(" " * (width - full - len(partial.strip())))


HIERARCHY = ["ethernet", "sll", "loopback", "vlan", "arp", "ipv4", "ipv6", "icmp", "icmpv6", "igmp", "tcp", "http",
             "tls", "udp", "dns", "mdns", "dhcp"]


def protocol_hierarchy(an: Analyzer) -> Table:
    t = Table(title="Protocol hierarchy", box=box.SIMPLE, header_style="bold", expand=True)
    t.add_column("Protocol")
    t.add_column("Packets", justify="right")
    t.add_column("%", justify="right")
    t.add_column("", ratio=1)
    total = an.count or 1
    depth = {"ethernet": 0, "sll": 0, "loopback": 0, "vlan": 1, "arp": 1, "ipv4": 1, "ipv6": 1, "icmp": 2, "icmpv6": 2,
             "igmp": 2, "tcp": 2, "udp": 2, "http": 3, "tls": 3, "dns": 3, "mdns": 3, "dhcp": 3}
    for name in HIERARCHY:
        n = an.protocols.get(name, 0)
        if not n:
            continue
        style = LAYER_STYLE.get(name, "white")
        t.add_row(Text("  " * depth[name] + LAYER_TITLES.get(name, name), style=style), str(n),
                  f"{n / total * 100:.1f}", bar(n, total, 18, style))
    return t


def talkers_table(an: Analyzer, limit: int = 8) -> Table:
    t = Table(title="Top talkers", box=box.SIMPLE, header_style="bold", expand=True)
    t.add_column("Address")
    t.add_column("Sent", justify="right")
    t.add_column("", ratio=1)
    top = an.talkers.most_common(limit)
    peak = top[0][1] if top else 1
    for addr, b in top:
        t.add_row(addr, human_bytes(b), bar(b, peak, 12, "steel_blue1"))
    return t


def sparkline(values: list[int], width: int = 60) -> Text:
    if not values:
        return Text("")
    peak = max(values) or 1
    ticks = "▁▂▃▄▅▆▇█"
    return Text("".join(ticks[min(7, int(v / peak * 7.999))] if v else " " for v in values), style="cyan")


def summary_panel(an: Analyzer, source: str) -> Panel:
    dur = (an.last_ts - an.first_ts) if an.first_ts is not None else 0
    tcp_flows = [f for f in an.flows if f.proto == "tcp"]
    complete = sum(1 for f in tcp_flows if "ack" in f.handshake)
    sev = Counter(a.severity for a in an.alerts)
    g = Table.grid(padding=(0, 3))
    for _ in range(4):
        g.add_column()
    g.add_row(_kv("Source", source), _kv("Packets", f"{an.count:,}"), _kv("Bytes", human_bytes(an.bytes)),
              _kv("Duration", f"{dur:.2f}s"))
    g.add_row(_kv("Flows", str(len(an.flows))), _kv("TCP handshakes", f"{complete}/{len(tcp_flows)}"),
              _kv("Avg rate", f"{an.count / dur:.1f} pkt/s" if dur else "-"),
              Text.assemble(("Alerts ", "grey62"), (f"{sev['high']} high ", SEV_STYLE["high"]),
                            (f"{sev['medium']} med ", SEV_STYLE["medium"]), (f"{sev['low']} low", SEV_STYLE["low"])))
    body = Group(g, Text(""), Text.assemble(("Activity   ", "grey62"), sparkline(_timeline(an, 70), 70),
                                            (f"  over {dur:.1f}s", "grey50")))
    return Panel(body, title="[bold]Capture summary[/]", title_align="left", border_style="steel_blue1")


def _timeline(an: Analyzer, width: int) -> list[int]:
    """Resample the 100 ms packet-count buckets into ``width`` columns."""
    if not an.timeline:
        return []
    n = max(an.timeline) + 1
    if n <= width:
        return [an.timeline.get(i, 0) for i in range(n)]
    out = [0] * width
    for k, v in an.timeline.items():
        out[min(width - 1, k * width // n)] += v
    return out


def _kv(k: str, v: str) -> Text:
    return Text.assemble((k + " ", "grey62"), (v, "bold"))


def print_stats(an: Analyzer, source: str, con: Console | None = None) -> None:
    from . import story
    con = con or console
    if an.count:
        con.print(Panel(Text(" ".join(story.summarize(an)["headline"])), title="[bold]In plain English[/]",
                        title_align="left", border_style="cyan", box=box.ROUNDED))
    con.print(summary_panel(an, source))
    side = Table.grid(expand=True, padding=(0, 2))
    side.add_column(ratio=3)
    side.add_column(ratio=2)
    side.add_row(protocol_hierarchy(an), talkers_table(an))
    con.print(side)
    con.print(flows_table(sorted(an.flows, key=lambda f: -f.bytes), limit=25, title="Top conversations by bytes"))
    if any(f.http for f in an.flows):
        con.print(http_table(an.flows))
    if any(f.dns for f in an.flows):
        con.print(dns_table(an.flows))
    if an.alerts:
        con.print(alerts_table(an.alerts, an.first_ts))
    else:
        con.print(Panel(Text("No suspicious traffic detected.", style="green3"), border_style="green3"))


# -- live dashboard -----------------------------------------------------------
class Dashboard:
    """Full-screen live view: packet tail, active conversations, alerts and counters."""

    def __init__(self, an: Analyzer, source: str, display_filter=None):
        self.an = an
        self.source = source
        self.filter = display_filter or (lambda p: True)
        self.recent: deque = deque(maxlen=200)
        self.started = time.time()
        self.rate: deque = deque(maxlen=60)  # packets per refresh second
        self._last_count = 0
        self._last_tick = time.time()
        self.paused = False
        self.finished = False   # a replay reached the end of the file
        self.keys = False       # keyboard control available
        self.shown = 0
        self.story = False      # show grouped plain-English events instead of raw packets

    def add(self, pkt: Packet) -> None:
        if self.filter(pkt):
            self.recent.append(pkt)
            self.shown += 1

    def tick(self) -> None:
        now = time.time()
        if now - self._last_tick >= 1.0:
            self.rate.append(self.an.count - self._last_count)
            self._last_count = self.an.count
            self._last_tick = now

    def render(self, height: int | None = None) -> Layout:
        self.tick()
        height = height or console.height
        body_h = max(10, height - 6)
        pkt_h = max(5, body_h * 11 // 20)
        low_h = body_h - pkt_h
        layout = Layout()
        layout.split_column(Layout(name="head", size=5), Layout(name="packets", size=pkt_h),
                            Layout(name="bottom", size=low_h), Layout(name="foot", size=1))
        layout["bottom"].split_row(Layout(name="flows", ratio=6), Layout(name="alerts", ratio=5),
                                   Layout(name="protos", ratio=3))
        layout["head"].update(self._header())
        layout["packets"].update(self._story(pkt_h - 2) if self.story else self._packets(pkt_h - 2))
        layout["flows"].update(self._flows(low_h - 3))
        layout["protos"].update(Panel(self._protos(), title="Protocols", title_align="left",
                                      border_style="steel_blue1"))
        layout["alerts"].update(self._alerts(low_h - 2))
        layout["foot"].update(self._footer())
        return layout

    def _footer(self) -> Text:
        if not self.keys:
            return Text(" Ctrl-C to stop · a full summary is printed on exit", style="grey50")
        toggle = ("s", "show packets" if self.story else "plain English")
        keys = [("q", "quit and show the summary"), ("space", "resume" if self.paused else "pause"), toggle]
        if self.finished:
            keys = [("e", "explore this capture"), toggle, ("q", "quit and show the summary")]
        t = Text(no_wrap=True, overflow="ellipsis")
        if self.paused:
            t.append(" PAUSED ", style="bold black on yellow")
            t.append(" ")
        elif self.finished:
            t.append(" REPLAY DONE ", style="bold black on green3")
            t.append(" ")
        for k, label in keys:
            t.append(f" {k} ", style="bold black on grey70")
            t.append(f" {label}  ")
        return t

    def _header(self) -> Panel:
        an = self.an
        elapsed = time.time() - self.started
        g = Table.grid(expand=True)
        for _ in range(5):
            g.add_column(ratio=1)
        sev = Counter(a.severity for a in an.alerts)
        g.add_row(_kv("Source", self.source), _kv("Packets", f"{an.count:,}"), _kv("Bytes", human_bytes(an.bytes)),
                  _kv("Flows", str(len(an.tracker.by_id))),
                  Text.assemble(("Alerts ", "grey62"), (str(sev["high"]), SEV_STYLE["high"]), " / ",
                                (str(sev["medium"]), SEV_STYLE["medium"]), " / ", (str(sev["low"]), SEV_STYLE["low"])))
        cur = self.rate[-1] if self.rate else 0
        g.add_row(_kv("Elapsed", f"{elapsed:.0f}s"), _kv("Rate", f"{cur} pkt/s"),
                  Text.assemble(("Shown ", "grey62"), (f"{self.shown:,}", "bold")), "",
                  sparkline(list(self.rate)[-30:], 30))
        return Panel(g, title="[bold cyan]pktanalyzer[/] [grey62]live[/]", title_align="left", border_style="cyan")

    def _packets(self, rows: int) -> Panel:
        width = max(60, console.width - 4)
        addr = 22 if width >= 120 else 17 if width >= 100 else 15
        widths = (6, addr, max(10, width - (6 + 1 + 11 + 1 + addr * 2 + 2 + 7 + 8)))
        t0 = self.an.first_ts
        lines = [packet_line(p, t0, widths) for p in list(self.recent)[-rows:]]
        return Panel(Group(*lines) if lines else Text("waiting for packets…", style="grey50"),
                     title="Packets", title_align="left", border_style="grey42")

    def _story(self, rows: int) -> Panel:
        width = max(40, console.width - 4)
        nar = self.an.narrator
        events = nar.recent(max(1, rows))
        now = self.an.last_ts or 0
        lines = [story_line(nar, ev, width, now) for ev in events]
        return Panel(Group(*lines) if lines else Text("waiting for packets…", style="grey50"),
                     title="What's happening  [grey50](newest first, repeats grouped)[/]", title_align="left",
                     border_style="cyan")

    def _flows(self, rows: int) -> Panel:
        flows = sorted(self.an.tracker.by_id.values(), key=lambda f: -f.last_ts)[:max(1, rows)]
        t = Table(box=None, expand=True, header_style="bold grey62", padding=(0, 1))
        t.add_column("Conversation", no_wrap=True, overflow="ellipsis", ratio=1)
        t.add_column("App", no_wrap=True, max_width=9)
        t.add_column("State", no_wrap=True)
        t.add_column("Bytes", justify="right", no_wrap=True)
        for f in flows:
            client = f"{f.client[0]}:{f.client[1]}" if f.client[1] else f.client[0]
            server = f"{f.server[0]}:{f.server[1]}" if f.server[1] else f.server[0]
            t.add_row(f"{client} → {server}", Text(f.label, style=PROTO_STYLE.get(f.label.upper(), "white")),
                      Text(f.state, style=STATE_STYLE.get(f.state, "white")), human_bytes(f.bytes))
        return Panel(t, title="Recent conversations", title_align="left", border_style="grey42")

    def _protos(self) -> Table:
        t = Table.grid(padding=(0, 1), expand=True)
        t.add_column(width=7)
        t.add_column(justify="right", width=7)
        t.add_column(ratio=1)
        total = self.an.count or 1
        for name, n in self.an.top_protocol.most_common(9):
            style = PROTO_STYLE.get(name, "white")
            t.add_row(Text(name, style=style), str(n), bar(n, total, max(4, console.width * 3 // 14 - 20), style))
        return t

    def _alerts(self, rows: int = 12) -> Panel:
        alerts = list(self.an.alerts)[-max(1, rows):]
        lines = []
        t0 = self.an.first_ts or 0
        for a in reversed(alerts):
            lines.append(Text.assemble((f"{SEV_ICON[a.severity]} ", SEV_STYLE[a.severity]),
                                       (f"{a.ts - t0:7.2f}s ", "grey50"), (a.rule + " ", "bold"),
                                       (a.message, SEV_STYLE[a.severity]), no_wrap=True, overflow="ellipsis"))
        body = Group(*lines) if lines else Text("nothing suspicious yet", style="green3")
        return Panel(body, title="Alerts", title_align="left",
                     border_style="red" if any(a.severity == "high" for a in alerts) else "grey42")


# -- timeline -------------------------------------------------------------------
def timeline_swimlanes(events: list, t0: float, t1: float, width: int = 80) -> Panel:
    """Density strip per event kind across the capture's duration."""
    span = max(t1 - t0, 1e-6)
    lanes = [k for k in TL.KINDS if any(e.kind == k for e in events)]
    t = Table.grid(padding=(0, 1))
    t.add_column(justify="right", style="grey62", no_wrap=True)
    t.add_column(no_wrap=True)
    t.add_column(justify="right", style="grey50", no_wrap=True)
    axis = Text(f"{0:.2f}s", style="grey50")
    end = f"{span:.2f}s"
    axis.append("─" * max(1, width - len(axis) - len(end)), style="grey35")
    axis.append(end, style="grey50")
    t.add_row("", axis, "")
    for k in lanes:
        cells = [0] * width
        for e in events:
            if e.kind == k:
                cells[min(width - 1, int((e.ts - t0) / span * (width - 1)))] += e.count
        row = Text()
        for n in cells:
            if n == 0:
                row.append("·", style="grey23")
            else:
                row.append(TL.KIND_MARK[k] if n < 3 else "█", style=TL.KIND_STYLE[k])
        t.add_row(Text(k, style=TL.KIND_STYLE[k]), row, str(sum(e.count for e in events if e.kind == k)))
    return Panel(t, title="Activity by type", title_align="left", border_style="grey42")


def timeline_table(events: list, t0: float) -> Table:
    t = Table(box=box.SIMPLE_HEAVY, header_style="bold", expand=True, show_edge=False)
    t.add_column("Time", justify="right", style="grey62", no_wrap=True)
    t.add_column("", no_wrap=True)
    t.add_column("Event", ratio=4, overflow="fold")
    t.add_column("Detail", ratio=3, overflow="fold")
    t.add_column("Latency", no_wrap=True)
    t.add_column("Flow", justify="right", style="grey50", no_wrap=True)
    peak = max((e.duration for e in events if e.duration), default=0) or 1
    for e in events:
        style = TL.KIND_STYLE[e.kind]
        level = TL.LEVEL_STYLE[e.level]
        lat = Text()
        if e.duration is not None:
            ms = e.duration * 1000
            n = max(1, round(e.duration / peak * 8))
            lat.append("▇" * n, style="red3" if ms > 500 else "yellow3" if ms > 100 else style)
            lat.append(f" {ms:.1f}ms", style="grey62")
        t.add_row(f"{e.ts - t0:.4f}", Text(f"{TL.KIND_MARK[e.kind]} {e.kind}", style=style),
                  Text(e.title, style=level or "white"), Text(e.detail, style="grey70"), lat,
                  str(e.flow) if e.flow is not None else "")
    return t


def timeline_view(an: Analyzer, events: list, width: int) -> Group:
    t0 = an.first_ts or 0.0
    t1 = an.last_ts or t0
    lane_w = max(20, min(width - 24, 120))
    if not events:
        return Group(Text("No events match.", style="grey50"))
    return Group(timeline_swimlanes(events, t0, t1, lane_w), timeline_table(events, t0))


# -- capture comparison ------------------------------------------------------
def _delta(before, after) -> Text:
    if not isinstance(before, (int, float)) or before == after:
        return Text("")
    if before == 0:
        return Text("new", style="yellow3")
    pct = (after - before) / abs(before) * 100
    style = "red3" if pct > 50 else "green3" if pct < -50 else "grey62"
    return Text(f"{pct:+.0f}%", style=style)


def diff_view(d: dict) -> Group:
    parts = []
    head = Text()
    for line in d["headline"]:
        bad = not line.startswith("No significant")
        head.append(("▲ " if bad else "✓ ") + line + "\n", style="bold" if bad else "green3")
    head.rstrip()
    parts.append(Panel(head, title=f"[bold]{os.path.basename(d['before'])}[/] → [bold]{os.path.basename(d['after'])}[/]",
                       title_align="left", border_style="red3" if d["new_alerts"] else "cyan"))

    t = Table(box=box.SIMPLE, header_style="bold", title="Overview")
    t.add_column("Metric")
    t.add_column("Before", justify="right")
    t.add_column("After", justify="right")
    t.add_column("Change", justify="right")
    for metric, before, after in d["summary"]:
        fmt = (lambda v: human_bytes(v)) if metric == "Bytes" else (lambda v: f"{v:,}" if isinstance(v, int) else str(v))
        t.add_row(metric, fmt(before), fmt(after), _delta(before, after))
    parts.append(t)

    def table(title, cols, rows, style=None):
        if not rows:
            return
        tb = Table(box=box.SIMPLE, header_style="bold", title=title, title_style=style or "bold", expand=True)
        for c in cols:
            tb.add_column(c, overflow="fold")
        for r in rows:
            tb.add_row(*r)
        parts.append(tb)

    table(f"New alerts ({len(d['new_alerts'])})", ["Sev", "Rule", "Source → target", "Message"],
          [(Text(f"{SEV_ICON[a['severity']]} {a['severity']}", style=SEV_STYLE[a["severity"]]), a["rule"],
            f"{a['src']} → {a['dst']}", a["message"]) for a in d["new_alerts"]], "bold red")
    table("Alerts that increased", ["Rule", "Source → target", "Before", "After"],
          [(a["rule"], f"{a['src']} → {a['dst']}", str(a["before"]), str(a["after"])) for a in d["increased_alerts"]])
    table(f"Resolved alerts ({len(d['resolved_alerts'])})", ["Sev", "Rule", "Source → target"],
          [(a["severity"], a["rule"], f"{a['src']} → {a['dst']}") for a in d["resolved_alerts"]], "bold green3")

    def risk_cell(r):
        return Text(str(r) if r else "", style=RISK_STYLE[level_for(r)])

    table(f"New conversations ({len(d['new_conversations'])})", ["Conversation", "Ports", "Flows", "Bytes", "Risk"],
          [(c["text"], ", ".join(map(str, c["ports"][:12])) + (" …" if len(c["ports"]) > 12 else ""),
            str(c["flows"]), human_bytes(c["bytes"]), risk_cell(c["max_risk"])) for c in d["new_conversations"]])
    table(f"Missing conversations ({len(d['missing_conversations'])})", ["Conversation", "Flows", "Bytes"],
          [(c["text"], str(c["flows"]), human_bytes(c["bytes"])) for c in d["missing_conversations"]], "grey62")
    table("Changed conversations", ["Conversation", "What changed", "Risk"],
          [(c["text"], "; ".join(c["changes"]), risk_cell(c["max_risk"])) for c in d["changed_conversations"]])

    table("Changed DNS answers", ["Name", "Type", "Before", "After"],
          [(x["name"], x["qtype"], ", ".join(x["before"]), Text(", ".join(x["after"]), style="yellow3"))
           for x in d["dns_changed"]], "bold yellow3")
    table(f"New DNS names ({len(d['dns_new'])})", ["Name", "Type", "Answer", "Asked by"],
          [(x["name"], x["qtype"], ", ".join(x["answers"][:3]), ", ".join(x["clients"])) for x in d["dns_new"]])
    if d["dns_missing"]:
        parts.append(Text("No longer looked up: " + ", ".join(x["name"] for x in d["dns_missing"][:15]),
                          style="grey62"))

    table("Changed TLS", ["SNI", "What changed"], [(x["sni"], "; ".join(x["changes"])) for x in d["tls_changed"]],
          "bold yellow3")
    table("New TLS servers", ["SNI", "Server", "Version", "Cipher", "Certificate"],
          [(x["sni"], x["server"], x["version"] or "", x["cipher"] or "",
            f"{x['subject'] or ''}" + (f" by {x['issuer']}" if x["issuer"] else "")) for x in d["tls_new"]])

    table("Open ports", ["Host", "Newly open", "No longer open"],
          [(p["host"], Text(", ".join(map(str, p["opened"])), style="red3"), ", ".join(map(str, p["closed"])))
           for p in d["port_changes"]])
    table(f"New hosts ({len(d['new_hosts'])})", ["Host", "Name", "Role", "Open ports", "Alerts"],
          [(h["host"], h["name"], ", ".join(h["roles"]), ", ".join(map(str, h["open_ports"])),
            str(h["alerts"] or "")) for h in d["new_hosts"]])
    if d["missing_hosts"]:
        parts.append(Text("Hosts no longer seen: " + ", ".join(h["host"] + (f" ({h['name']})" if h["name"] else "")
                                                             for h in d["missing_hosts"][:15]), style="grey62"))

    table("Protocol mix (share of packets)", ["Protocol", "Before", "After", "Change"],
          [(p["protocol"], f"{p['before']}%", f"{p['after']}%",
            Text(f"{p['delta']:+.1f} pts" + (f" ({p['status']})" if p["status"] else ""),
                 style="yellow3" if p["status"] else "")) for p in d["protocols"]])
    table("Bandwidth per host (bytes sent per second)", ["Host", "Before", "After"],
          [(b["host"], f"{b['before']:,} B/s", f"{b['after']:,} B/s") for b in d["bandwidth"]])
    return Group(*parts)


# -- behavioural hunting -------------------------------------------------------
HUNT_TITLE = {"beaconing": "Beaconing", "exfiltration": "Data exfiltration", "long-session": "Long encrypted session",
              "dns-exfiltration": "DNS exfiltration", "icmp-tunnel": "ICMP tunnel"}


def beacon_strip(series: list, t0: float, t1: float, width: int = 60) -> Text:
    """One tick per check-in on a shared time axis; regular spacing is the giveaway."""
    cells = [" "] * width
    span = max(t1 - t0, 1e-9)
    for ts, _ in series:
        cells[min(width - 1, int((ts - t0) / span * (width - 1)))] = "┃"
    return Text("".join(cells), style="red3")


def hunt_view(findings: list, t0: float, t1: float, width: int = 100) -> Group:
    if not findings:
        return Group(Panel(Text("No beaconing or exfiltration patterns found.", style="green3"),
                           border_style="green3"))
    parts = []
    for x in findings:
        sev = x.severity
        body = Text()
        body.append(x.summary + "\n", style="bold")
        for e in x.evidence:
            body.append(f"  • {e}\n")
        body.append(f"  seen {x.first_ts - t0:.1f}s → {x.last_ts - t0:.1f}s", style="grey62")
        if x.flows:
            body.append(f"   flows {', '.join(map(str, x.flows[:8]))}" + (" …" if len(x.flows) > 8 else ""),
                        style="cyan")
        items = [body]
        if x.series:
            strip_w = max(20, min(80, width - 16))
            items += [Text(""), Text.assemble(("  check-ins ", "grey62"), beacon_strip(x.series, t0, t1, strip_w))]
            gaps = [b[0] - a[0] for a, b in zip(x.series, x.series[1:])]
            items.append(Text.assemble(("  gaps (s)  ", "grey62"),
                                       (" ".join(f"{g:.0f}" for g in gaps[:24]), "grey70")))
        title = Text.assemble((f"{SEV_ICON[sev]} {HUNT_TITLE.get(x.kind, x.kind)}", SEV_STYLE[sev]),
                              (f"  score {x.score}/100", "bold"))
        parts.append(Panel(Group(*items), title=title, title_align="left",
                           border_style=SEV_STYLE[sev].replace("bold ", "")))
    return Group(*parts)


# -- plain-English story ----------------------------------------------------------
CAT_STYLE = {"alert": "bold red", "web": "cyan", "connect": "magenta", "lookup": "medium_purple1",
             "network": "grey62", "discovery": "green3", "more": "grey50"}


def _ago(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.0f}s"
    if seconds < 3600:
        return f"{seconds / 60:.0f}m"
    return f"{seconds / 3600:.0f}h"


def story_line(nar, ev, width: int, t_ref: float | None = None, wrap: bool = False) -> Text:
    """One grouped event: a category tag, the sentence and how often it happened."""
    from .story import CATEGORY_LABEL, shown_count
    cat = ev.category
    style = SEV_STYLE.get(ev.severity, CAT_STYLE[cat]) if cat == "alert" else CAT_STYLE[cat]
    t = Text(no_wrap=not wrap, overflow="fold" if wrap else "ellipsis")
    if t_ref is not None:
        t.append(f"{_ago(max(0.0, t_ref - ev.last_ts)):>4} ", style="grey50")
    t.append(f"{CATEGORY_LABEL[cat][:9]:<9} ", style=style)
    t.append(nar.describe(ev), style="bold" if cat == "alert" else "")
    n = shown_count(ev)
    if n > 1:
        t.append(f"  ×{n}", style="bold yellow3")
    if not wrap:
        t.truncate(max(10, width), overflow="ellipsis")
    return t


def story_view(an: Analyzer, width: int = 100, summary: dict | None = None) -> Group:
    """The whole capture as a short, readable summary."""
    from . import story
    s = summary or story.summarize(an)
    parts = [Panel(Text(" ".join(s["headline"])), title="[bold]What happened[/]", title_align="left",
                   border_style="cyan", box=box.ROUNDED)]
    if s["concerns"]:
        body = Text()
        for c in s["concerns"][:8]:
            body.append(f"{SEV_ICON[c['severity']]} ", style=SEV_STYLE[c["severity"]])
            body.append(c["title"], style="bold")
            if c["count"] > 1:
                body.append(f" ×{c['count']}", style="bold yellow3")
            if c["who"]:
                body.append(f"  from {', '.join(c['who'][:2])}", style="grey62")
            body.append(f"\n   {c['why'].split('. ')[0].rstrip('.')}.\n", style="grey70")
        if len(s["concerns"]) > 8:
            body.append(f"… and {len(s['concerns']) - 8} more kinds of warning (see the alerts view)\n", style="grey62")
        body.rstrip()
        high = any(c["severity"] == "high" for c in s["concerns"])
        parts.append(Panel(body, title="[bold]What to look at[/]", title_align="left",
                           border_style="red3" if high else "dark_orange", box=box.ROUNDED))
    else:
        parts.append(Panel(Text("Nothing suspicious stood out.", style="green3"), border_style="green3"))
    if s["devices"]:
        body = Text()
        inner = max(30, width - 6)
        for d in s["devices"][:12]:
            body.append(d["title"], style="bold")
            if d["desc"]:
                body.append(f"  {d['desc']}", style="grey62")
            body.append("\n")
            for cat, line, count in d["lines"]:
                body.append("  • ", style=CAT_STYLE.get(cat, "white"))
                room = inner - 4 - (len(f"  ×{count}") if count > 1 else 0)
                body.append(line if len(line) <= room else line[:room - 1] + "…")
                if count > 1:
                    body.append(f"  ×{count}", style="bold yellow3")
                body.append("\n")
        if len(s["devices"]) > 12:
            body.append(f"… and {len(s['devices']) - 12} more devices\n", style="grey62")
        body.rstrip()
        parts.append(Panel(body, title="[bold]Who did what[/]", title_align="left", border_style="steel_blue1",
                           box=box.ROUNDED))
    if s["nearby"]:
        t = Table(box=box.SIMPLE, header_style="bold", expand=True, padding=(0, 1))
        t.add_column("Device", style="bold", ratio=3, overflow="fold")
        t.add_column("Address", no_wrap=True)
        t.add_column("What it is", ratio=3, overflow="fold")
        t.add_column("Offers", ratio=4, overflow="fold")
        t.add_column("Seen", justify="right", no_wrap=True)
        for d in s["nearby"][:20]:
            what = d.kind + (f" · {d.os}" if d.os else "")
            t.add_row(d.name or "—", d.addr, what, ", ".join(d.labels) or "—", f"×{d.announcements}")
        parts.append(Panel(t, title="[bold]Devices that announced themselves[/]", title_align="left",
                           border_style="green3", box=box.ROUNDED))
    for b in s["background"]:
        parts.append(Text(b, style="grey50"))
    return Group(*parts)


def story_page(nar, ev, t0: float | None) -> Group:
    """Detail for one grouped event, with decoded mDNS records for a device announcement."""
    from . import discovery
    t0 = t0 or ev.first_ts
    head = Text()
    head.append(nar.describe(ev) + "\n", style="bold")
    meaning = nar.meaning(ev)
    if meaning:
        head.append(meaning + "\n", style="grey70")
    head.append(f"\nHappened {ev.count}× between {ev.first_ts - t0:.2f}s and {ev.last_ts - t0:.2f}s", style="grey62")
    if ev.packets:
        head.append(f"\nPackets {', '.join(map(str, ev.packets))}" + (" …" if ev.count > len(ev.packets) else ""),
                    style="cyan")
    from .story import CATEGORY_LABEL
    parts = [Panel(head, title=f"[bold]{CATEGORY_LABEL[ev.category]}[/]", title_align="left", border_style="cyan")]
    if ev.items and ev.kind in ("lookup", "arp", "http", "alert"):
        label = {"lookup": "Names looked up", "arp": "Addresses asked about", "http": "Pages",
                 "alert": "Targets"}[ev.kind]
        parts.append(Panel(Text("\n".join(list(ev.items)[:60])), title=label, title_align="left",
                           border_style="grey42"))
    if ev.kind == "search":
        t = Table(box=box.SIMPLE, header_style="bold", expand=True)
        t.add_column("Asked for", style="bold")
        t.add_column("Meaning")
        for item in ev.items:
            if item.startswith("ssdp:"):
                t.add_row(item[5:], discovery.ssdp_target(item[5:]))
            else:
                t.add_row(item, discovery.search_meaning(item))
        parts.append(t)
    dev = nar.an.discovery.devices.get(ev.src) if ev.kind == "announce" else None
    if dev is not None:
        info = Table.grid(padding=(0, 2))
        info.add_column(style="grey62")
        info.add_column()
        for k, v in (("Name", dev.name), ("Model", f"{dev.model_name}" + (f"  ({dev.model})" if dev.model and
                                                                          dev.model != dev.model_name else "")),
                     ("Software", dev.os), ("Hostname", dev.hostname), ("Other addresses", ", ".join(sorted(dev.addrs))),
                     ("UPnP server", dev.server)):
            if v:
                info.add_row(k, v)
        parts.append(Panel(info, title="Device", title_align="left", border_style="green3"))
        for svc, entry in dev.services.items():
            t = Table(box=box.SIMPLE, header_style="bold", expand=True, padding=(0, 1))
            t.add_column("Key", style="bold cyan", no_wrap=True)
            t.add_column("Value", overflow="fold", ratio=3)
            t.add_column("What it means", overflow="fold", ratio=3, style="grey70")
            for k, v, m in discovery.explain_txt(entry["txt"]):
                t.add_row(k, v, m)
            title = f"{discovery.service_label(svc)} ({svc}" + (f", port {entry['port']}" if entry["port"] else "") \
                + f") · it {discovery.service_meaning(svc)}"
            parts.append(Panel(t if entry["txt"] else Text("no extra details", style="grey50"), title=title,
                               title_align="left", border_style="grey42"))
    return Group(*parts)


def mdns_panel(fields: dict) -> Panel:
    """A plain-English reading of one mDNS packet, with every TXT key explained."""
    from . import discovery
    m = discovery.interpret_mdns(fields)
    parts = [Text(discovery.mdns_summary(fields).removeprefix("mDNS: "), style="bold")]
    if not m["response"] and m["asks"]:
        parts.append(Text("A device is asking the local network: is anyone here offering "
                          + ", ".join(discovery.search_meaning(a) for a in m["asks"]) + "?", style="grey70"))
    for svc in m["services"]:
        line = Text.assemble(("• ", "green3"), (discovery.service_label(svc), "bold"), f" ({svc}"
                             + (f", port {m['ports'][svc]}" if svc in m["ports"] else "") + "): it "
                             + discovery.service_meaning(svc))
        parts.append(line)
        txt = m["txt"].get(svc)
        if txt:
            t = Table(box=None, show_header=False, padding=(0, 1), expand=True)
            t.add_column(style="bold cyan", no_wrap=True)
            t.add_column(overflow="fold", ratio=3)
            t.add_column(style="grey70", overflow="fold", ratio=3)
            for k, v, meaning in discovery.explain_txt(txt):
                t.add_row("   " + k, v, meaning)
            parts.append(t)
    if m["addrs"]:
        parts.append(Text(f"Addresses: {', '.join(sorted(m['hostnames']))} → {', '.join(sorted(m['addrs']))}",
                          style="grey62"))
    parts.append(Text("This is Bonjour/mDNS: devices telling each other what they are. It is normal background "
                      "traffic.", style="grey50"))
    return Panel(Group(*parts), title="[bold]In plain English[/]", title_align="left", border_style="green3")
