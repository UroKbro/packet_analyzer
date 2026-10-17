"""Conversation timeline: one time-ordered story of what happened on the wire.

Handshakes, DNS lookups, HTTP exchanges, TLS sessions, retransmissions, resets
and alerts are pulled out of the analyzed flows and laid on a single clock, so
latency and attack sequences can be read top to bottom.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from rich import box
from rich.console import Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .analyzer import Analyzer

KINDS = ("handshake", "dns", "http", "tls", "retrans", "reset", "close", "alert")
DEFAULT_KINDS = ("handshake", "dns", "http", "tls", "retrans", "reset", "alert")
KIND_STYLE = {"handshake": "cyan", "dns": "magenta", "http": "green3", "tls": "gold1", "retrans": "yellow3",
              "reset": "red3", "close": "grey58", "alert": "bold red"}
KIND_MARK = {"handshake": "●", "dns": "◆", "http": "▲", "tls": "■", "retrans": "↻", "reset": "✕",
             "close": "○", "alert": "!"}
LEVEL_STYLE = {"info": "", "warn": "yellow3", "bad": "red3"}
COLLAPSE_WINDOW = 2.0  # seconds within which repeated refusals/resets/retransmissions merge


@dataclass
class Event:
    ts: float
    kind: str
    title: str
    detail: str = ""
    level: str = "info"            # info, warn, bad
    flow: int | None = None
    src: str = ""
    dst: str = ""
    duration: float | None = None  # latency the event represents (RTT, DNS answer time, HTTP response time)
    count: int = 1                 # >1 when several similar events were collapsed
    ports: list = field(default_factory=list)
    duration_span: float = 0.0     # time covered by a collapsed group

    def to_dict(self, t0: float = 0.0) -> dict:
        return dict(t=round(self.ts - t0, 6), ts=self.ts, kind=self.kind, title=self.title, detail=self.detail,
                    level=self.level, flow=self.flow, src=self.src, dst=self.dst,
                    duration_ms=round(self.duration * 1000, 3) if self.duration is not None else None,
                    count=self.count)


def _ep(addr: tuple) -> str:
    return f"{addr[0]}:{addr[1]}" if addr[1] else addr[0]


def build(an: Analyzer, kinds=DEFAULT_KINDS, host: str | None = None, flow_id: int | None = None,
          collapse: bool = True) -> list[Event]:
    events: list[Event] = []
    for f in an.flows:
        if flow_id is not None and f.id != flow_id:
            continue
        c, s = _ep(f.client), _ep(f.server)
        common = dict(flow=f.id, src=f.client[0], dst=f.server[0])
        if f.proto == "tcp":
            hs = f.handshake
            if "syn" in hs:
                if "ack" in hs:
                    events.append(Event(hs["syn"], "handshake", f"TCP handshake {c} → {s}",
                                        f"{f.label}, RTT {f.rtt * 1000:.1f} ms", duration=f.rtt, **common))
                elif f.state == "REFUSED":
                    events.append(Event(hs["syn"], "reset", f"Connection refused {c} → {s}", "SYN answered with RST",
                                        "warn", ports=[f.server[1]], **common))
                elif f.state != "RESET":  # a reset half-open probe is reported by the reset event
                    missing = "ACK" if "synack" in hs else "SYN-ACK"
                    events.append(Event(hs["syn"], "handshake", f"Handshake incomplete {c} → {s}",
                                        f"no {missing} seen", "warn", **common))
            if f.syn_retries:
                events.append(Event(hs.get("syn", f.first_ts), "retrans", f"SYN retransmitted ×{f.syn_retries}",
                                    f"{c} → {s} (server slow or dropping)", "warn", **common))
            for ts, state in f.history:
                if state == "RESET":
                    events.append(Event(ts, "reset", f"Connection reset {c} ↔ {s}", f"after {ts - f.first_ts:.3f}s",
                                        "warn", ports=[f.server[1]], **common))
                elif state == "CLOSED":
                    events.append(Event(ts, "close", f"Connection closed {c} ↔ {s}",
                                        f"{f.packets} pkts in {ts - f.first_ts:.3f}s", **common))
            for ev in f.events:
                if ev.note in ("retransmission", "partial retransmission", "out-of-order"):
                    who = c if ev.direction == "c2s" else s
                    events.append(Event(ev.ts, "retrans", ev.note.capitalize(), f"{who} seq={ev.seq} len={ev.length}",
                                        "warn", **common))
        if f.tls_sni:
            events.append(Event(f.tls_ts or f.first_ts, "tls", f"TLS to {f.tls_sni}", f"{c} → {s}", **common))
        pending = {}
        for d in f.dns:
            if not d["response"]:
                pending[d["id"]] = d
                continue
            q = pending.pop(d["id"], None)
            answer = ", ".join(map(str, d["answers"][:3])) or d["rcode"]
            level = "warn" if d["rcode"] != "NOERROR" else "info"
            start = q["ts"] if q else d["ts"]
            events.append(Event(start, "dns", f"DNS {d['qtype']} {d['qname']}", f"→ {answer}", level,
                                duration=(d["ts"] - q["ts"]) if q else None, **common))
        for q in pending.values():
            events.append(Event(q["ts"], "dns", f"DNS {q['qtype']} {q['qname']}", "no answer seen", "warn", **common))
        for tx in f.http:
            req, resp = tx.get("request"), tx.get("response")
            if req is None:
                continue
            target = req.get("host", "") + req["uri"] if req["uri"].startswith("/") else req["uri"]
            if resp:
                level = "bad" if resp["status"] >= 500 else "warn" if resp["status"] >= 400 else "info"
                detail = f"→ {resp['status']} {resp['reason']}, {resp.get('body_len', 0)} B"
                events.append(Event(req["ts"], "http", f"{req['method']} {target}", detail, level,
                                    duration=resp["ts"] - req["ts"], **common))
            else:
                events.append(Event(req["ts"], "http", f"{req['method']} {target}", "no response seen", "warn",
                                    **common))
    for a in an.alerts:
        if flow_id is not None and a.flow != flow_id:
            continue
        events.append(Event(a.ts, "alert", a.rule, a.message, "bad" if a.severity == "high" else "warn",
                            flow=a.flow, src=a.src, dst=a.dst))
    events = [e for e in events if e.kind in kinds]
    if host:
        events = [e for e in events if host in (e.src, e.dst)]
    events.sort(key=lambda e: (e.ts, KINDS.index(e.kind)))
    return _collapse(events) if collapse else events


def _collapse(events: list[Event]) -> list[Event]:
    """Merge bursts (a port scan's 20 refusals) into one line per source/destination pair."""
    out: list[Event] = []
    open_groups: dict[tuple, Event] = {}
    for e in events:
        if e.kind not in ("reset", "retrans"):
            out.append(e)
            continue
        key = (e.kind, e.title.split(" ")[0], e.src, e.dst)
        g = open_groups.get(key)
        if g is not None and e.ts - g.ts <= COLLAPSE_WINDOW + g.duration_span:
            g.count += 1
            g.ports.extend(e.ports)
            g.duration_span = e.ts - g.ts
            continue
        open_groups[key] = e
        out.append(e)
    for e in out:
        if e.count > 1:
            if e.kind == "reset":
                verb = "refused" if e.title.startswith("Connection refused") else "reset"
                ports = sorted(set(e.ports))
                plist = ", ".join(map(str, ports[:8])) + (f" … (+{len(ports) - 8})" if len(ports) > 8 else "")
                e.title = f"{e.count} connections {verb} {e.src} → {e.dst}"
                e.detail = f"ports {plist}" if ports else e.detail
            else:
                e.title = f"{e.title} ×{e.count}"
            e.detail += f" over {e.duration_span:.2f}s"
            e.level = "bad" if e.count >= 10 else e.level
    return out


# -- rendering ------------------------------------------------------------------
def swimlanes(events: list[Event], t0: float, t1: float, width: int = 80) -> Panel:
    """Density strip per event kind across the capture's duration."""
    span = max(t1 - t0, 1e-6)
    lanes = [k for k in KINDS if any(e.kind == k for e in events)]
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
                row.append(KIND_MARK[k] if n < 3 else "█", style=KIND_STYLE[k])
        t.add_row(Text(k, style=KIND_STYLE[k]), row, str(sum(e.count for e in events if e.kind == k)))
    return Panel(t, title="Activity by type", title_align="left", border_style="grey42")


def table(events: list[Event], t0: float) -> Table:
    t = Table(box=box.SIMPLE_HEAVY, header_style="bold", expand=True, show_edge=False)
    t.add_column("Time", justify="right", style="grey62", no_wrap=True)
    t.add_column("", no_wrap=True)
    t.add_column("Event", ratio=4, overflow="fold")
    t.add_column("Detail", ratio=3, overflow="fold")
    t.add_column("Latency", no_wrap=True)
    t.add_column("Flow", justify="right", style="grey50", no_wrap=True)
    peak = max((e.duration for e in events if e.duration), default=0) or 1
    for e in events:
        style = KIND_STYLE[e.kind]
        level = LEVEL_STYLE[e.level]
        lat = Text()
        if e.duration is not None:
            ms = e.duration * 1000
            n = max(1, round(e.duration / peak * 8))
            lat.append("▇" * n, style="red3" if ms > 500 else "yellow3" if ms > 100 else style)
            lat.append(f" {ms:.1f}ms", style="grey62")
        t.add_row(f"{e.ts - t0:.4f}", Text(f"{KIND_MARK[e.kind]} {e.kind}", style=style),
                  Text(e.title, style=level or "white"), Text(e.detail, style="grey70"), lat,
                  str(e.flow) if e.flow is not None else "")
    return t


def render(an: Analyzer, events: list[Event], width: int) -> Group:
    t0 = an.first_ts or 0.0
    t1 = an.last_ts or t0
    lane_w = max(20, min(width - 24, 120))
    if not events:
        return Group(Text("No events match.", style="grey50"))
    return Group(swimlanes(events, t0, t1, lane_w), table(events, t0))
