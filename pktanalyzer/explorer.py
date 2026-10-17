"""Interactive, keyboard-driven explorer for a capture file.

``Explorer`` is a plain state machine: ``handle_key(name)`` changes the state
and ``render(width, height)`` draws it. ``run()`` wires it to the terminal
(raw key reading plus a full-screen rich Live), which keeps everything else
testable without a TTY.
"""
from __future__ import annotations

import os
import sys
import time
import webbrowser
from dataclasses import dataclass, field

from rich import box
from rich.console import Console, Group
from rich.panel import Panel
from rich.rule import Rule
from rich.segment import Segment
from rich.table import Table
from rich.text import Text

from . import explain, hosts as host_profiles, story, timeline as TL, ui
from .analyzer import Analyzer
from .filters import FilterError, compile_filter
from .scoring import level_for, score_flows

TABS = ("Overview", "Packets", "Conversations", "Hosts", "Alerts", "Timeline", "Hunt", "Activity")
SHORT = ("Home", "Pkts", "Convs", "Hosts", "Alerts", "Time", "Hunt", "Activity")
SORTS = ("time", "risk", "bytes")
SELECTED = "reverse"

HELP = [
    ("Move", [("↑ ↓   k j", "one row"), ("PgUp PgDn   b space", "one page"), ("g   G", "top / bottom")]),
    ("Open", [("Enter   →   l", "open the selected row"), ("Esc   ←   h", "go back"),
              ("n   p", "next / previous item in a detail")]),
    ("Views", [("1 … 8", "Home Packets Conversations Hosts Alerts Timeline Hunt Activity"), ("Tab   Shift-Tab", "next / previous")]),
    ("Find", [("/", "filter the list; packets take filters like  dns  or  tcp.port == 443"), ("c", "clear the filter")]),
    ("Act", [("f", "follow the conversation behind a packet, alert or finding"),
             ("s", "sort conversations by time, risk or bytes"), ("x", "hex dump on/off in a packet"),
             ("r", "write an HTML report and open it")]),
    ("Other", [("?", "this help"), ("q", "quit")]),
]


@dataclass
class View:
    """One open detail page (a packet, a conversation, a host, ...)."""
    kind: str
    item: object
    index: int            # position of the item in the list it was opened from
    scroll: int = 0


@dataclass
class ListState:
    cursor: int = 0
    top: int = 0
    query: str = ""
    items: list = field(default_factory=list)
    error: str = ""


class _Window:
    """Shows a slice of pre-rendered lines, which is how long pages scroll."""

    def __init__(self, lines: list, start: int, height: int):
        self.lines, self.start, self.height = lines, start, height

    def __rich_console__(self, console, options):
        for line in self.lines[self.start:self.start + self.height]:
            yield from line
            yield Segment.line()


class Explorer:
    def __init__(self, an: Analyzer, source: str, console: Console | None = None):
        self.an = an
        self.source = source
        self.console = console or ui.console
        an.finish()
        score_flows(an)
        self.t0 = an.first_ts or 0.0
        self.t1 = an.last_ts or 0.0
        self.packets = list(an.packets)
        self.flows = list(an.flows)
        self.hosts = host_profiles.profile(an)
        self.alerts = sorted(an.alerts, key=lambda a: (a.ts, a.rule))
        self.events = TL.build(an)
        self.findings = list(an.findings or [])
        self.nar = an.narrator
        self.story = story.summarize(an)
        self.activity = self.story["events"]
        self.tab = 0
        self.lists = {name: ListState() for name in TABS}
        self.sort = 0
        self.stack: list[View] = []
        self.show_help = False
        self.show_hex = True
        self.typing: str | None = None     # filter being typed, or None
        self.message = ""
        self.page = 20                     # rows per page, updated on every render
        self.overview_scroll = 0
        self.help_view = View("help", None, -1)
        self._cache: dict = {}
        for name in TABS[1:]:
            self._refilter(name)

    # -- data per tab ----------------------------------------------------------
    def _source(self, name: str) -> list:
        if name == "Packets":
            return self.packets
        if name == "Conversations":
            key = SORTS[self.sort]
            if key == "risk":
                return sorted(self.flows, key=lambda f: (-f.risk.score, f.first_ts))
            if key == "bytes":
                return sorted(self.flows, key=lambda f: -f.bytes)
            return self.flows
        return {"Hosts": self.hosts, "Alerts": self.alerts, "Timeline": self.events, "Hunt": self.findings,
                "Activity": self.activity}[name]

    def _search_text(self, name: str, item) -> str:
        if name == "Conversations":
            return f"{item.key_str} {item.label} {item.state} {item.tls_sni or ''}"
        if name == "Hosts":
            return f"{item.addr} {item.name} {' '.join(item.names)} {item.mac} {' '.join(item.roles)} {item.os}"
        if name == "Alerts":
            return f"{item.rule} {item.severity} {item.src} {item.dst} {item.message}"
        if name == "Timeline":
            return f"{item.kind} {item.title} {item.detail} {item.src} {item.dst}"
        if name == "Hunt":
            return f"{item.kind} {item.client} {item.target} {item.summary}"
        if name == "Activity":
            return f"{item.kind} {item.category} {self.nar.describe(item)} {' '.join(map(str, item.items))}"
        return ""

    def _refilter(self, name: str) -> None:
        st = self.lists[name]
        items = self._source(name)
        st.error = ""
        if st.query:
            if name == "Packets":
                try:
                    pred = compile_filter(st.query)
                    items = [p for p in items if pred(p)]
                except FilterError as e:
                    st.error = str(e)
            else:
                q = st.query.lower()
                items = [x for x in items if q in self._search_text(name, x).lower()]
        st.items = items
        st.cursor = min(st.cursor, max(0, len(items) - 1))
        st.top = min(st.top, st.cursor)

    @property
    def tab_name(self) -> str:
        return TABS[self.tab]

    @property
    def state(self) -> ListState:
        return self.lists[self.tab_name]

    def selected(self):
        st = self.state
        return st.items[st.cursor] if st.items else None

    # -- keys -------------------------------------------------------------------
    def handle_key(self, key: str) -> bool:
        """Apply one key press. Returns False when the user quits."""
        self.message = ""
        if self.typing is not None:
            self._type(key)
            return True
        if self.show_help:
            hv = self.help_view
            if key in ("down", "j", "pgdn", " "):
                hv.scroll += 1 if key in ("down", "j") else self.page
            elif key in ("up", "k", "pgup", "b"):
                hv.scroll = max(0, hv.scroll - (1 if key in ("up", "k") else self.page))
            else:
                self.show_help = False
            return True
        if key == "q":
            return False
        if key == "?":
            self.show_help = True
            self.help_view.scroll = 0
        elif key in "12345678" and len(key) == 1:
            self._switch(int(key) - 1)
        elif key == "tab":
            self._switch((self.tab + 1) % len(TABS))
        elif key == "btab":
            self._switch((self.tab - 1) % len(TABS))
        elif key == "r":
            self._report()
        elif key == "/" and self.tab_name != "Overview":
            self.stack.clear()  # filtering applies to the list, so leave any open detail
            self.typing = ""
        elif self.stack:
            self._detail_key(key)
        else:
            self._list_key(key)
        return True

    def _switch(self, tab: int) -> None:
        self.tab = tab
        self.stack.clear()

    def _type(self, key: str) -> None:
        if key == "esc":
            self.typing = None
        elif key == "enter":
            st = self.state
            previous = st.query
            st.query = self.typing.strip()
            self.typing = None
            st.cursor = st.top = 0
            self._refilter(self.tab_name)
            if st.error:
                error = st.error
                st.query = previous  # keep showing what worked before
                self._refilter(self.tab_name)
                self.message = f"Filter error: {error}"
            elif st.query:
                self.message = f"{len(st.items)} match{'es' if len(st.items) != 1 else ''} for “{st.query}”"
        elif key == "backspace":
            self.typing = self.typing[:-1]
        elif len(key) == 1 and key.isprintable():
            self.typing += key

    def _move(self, delta: int) -> None:
        st = self.state
        if not st.items:
            return
        st.cursor = max(0, min(len(st.items) - 1, st.cursor + delta))

    def _list_key(self, key: str) -> None:
        if self.tab_name == "Overview":
            if key in ("down", "j"):
                self.overview_scroll += 1
            elif key in ("up", "k"):
                self.overview_scroll = max(0, self.overview_scroll - 1)
            elif key in ("pgdn", " "):
                self.overview_scroll += self.page
            elif key in ("pgup", "b"):
                self.overview_scroll = max(0, self.overview_scroll - self.page)
            elif key in ("g", "home"):
                self.overview_scroll = 0
            elif key in ("enter", "right", "l"):
                self._switch(4 if self.alerts else 2)
            return
        st = self.state
        moves = {"down": 1, "j": 1, "up": -1, "k": -1, "pgdn": self.page, " ": self.page, "pgup": -self.page,
                 "b": -self.page}
        if key in moves:
            self._move(moves[key])
        elif key in ("g", "home"):
            st.cursor = 0
        elif key in ("G", "end"):
            st.cursor = max(0, len(st.items) - 1)
        elif key in ("enter", "right", "l"):
            item = self.selected()
            if item is not None:
                self._open(self._kind_for(self.tab_name), item, st.cursor)
        elif key == "/":
            self.typing = ""
        elif key == "c":
            st.query = ""
            self._refilter(self.tab_name)
            self.message = "Filter cleared"
        elif key == "s" and self.tab_name == "Conversations":
            self.sort = (self.sort + 1) % len(SORTS)
            self._refilter("Conversations")
            self.message = f"Sorted by {SORTS[self.sort]}"
        elif key == "f":
            self._follow(self.selected())
        elif key in ("esc", "left", "h") and st.query:
            st.query = ""
            self._refilter(self.tab_name)

    def _kind_for(self, tab: str) -> str:
        return {"Packets": "packet", "Conversations": "flow", "Hosts": "host", "Alerts": "alert",
                "Timeline": "event", "Hunt": "finding", "Activity": "story"}[tab]

    def _open(self, kind: str, item, index: int) -> None:
        if kind == "event":  # timeline events open the conversation they belong to
            flow = self.an.tracker.by_id.get(item.flow) if item.flow is not None else None
            if flow is not None:
                kind, item = "flow", flow
            else:
                alert = next((a for a in self.alerts if a.ts == item.ts and a.rule == item.title), None)
                if alert is None:
                    self.message = "This event has no conversation to open"
                    return
                kind, item = "alert", alert
        self.stack.append(View(kind, item, index))

    def _flow_of(self, item):
        flow_id = getattr(item, "flow_id", None) or getattr(item, "flow", None)
        if flow_id is None and getattr(item, "flows", None):
            flow_id = sorted(item.flows)[0]
        return self.an.tracker.by_id.get(flow_id) if isinstance(flow_id, int) else None

    def _follow(self, item) -> None:
        flow = self._flow_of(item)
        if flow is None:
            self.message = "Nothing to follow here"
            return
        self.stack.append(View("flow", flow, -1))

    def _detail_key(self, key: str) -> None:
        view = self.stack[-1]
        if key in ("esc", "left", "h", "backspace"):
            self.stack.pop()
        elif key in ("down", "j"):
            view.scroll += 1
        elif key in ("up", "k"):
            view.scroll = max(0, view.scroll - 1)
        elif key in ("pgdn", " "):
            view.scroll += self.page
        elif key in ("pgup", "b"):
            view.scroll = max(0, view.scroll - self.page)
        elif key in ("g", "home"):
            view.scroll = 0
        elif key in ("G", "end"):
            view.scroll = 10 ** 9
        elif key == "x" and view.kind == "packet":
            self.show_hex = not self.show_hex
        elif key in ("n", "p") and view.index >= 0 and len(self.stack) == 1:
            st = self.state
            new = view.index + (1 if key == "n" else -1)
            if 0 <= new < len(st.items):
                st.cursor = new
                self.stack[-1] = View(self._kind_for(self.tab_name), st.items[new], new)
                if self.stack[-1].kind == "event":
                    self.stack.pop()
                    self._open("event", st.items[new], new)
        elif key == "f":
            if view.kind == "packet":
                self._follow(view.item)
            elif view.kind == "alert":
                self._follow(view.item)
            elif view.kind == "finding":
                self._follow(view.item)
        elif key in ("enter", "right", "l") and view.kind == "alert":
            self._follow(view.item)
        elif key in ("enter", "right", "l") and view.kind == "story":
            pkt = self._packet(view.item.packets[0]) if view.item.packets else None
            if pkt is None:
                self.message = "That packet is no longer in memory"
            else:
                self.stack.append(View("packet", pkt, -1))

    def _packet(self, number: int):
        i = number - self.packets[0].number if self.packets else -1
        if 0 <= i < len(self.packets) and self.packets[i].number == number:
            return self.packets[i]
        return next((p for p in self.packets if p.number == number), None)

    def _report(self) -> None:
        from .report import write_report
        name = os.path.splitext(os.path.basename(self.source))[0] or "capture"
        path = os.path.abspath(f"report-{name}.html")
        try:
            write_report(self.an, self.source, path)
        except OSError as e:
            self.message = f"Could not write the report: {e}"
            return
        opened = False
        try:
            opened = webbrowser.open(f"file://{path}")
        except Exception:
            pass
        self.message = f"Report written to {path}" + (" and opened in your browser" if opened else "")

    # -- rendering --------------------------------------------------------------
    def render(self, width: int, height: int):
        body_h = max(3, height - 3)
        self.page = max(1, body_h - 2)
        parts = [self._tabs(width)]
        if self.show_help:
            body = self._scrolled(("help", width), self._help, width, body_h, view=self.help_view)
        elif self.stack:
            body = self._detail(width, body_h)
        elif self.tab_name == "Overview":
            body = self._scrolled(("overview", width), self._overview, width, body_h)
        else:
            body = self._list(width, body_h)
        parts.append(body)
        lines = self.console.render_lines(Group(*parts), self.console.options.update(width=width, height=None),
                                          pad=True)
        lines = lines[:height - 2]
        lines += [[Segment(" " * width)]] * (height - 2 - len(lines))
        status, footer = self._status(width), self._footer(width)
        status.truncate(width, overflow="ellipsis")
        footer.truncate(width, overflow="ellipsis")
        return Group(_Window(lines, 0, len(lines)), status, footer)

    def _tabs(self, width: int) -> Text:
        counts = {"Packets": len(self.packets), "Conversations": len(self.flows), "Hosts": len(self.hosts),
                  "Alerts": len(self.alerts), "Hunt": len(self.findings), "Activity": len(self.activity)}
        for names, with_counts, show_file in ((TABS, True, True), (TABS, True, False), (SHORT, True, False),
                                              (SHORT, False, False)):
            t = Text(no_wrap=True, overflow="ellipsis")
            t.append(" pktanalyzer ", style="bold black on cyan")
            if show_file:
                t.append(f" {os.path.basename(self.source)} ", style="bold")
            for i, name in enumerate(TABS):
                count = counts.get(name) if with_counts else None
                label = f" {i + 1} {names[i]}" + (f" {count}" if count is not None else "") + " "
                if i == self.tab:
                    t.append(label, style="bold reverse")
                else:
                    t.append(label, style="bold red" if name in ("Alerts", "Hunt") and counts.get(name) else "")
            if t.cell_len <= width:
                return t
        return t

    def _status(self, width: int) -> Text:
        t = Text(no_wrap=True, overflow="ellipsis")
        if self.typing is not None:
            hint = "display filter, e.g.  dns  or  ip.src == 10.0.0.66  or  tcp.port == 443" \
                if self.tab_name == "Packets" else "text to search for"
            t.append(" Filter: ", style="bold black on yellow")
            t.append(" " + self.typing, style="bold")
            t.append("█", style="blink")
            t.append(f"   {hint}  ·  Enter apply  Esc cancel", style="grey50")
        elif self.message:
            style = "bold red" if self.message.startswith(("Filter error", "Could not")) else "green3"
            t.append(" " + self.message, style=style)
        elif self.stack:
            crumbs = [self.tab_name] + [self._crumb(v) for v in self.stack]
            t.append(" " + "  ›  ".join(crumbs), style="grey62")
        elif self.tab_name != "Overview":
            st = self.state
            if st.query:
                t.append(f" filter: {st.query}", style="yellow3")
                t.append(f"  ({len(st.items)} of {len(self._source(self.tab_name))})  c clears", style="grey50")
        return t

    @staticmethod
    def _crumb(v: View) -> str:
        item = v.item
        return {"packet": lambda: f"packet #{item.number}", "flow": lambda: f"conversation {item.id}",
                "host": lambda: f"host {item.addr}", "alert": lambda: f"alert {item.rule}",
                "finding": lambda: f"{item.kind} {item.client}",
                "story": lambda: f"{item.category} {item.src}"}.get(v.kind, lambda: v.kind)()

    def _footer(self, width: int) -> Text:
        if self.typing is not None:
            keys = [("Enter", "apply"), ("Esc", "cancel")]
        elif self.show_help:
            keys = [("↑↓", "scroll"), ("any other key", "close help")]
        elif self.stack:
            kind = self.stack[-1].kind
            keys = [("↑↓", "scroll"), ("Esc", "back")]
            if self.stack[-1].index >= 0 and len(self.stack) == 1:
                keys.append(("n/p", "next/prev"))
            if kind in ("packet", "alert", "finding") and self._flow_of(self.stack[-1].item) is not None:
                keys.append(("f", "follow conversation"))
            if kind == "packet":
                keys.append(("x", "hex on/off"))
            if kind == "story" and self.stack[-1].item.packets:
                keys.append(("Enter", "first packet"))
            keys += [("?", "help"), ("q", "quit")]
        elif self.tab_name == "Overview":
            keys = [("1-8", "views"), ("Enter", "see the alerts"), ("↑↓", "scroll"), ("r", "HTML report"),
                    ("?", "help"), ("q", "quit")]
        else:
            keys = [("↑↓", "move"), ("Enter", "open"), ("/", "filter"), ("Tab", "next view")]
            if self.tab_name == "Conversations":
                keys.append(("s", f"sort: {SORTS[self.sort]}"))
            if self.tab_name in ("Packets", "Alerts", "Timeline", "Hunt", "Activity"):
                keys.append(("f", "follow"))
            keys += [("r", "report"), ("?", "help"), ("q", "quit")]
        t = Text(no_wrap=True, overflow="ellipsis")
        for k, label in keys:
            t.append(f" {k} ", style="bold black on grey70")
            t.append(f" {label}  ")
        return t

    # list views
    def _list(self, width: int, height: int):
        st = self.state
        rows = max(1, height - 1)
        if st.cursor < st.top:
            st.top = st.cursor
        elif st.cursor >= st.top + rows:
            st.top = st.cursor - rows + 1
        header, row = self._row_fn(self.tab_name, width)
        out = [Text(header, style="bold underline", no_wrap=True, overflow="ellipsis")]
        if not st.items:
            msg = "No matches. Press c to clear the filter." if st.query else {
                "Alerts": "No alerts: nothing suspicious was detected.",
                "Hunt": "No beaconing or exfiltration patterns found.",
            }.get(self.tab_name, "Nothing to show.")
            out.append(Text(msg, style="grey50"))
            return Group(*out)
        for i in range(st.top, min(len(st.items), st.top + rows)):
            line = row(st.items[i])
            line.no_wrap, line.overflow = True, "ellipsis"
            line.truncate(width, pad=True)
            if i == st.cursor:
                line.stylize(SELECTED)
            out.append(line)
        return Group(*out)

    def _row_fn(self, tab: str, width: int):
        t0 = self.t0
        if tab == "Packets":
            addr = 22 if width >= 120 else 17 if width >= 100 else 15
            widths = (6, addr, max(20, width - (6 + 1 + 11 + 1 + addr * 2 + 2 + 7 + 6 + 2) - 1))
            header = f"{'No.':>6} {'Time':<11} {'Source':<{addr}} {'Destination':<{addr}} {'Proto':<7}{'Len':>6}  Info"

            def row(p):
                line = ui.packet_line(p, t0, widths)
                if p.alerts:
                    a = p.alerts[0]
                    line.append(f"  {ui.SEV_ICON[a.severity]} {a.rule}", style=ui.SEV_STYLE[a.severity])
                return line
            return header, row
        if tab == "Conversations":
            ep = 22 if width >= 110 else 18
            header = (f"{'#':>4}  {'Client':<{ep}} {'Server':<{ep}} {'App':<8}{'State':<12}{'Pkts':>6}{'Bytes':>10}"
                      f"{'RTT':>9}  Risk  Notes")

            def row(f):
                c, s = f"{f.client[0]}:{f.client[1]}", f"{f.server[0]}:{f.server[1]}"
                rtt = f"{f.rtt * 1000:.1f}ms" if f.rtt is not None else ""
                t = Text(f"{f.id:>4}  {ui._cell(c, ep)} {ui._cell(s, ep)} {f.label[:7]:<8}{f.state[:11]:<12}"
                         f"{f.packets:>6}{ui.human_bytes(f.bytes):>10}{rtt:>9}  ")
                r = f.risk
                t.append(f"{r.score if r.score else '·':>4}", style=ui.RISK_STYLE[r.level])
                note = f.tls_sni or (r.reasons[0].rsplit(' (+', 1)[0] if r.reasons else "")
                t.append(f"  {note}", style="grey62")
                return t
            return header, row
        if tab == "Hosts":
            aw, nw, rw = (26, 28, 30) if width >= 130 else (17, 25, 24)
            header = f"{'Host':<{aw}}{'Name':<{nw}}{'Role':<{rw}}{'Open ports':<13}{'Alerts':<10}Risk"

            def row(h):
                roles = ", ".join(h.roles)
                t = Text(f"{ui._cell(h.addr, aw - 1)} {ui._cell(h.name, nw - 1)} ", style="bold" if h.local else "")
                t.append(f"{ui._cell(roles, rw - 1)} ", style="red3" if "scanner" in h.roles else "cyan")
                t.append(f"{ui._cell(', '.join(map(str, h.open_ports[:5])), 12)} ", style="green3")
                al = ui._alert_text(h.alerts_caused)
                al.truncate(9, pad=True)
                t.append(al)
                t.append(" ")
                t.append(f"{h.max_risk or '':>4}", style=ui.RISK_STYLE[level_for(h.max_risk)])
                return t
            return header, row
        if tab == "Alerts":
            header = f"{'Sev':<9}{'Time':>9}  {'Rule':<24}{'Source':<20}Message"

            def row(a):
                t = Text(f"{ui.SEV_ICON[a.severity]} {a.severity:<7}", style=ui.SEV_STYLE[a.severity])
                t.append(f"{a.ts - t0:>9.3f}  ", style="grey62")
                t.append(f"{a.rule[:23]:<24}", style="bold")
                t.append(f"{a.src[:19]:<20}{a.message}")
                return t
            return header, row
        if tab == "Timeline":
            header = f"{'Time':>10}  {'Kind':<12}{'Event':<52}Detail"

            def row(e):
                t = Text(f"{e.ts - t0:>10.3f}  ", style="grey62")
                t.append(f"{TL.KIND_MARK[e.kind]} {e.kind:<10}", style=TL.KIND_STYLE[e.kind])
                t.append(f"{e.title[:51]:<52}", style=TL.LEVEL_STYLE[e.level] or "")
                t.append(e.detail, style="grey62")
                return t
            return header, row
        if tab == "Activity":
            header = f"{'Time':>9}  {'Kind':<10}What happened"

            def row(e):
                t = Text(f"{e.first_ts - t0:>9.2f}  ", style="grey62")
                t.append_text(ui.story_line(self.nar, e, width - 11))
                return t
            return header, row
        header = f"{'Sev':<9}{'Score':>6}  {'Kind':<18}Summary"

        def row(x):
            t = Text(f"{ui.SEV_ICON[x.severity]} {x.severity:<7}", style=ui.SEV_STYLE[x.severity])
            t.append(f"{x.score:>6}  {ui.HUNT_TITLE.get(x.kind, x.kind):<18}", style="bold")
            t.append(x.summary)
            return t
        return header, row

    # pages
    def _scrolled(self, key, build, width: int, height: int, view=None):
        if key not in self._cache:
            if len(self._cache) > 64:
                self._cache.clear()
            self._cache[key] = self.console.render_lines(build(width), self.console.options.update(width=width),
                                                         pad=False)
        lines = self._cache[key]
        holder = view if view is not None else self
        attr = "scroll" if view is not None else "overview_scroll"
        top = max(0, min(getattr(holder, attr), len(lines) - height))
        setattr(holder, attr, top)
        return _Window(lines, top, height)

    def _detail(self, width: int, height: int):
        view = self.stack[-1]
        key = (view.kind, id(view.item), width, self.show_hex)
        return self._scrolled(key, lambda w: self._page(view, w), width, height, view=view)

    def _page(self, view: View, width: int):
        kind, item = view.kind, view.item
        if kind == "packet":
            parts = [ui.packet_detail(item, show_hex=self.show_hex)]
            for a in item.alerts:
                title, why, action = explain.explain(a.rule)
                parts.append(Text.assemble((f"{ui.SEV_ICON[a.severity]} {title}: ", ui.SEV_STYLE[a.severity]),
                                           (a.message + "\n", ""), ("  What to do: ", "grey62"), (action, "green3")))
            mdns = item.layer("mdns")
            if mdns is not None:
                parts.insert(0, ui.mdns_panel(mdns.fields))
            if item.flow_id is not None:
                parts.append(Text(f"Part of conversation {item.flow_id}: press f to follow it.", style="grey62"))
            return Group(*parts)
        if kind == "flow":
            return self._flow_page(item, width)
        if kind == "host":
            related = [f for f in self.flows if item.addr in (f.client[0], f.server[0])]
            parts = [ui.host_panel(item, self.t0)]
            if related:
                parts.append(ui.flows_table(related, limit=25, title=f"Conversations of {item.addr}"))
            return Group(*parts)
        if kind == "alert":
            title, why, action = explain.explain(item.rule)
            body = Table.grid(padding=(0, 2))
            body.add_column(style="grey62", no_wrap=True)
            body.add_column()
            body.add_row("What happened", item.message)
            body.add_row("When", f"{item.ts - self.t0:.3f}s into the capture")
            body.add_row("From → to", f"{item.src} → {item.dst}")
            body.add_row("Why it matters", why)
            body.add_row("What to do", Text(action, style="green3"))
            if item.flow is not None:
                body.add_row("Conversation", Text(f"{item.flow}  (press Enter or f to follow it)", style="cyan"))
            sev = ui.SEV_STYLE[item.severity]
            return Panel(body, title=Text(f"{ui.SEV_ICON[item.severity]} {title}", style=sev), title_align="left",
                         border_style=sev.replace("bold ", ""))
        if kind == "finding":
            parts = [ui.hunt_view([item], self.t0, self.t1, width)]
            related = [self.an.tracker.by_id[i] for i in item.flows if i in self.an.tracker.by_id]
            if related:
                parts.append(ui.flows_table(related, limit=25, title="Conversations involved (f follows the first)"))
            return Group(*parts)
        if kind == "story":
            return ui.story_page(self.nar, item, self.t0)
        return Text(str(item))

    def _flow_page(self, flow, width: int):
        parts = []
        if flow.proto == "tcp":
            parts.append(ui.handshake_panel(flow))
        r = flow.risk
        if flow.proto != "tcp" and r is not None and r.reasons:  # the TCP panel already shows the risk
            parts.append(Text.assemble(("Risk ", "grey62"), (f"{r.score}/100 {r.level}", ui.RISK_STYLE[r.level]),
                                       ("  " + "; ".join(r.reasons), "")))
        parts.append(Rule(f"Conversation ladder · flow {flow.id}", style="grey42"))
        parts.append(ui.ladder(flow, width=width, limit=200))
        if flow.tls:
            parts.append(ui.cert_panel(flow))
        if flow.http:
            parts.append(ui.http_table([flow]))
        if flow.dns:
            parts.append(ui.dns_table([flow]))
        if flow.proto == "tcp":
            parts += [Rule("Reassembled stream", style="grey42"), ui.stream_view(flow, max_bytes=6000)]
        return Group(*parts)

    def _overview(self, width: int):
        an = self.an
        sev = {s: sum(1 for a in self.alerts if a.severity == s) for s in ("high", "medium", "low")}
        parts = [Panel(Text(" ".join(self.story["headline"])), title="[bold]In plain English[/]", title_align="left",
                       border_style="cyan", box=box.ROUNDED), ui.summary_panel(an, self.source)]
        if self.alerts or self.findings:
            verdict = Text("What stands out\n", style="bold")
            groups = explain.group(self.alerts)
            for g in groups[:6]:
                verdict.append(f"  {ui.SEV_ICON[g['severity']]} ", style=ui.SEV_STYLE[g["severity"]])
                verdict.append(f"{g['title']}", style="bold")
                who = ", ".join(g["sources"][:2])
                verdict.append(f"  ×{g['count']}  from {who}\n", style="grey62")
            if len(groups) > 6:
                verdict.append(f"  … and {len(groups) - 6} more kinds of alert\n", style="grey62")
            risky = [f for f in sorted(self.flows, key=lambda f: -f.risk.score) if f.risk.score >= 40][:3]
            for f in risky:
                verdict.append(f"  Risky conversation {f.id}: {f.key_str} scored {f.risk.score}/100\n",
                               style=ui.RISK_STYLE[f.risk.level])
            border = "red3" if sev["high"] else "dark_orange"
            parts.append(Panel(verdict, border_style=border, title=f"{sev['high']} high · {sev['medium']} medium · "
                               f"{sev['low']} low alerts", title_align="left"))
        else:
            parts.append(Panel(Text("Nothing suspicious was detected in this capture.", style="green3"),
                               border_style="green3"))
        tips = Table.grid(padding=(0, 2))
        tips.add_column(style="bold cyan", no_wrap=True)
        tips.add_column()
        for k, v in (("8", "everything that happened, as plain sentences with repeats grouped"),
                     ("5  or  Enter", "see every alert with what it means and what to do"),
                     ("2", "browse packets; Enter opens one with its layers and hex dump"),
                     ("3", "conversations; Enter shows the ladder diagram and the reassembled data"),
                     ("4", "who is on the network: roles, open ports, DNS lookups"),
                     ("6  /  7", "everything on one timeline / beaconing and data exfiltration"),
                     ("/", "filter any list, e.g.  dns  or  tcp.port == 443  on the packets view"),
                     ("r", "write a shareable HTML report and open it"),
                     ("?", "all keyboard shortcuts")):
            tips.add_row(k, v)
        parts.append(Panel(tips, title="Where to go next", title_align="left", border_style="cyan", box=box.ROUNDED))
        parts.append(ui.protocol_hierarchy(an))
        return Group(*parts)

    def _help(self, width: int = 0):
        def block(sections):
            t = Table(box=None, show_header=False, expand=True, padding=(0, 1))
            t.add_column(style="bold cyan", no_wrap=True)
            t.add_column()
            for i, (section, rows) in enumerate(sections):
                if i:
                    t.add_row("", "")
                t.add_row(Text(section, style="bold underline"), "")
                for k, v in rows:
                    t.add_row(k, v)
            return t
        if width >= 100:
            body = Table.grid(expand=True, padding=(0, 3))
            body.add_column(ratio=1)
            body.add_column(ratio=1)
            body.add_row(block(HELP[:3]), block(HELP[3:]))
        else:
            body = block(HELP)
        return Panel(body, title="Keyboard shortcuts", subtitle="press ? or Esc to close", border_style="cyan",
                     box=box.ROUNDED)


# -- terminal I/O ------------------------------------------------------------------
ESCAPES = {"[A": "up", "[B": "down", "[C": "right", "[D": "left", "[5~": "pgup", "[6~": "pgdn", "[H": "home",
           "[F": "end", "[1~": "home", "[4~": "end", "[7~": "home", "[8~": "end", "[Z": "btab", "OA": "up",
           "OB": "down", "OC": "right", "OD": "left", "OH": "home", "OF": "end", "[3~": "delete"}
WIN_KEYS = {"H": "up", "P": "down", "K": "left", "M": "right", "I": "pgup", "Q": "pgdn", "G": "home", "O": "end"}


def decode_keys(data: str) -> list[str]:
    """Turn raw terminal input into key names (``up``, ``enter``, ``q`` ...)."""
    keys, i = [], 0
    while i < len(data):
        ch = data[i]
        if ch == "\x1b":
            if i + 1 >= len(data):
                keys.append("esc")
                i += 1
                continue
            for seq, name in sorted(ESCAPES.items(), key=lambda kv: -len(kv[0])):
                if data.startswith(seq, i + 1):
                    keys.append(name)
                    i += 1 + len(seq)
                    break
            else:
                keys.append("esc")
                i += 1
            continue
        keys.append({"\r": "enter", "\n": "enter", "\t": "tab", "\x7f": "backspace", "\x08": "backspace",
                     "\x03": "q"}.get(ch, ch))
        i += 1
    return keys


class KeyReader:
    """Reads key presses without waiting for Enter (POSIX terminals and Windows consoles)."""

    def __init__(self):
        self.windows = os.name == "nt"
        self._saved = None

    def __enter__(self):
        if not self.windows:
            import termios
            import tty
            fd = sys.stdin.fileno()
            self._saved = termios.tcgetattr(fd)
            tty.setcbreak(fd)
        return self

    def __exit__(self, *exc):
        if self._saved is not None:
            import termios
            termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, self._saved)

    def read(self, timeout: float = 0.25) -> list[str]:
        if self.windows:
            import msvcrt
            end = time.time() + timeout
            while time.time() < end:
                if msvcrt.kbhit():
                    ch = msvcrt.getwch()
                    if ch in ("\x00", "\xe0"):
                        return [WIN_KEYS.get(msvcrt.getwch(), "")]
                    return decode_keys(ch)
                time.sleep(0.02)
            return []
        import select
        fd = sys.stdin.fileno()
        ready, _, _ = select.select([fd], [], [], timeout)
        if not ready:
            return []
        data = os.read(fd, 1024)
        # an escape sequence can arrive split across reads
        while data.endswith(b"\x1b") or (data[-2:-1] == b"\x1b") or data.endswith(b"\x1b["):
            more, _, _ = select.select([fd], [], [], 0.03)
            if not more:
                break
            data += os.read(fd, 1024)
        return decode_keys(data.decode("utf-8", "replace"))


def run(an: Analyzer, source: str, console: Console | None = None) -> None:
    from rich.live import Live
    con = console or ui.console
    ex = Explorer(an, source, con)
    size = None
    with KeyReader() as keys, Live(console=con, screen=True, auto_refresh=False, transient=True) as live:
        while True:
            now = (con.size.width, con.size.height)
            if now != size:
                size = now
                live.update(ex.render(*size), refresh=True)
            pressed = keys.read()
            if not pressed:
                continue
            for k in pressed:
                if not ex.handle_key(k):
                    return
            live.update(ex.render(con.size.width, con.size.height), refresh=True)
