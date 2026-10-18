"""The capture in plain English.

``Narrator`` turns packets into a short list of grouped, readable events as
they arrive ("Living Room (10.0.0.30) is announcing itself: AirPlay, ...
x34"), so a repeated packet becomes one line with a count instead of a
screenful. ``summarize`` turns those events, the host profiles and the
alerts into a summary anyone can read.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from . import discovery, explain
from .flows import APP_BY_PORT
from .scoring import is_private

if TYPE_CHECKING:  # pragma: no cover
    from .analyzer import Analyzer

# event kind -> category; categories are listed most important first
CATEGORY = {"alert": "alert", "web": "web", "http": "web", "quic": "web", "connect": "connect", "lookup": "lookup",
            "ping": "network", "time": "network", "dhcp": "network", "arp": "network",
            "announce": "discovery", "search": "discovery"}
CATEGORY_ORDER = ("alert", "web", "connect", "lookup", "network", "discovery")
CATEGORY_LABEL = {"alert": "Warning", "web": "Web", "connect": "Connect", "lookup": "Lookup",
                  "network": "Network", "discovery": "Nearby"}
# what the bytes were, for "most of the traffic was ..."
VOLUME_LABEL = {"web-tls": "encrypted web traffic (HTTPS)", "web-http": "unencrypted web traffic (HTTP)",
                "quic": "fast encrypted web traffic (QUIC)", "dns": "name lookups (DNS)",
                "discovery": "devices announcing themselves (mDNS/SSDP)", "housekeeping": "network housekeeping "
                "(ARP, DHCP, ping, time sync)", "other": "other traffic"}
BACKGROUND_NOTE = ("Devices on a home or office network constantly announce what they are and look for each other "
                   "(mDNS/Bonjour, SSDP/UPnP, ARP). It is normal and usually not worth worrying about.")
SAMPLE_PACKETS = 12
MAX_EVENTS = 2000       # grouped lines kept; the least recently active one makes room for a new one
MAX_ITEMS = 200         # names/ports/pages remembered per line
MAX_SITES = 4096


@dataclass
class Event:
    key: tuple
    kind: str
    first_ts: float
    last_ts: float
    src: str = ""
    dst: str = ""
    count: int = 0
    packets: list = field(default_factory=list)
    items: dict = field(default_factory=dict)   # ordered set of names / services seen
    data: dict = field(default_factory=dict)
    flows: set = field(default_factory=set)

    @property
    def category(self) -> str:
        return CATEGORY[self.kind]

    @property
    def severity(self) -> str:
        return self.data.get("severity", "")


def shown_count(ev: Event) -> int:
    """The ×N worth showing: repeats of the same thing, not packets of a list that is already spelled out."""
    if ev.kind in ("lookup", "search", "arp") or (ev.kind == "connect" and len(ev.items) > 3):
        return 0
    return ev.count


def human_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} GB"  # pragma: no cover


def human_duration(s: float) -> str:
    if s < 1:
        return f"{s * 1000:.0f} ms"
    if s < 90:
        return f"{s:.0f} seconds" if s >= 2 else f"{s:.1f} seconds"
    if s < 5400:
        return f"{s / 60:.0f} minutes"
    return f"{s / 3600:.1f} hours"


def _list(items, n: int = 3) -> str:
    items = list(items)
    shown = ", ".join(items[:n])
    return shown + (f" and {len(items) - n} more" if len(items) > n else "")


def classify(pkt) -> str:
    if pkt.layer("mdns") is not None:
        return "discovery"
    if pkt.layer("dns") is not None:
        return "dns"
    tcp, udp = pkt.layer("tcp"), pkt.layer("udp")
    if tcp is not None:
        ports = {tcp["sport"], tcp["dport"]}
        if pkt.layer("tls") is not None or ports & {443, 8443}:
            return "web-tls"
        if pkt.layer("http") is not None or ports & {80, 8080}:
            return "web-http"
        port = min(ports)
        return APP_BY_PORT.get(port, "other")
    if udp is not None:
        ports = {udp["sport"], udp["dport"]}
        if 443 in ports:
            return "quic"
        if 1900 in ports:
            return "discovery"
        if ports & {67, 68, 123}:
            return "housekeeping"
        return "other"
    if pkt.layer("arp") is not None or pkt.layer("icmp") is not None or pkt.layer("icmpv6") is not None:
        return "housekeeping"
    return "other"


class Narrator:
    """Turns packets into grouped plain-English events as they are analyzed."""

    def __init__(self, an: Analyzer):
        self.an = an
        self.events: dict[tuple, Event] = {}  # least recently active first
        self.volume: Counter = Counter()      # classify() -> bytes
        self.site: dict[str, str] = {}        # server address -> the name a client asked for (SNI / Host)
        self.web_ports: dict = {}             # (client, server, port) already told as a web visit
        self._alerts_seen = 0

    # -- collecting ------------------------------------------------------------
    def _event(self, key: tuple, kind: str, pkt, src: str = "", dst: str = "", flow=None) -> Event:
        ev = self.events.pop(key, None)  # re-inserted below, so the dict stays in least-recent-first order
        if ev is None:
            self._make_room()
            ev = Event(key, kind, pkt.ts, pkt.ts, src=src, dst=dst)
        self.events[key] = ev
        ev.last_ts = pkt.ts
        if flow is not None:
            if flow.id in ev.flows:
                return ev
            ev.flows.add(flow.id)
        ev.count += 1
        if len(ev.packets) < SAMPLE_PACKETS:
            ev.packets.append(pkt.number)
        return ev

    def _make_room(self) -> None:
        """Forget the least recently active non-alert line when full, so a flood of junk (spoofed ARP,
        random names) can push out old chatter but never stops new activity from being told."""
        if len(self.events) < MAX_EVENTS:
            return
        oldest = next((k for k, e in self.events.items() if e.kind != "alert"), None)
        del self.events[oldest if oldest is not None else next(iter(self.events))]

    @staticmethod
    def _remember(mapping: dict, key, value) -> None:
        if key not in mapping and len(mapping) >= MAX_SITES:
            del mapping[next(iter(mapping))]
        mapping[key] = value

    def sync_alerts(self) -> None:
        alerts = self.an.alerts
        for a in alerts[self._alerts_seen:]:
            key = ("alert", a.rule, a.src)
            ev = self.events.get(key)
            if ev is None:
                ev = self.events[key] = Event(key, "alert", a.ts, a.ts, src=a.src, dst=a.dst,
                                              data=dict(rule=a.rule, severity=a.severity, message=a.message))
            ev.count += 1
            ev.last_ts = max(ev.last_ts, a.ts)
            if a.dst and len(ev.items) < MAX_ITEMS:
                ev.items[a.dst] = None
            if a.packet and len(ev.packets) < SAMPLE_PACKETS:
                ev.packets.append(a.packet)
        self._alerts_seen = len(alerts)

    def process(self, pkt, flow=None, disc: dict | None = None) -> None:
        self.sync_alerts()
        self.volume[classify(pkt)] += pkt.orig_len
        src, dst = pkt.src, pkt.dst
        if disc is not None:
            if "device" in disc:
                dev = disc["device"]   # one line per device, whichever of its addresses it spoke from
                ev = self._event(("announce", id(dev)), "announce", pkt)
                ev.src, ev.data["device"] = dev.addr, dev
            else:
                asks = disc["m"]["asks"] if disc["proto"] == "mdns" else ["ssdp:" + (disc["s"]["target"] or "ssdp:all")]
                if asks:
                    ev = self._event(("search", src), "search", pkt, src)
                    for a in asks[:MAX_ITEMS - len(ev.items)]:
                        ev.items[a] = None
            return
        d = pkt.layer("dns")
        if d is not None:
            if not d["response"] and d.get("qname"):
                ev = self._event(("lookup", src), "lookup", pkt, src)
                if len(ev.items) < MAX_ITEMS:
                    ev.items[d["qname"].rstrip(".")] = None
            return
        tls = pkt.layer("tls")
        if tls is not None and tls.get("sni"):
            self._remember(self.site, dst, tls["sni"])
            if pkt.layer("tcp") is not None:
                self._remember(self.web_ports, (src, dst, pkt.layer("tcp")["dport"]), None)
            self._event(("web", src, tls["sni"]), "web", pkt, src, dst, flow)
            return
        h = pkt.layer("http")
        if h is not None and h.get("method"):
            host = h.get("host") or dst
            if dst not in self.site:
                self._remember(self.site, dst, host.split(":")[0])
            if pkt.layer("tcp") is not None:
                self._remember(self.web_ports, (src, dst, pkt.layer("tcp")["dport"]), None)
            ev = self._event(("http", src, host), "http", pkt, src, dst)
            if len(ev.items) < MAX_ITEMS:
                ev.items[h.get("uri", "/")] = None
            return
        tcp, udp = pkt.layer("tcp"), pkt.layer("udp")
        if tcp is not None:
            if tcp["flags.syn"] and not tcp["flags.ack"]:
                ev = self._event(("connect", src, dst), "connect", pkt, src, dst, flow)
                if len(ev.items) < MAX_ITEMS:
                    ev.items[tcp["dport"]] = None
            return
        if udp is not None:
            if udp["dport"] == 443:
                self._event(("quic", src, dst), "quic", pkt, src, dst, flow)
            elif udp["dport"] == 123:
                self._event(("time", src, dst), "time", pkt, src, dst, flow)
            dh = pkt.layer("dhcp")
            if dh is not None:
                ev = self._event(("dhcp", dh["client_mac"], dh.get("msg_type", "?")), "dhcp", pkt, src, dst)
                ev.data.update(mac=dh["client_mac"], type=dh.get("msg_type", "?"), your_ip=dh.get("your_ip"),
                               hostname=dh.get("hostname") or ev.data.get("hostname"))
            return
        ic = pkt.layer("icmp") or pkt.layer("icmpv6")
        if ic is not None and ic.get("type") in (8, 128):
            self._event(("ping", src, dst), "ping", pkt, src, dst)
            return
        arp = pkt.layer("arp")
        if arp is not None and arp.get("op") == 1 and src != "?":
            ev = self._event(("arp", src), "arp", pkt, src)
            if len(ev.items) < MAX_ITEMS:
                ev.items[arp["target_ip"]] = None

    # -- describing ------------------------------------------------------------
    def local_name(self, ip: str) -> str:
        dev = self.an.discovery.devices.get(ip)
        if dev is not None and dev.name:
            return dev.name
        h = self.an.hosts.hosts.get(ip)
        if h is not None:
            dhcp = self.an.hosts.dhcp_names.get(h.mac)
            if dhcp and not h.routed:
                return dhcp
        return self.an.discovery.name_for(ip)

    def who(self, ip: str) -> str:
        """A local device: its announced or DHCP name plus the address."""
        if not ip:
            return "a device"
        name = self.local_name(ip)
        return f"{name} ({ip})" if name else ip

    def where(self, ip: str) -> str:
        """A remote server: the name a client used for it, else its DNS name, else the address."""
        if ip in self.site:
            return self.site[ip]
        h = self.an.hosts.hosts.get(ip)
        if h is not None and h.names:
            return next(iter(h.names))
        if is_private(ip):
            return self.who(ip)
        return ip

    def describe(self, ev: Event, short: bool = False) -> str:
        """The event as a sentence; ``short`` drops the subject for lists under that device's name."""
        text = self._describe(ev)
        who = self._subject(ev)
        if short and text.startswith(who + " "):
            text = text[len(who) + 1:]
            text = text[:1].upper() + text[1:]
        return text

    def _subject(self, ev: Event) -> str:
        dev = ev.data.get("device")
        if dev is not None:  # the announcing device itself, even if another device has used its address
            return f"{dev.name} ({dev.addr})" if dev.name else dev.addr
        return self.who(ev.src)

    def _describe(self, ev: Event) -> str:
        k = ev.kind
        who = self._subject(ev)
        if k == "alert":
            title = explain.explain(ev.data["rule"])[0]
            msg = ev.data["message"]
            if msg.lower().startswith(title.lower() + ":"):
                msg = msg[len(title) + 1:].lstrip()
            return f"{title} from {who}: {msg}" if ev.src else f"{title}: {msg}"
        if k == "web":
            return f"{who} connected securely to {ev.key[2]}"
        if k == "http":
            pages = _list(ev.items, 2)
            return f"{who} loaded {ev.key[2]} without encryption (HTTP{': ' + pages if pages else ''})"
        if k == "quic":
            return f"{who} exchanged encrypted web traffic with {self.where(ev.dst)} (QUIC)"
        if k == "connect":
            svcs = [APP_BY_PORT.get(p, f"port {p}") for p in self.ports(ev)]
            if len(svcs) > 3:
                return f"{who} tried {len(svcs)} different services on {self.where(ev.dst)}: {_list(svcs, 4)}"
            return f"{who} connected to {self.where(ev.dst)} using {_list(svcs, 3)}"
        if k == "lookup":
            n = len(ev.items)
            return f"{who} looked up {n} name{'s' if n != 1 else ''}: {_list(reversed(list(ev.items)), 4)}"
        if k == "ping":
            return f"{who} pinged {self.where(ev.dst)}"
        if k == "time":
            return f"{who} synced its clock with {self.where(ev.dst)} (NTP)"
        if k == "dhcp":
            name = ev.data.get("hostname") or ev.data.get("mac")
            t = ev.data.get("type", "")
            if t in ("DISCOVER", "REQUEST"):
                return f"{name} asked for an IP address (DHCP {t.lower()})"
            if t in ("OFFER", "ACK"):
                return f"The router {'offered' if t == 'OFFER' else 'gave'} {ev.data.get('your_ip')} to {name} (DHCP)"
            return f"DHCP {t.lower()} for {name}"
        if k == "arp":
            n = len(ev.items)
            return (f"{who} asked who has {_list(ev.items, 2)} (ARP, finding devices by address)" if n <= 3 else
                    f"{who} checked which of {n} addresses are in use (ARP)")
        if k == "announce":
            dev = ev.data["device"]
            what = dev.kind
            labels = dev.labels
            article = "an" if what[:1] in "aeioAEIO" else "a"
            head = f"{who} announced itself as {article} {what}" if what != "device" else f"{who} announced itself"
            if dev.os:
                head += f" running {dev.os}"
            return head + (f", offering {_list(labels, 4)}" if labels else "")
        if k == "search":
            wanted = []
            for item in ev.items:
                w = discovery.ssdp_target(item[5:]) if item.startswith("ssdp:") else discovery.search_meaning(item)
                if w not in wanted:
                    wanted.append(w)
            return f"{who} looked for {_list(wanted, 2)} on the local network"
        return " ".join(map(str, ev.key))  # pragma: no cover

    def meaning(self, ev: Event) -> str:
        """A sentence of context for a detail page."""
        k = ev.kind
        if k == "alert":
            return explain.explain(ev.data["rule"])[1]
        if k == "announce":
            bits = [f"It {discovery.service_meaning(s)}." for s in ev.data["device"].services if s != "_device-info"]
            return " ".join(bits[:6]) + " " + BACKGROUND_NOTE
        if k == "search":
            return ("Phones, computers and TV apps look for nearby screens, speakers and printers like this whenever "
                    "you open a share or cast menu, and often in the background. " + BACKGROUND_NOTE)
        if k == "web":
            return ("The name comes from the TLS handshake (SNI); the page contents are encrypted, so only the site "
                    "and the amount of data are visible.")
        if k == "http":
            return "HTTP is not encrypted: anyone on the network path can read and change these pages."
        if k == "quic":
            return "QUIC is the encrypted transport behind HTTP/3, used by Google, YouTube, Meta and others."
        if k == "lookup":
            return "Before connecting to a website or service, a device asks a DNS server for its address."
        if k == "arp":
            return "ARP is how devices on the same network find each other's hardware address. " + BACKGROUND_NOTE
        if k == "dhcp":
            return "DHCP is how a device joining the network gets its IP address from the router."
        if k == "time":
            return "Devices check the time with a time server regularly. This is normal."
        if k == "ping":
            return "A ping checks whether another machine is reachable."
        return ""

    def ports(self, ev: Event) -> list[int]:
        """A connection's ports, minus those already told as the web visit they led to."""
        return [p for p in ev.items if (ev.src, ev.dst, p) not in self.web_ports]

    def visible(self) -> list[Event]:
        self.sync_alerts()
        return [e for e in self.events.values() if e.kind != "connect" or self.ports(e)]

    def recent(self, n: int = 20) -> list[Event]:
        return sorted(self.visible(), key=lambda e: e.last_ts, reverse=True)[:n]

    def ordered(self) -> list[Event]:
        """Important first: alerts by severity, then web, connections, lookups, housekeeping, discovery."""
        sev = {"high": 0, "medium": 1, "low": 2}
        return sorted(self.visible(),
                      key=lambda e: (CATEGORY_ORDER.index(e.category), sev.get(e.severity, 3), -e.count, e.first_ts))


def summarize(an: Analyzer) -> dict:
    """Everything a non-expert needs: what happened, what to worry about, who did what."""
    from .hosts import profile
    an.finish()
    nar: Narrator = an.narrator
    duration = (an.last_ts - an.first_ts) if an.count else 0.0
    hosts = profile(an) if an.count else []
    local = [h for h in hosts if h.local and h.addr not in ("0.0.0.0", "?") and (h.pkts_sent or h.pkts_recv)]
    remote = [h for h in hosts if not h.local]
    headline = []
    if not an.count:
        return dict(headline=["No packets were captured."], concerns=[], devices=[], background=[], events=[],
                    nearby=[], volume=[])
    headline.append(f"This capture covers {human_duration(duration)}: {an.count:,} packets ({human_bytes(an.bytes)}) "
                    f"from {len(local)} device{'s' if len(local) != 1 else ''} on the local network"
                    + (f" talking to {len(remote)} outside address{'es' if len(remote) != 1 else ''}." if remote
                       else ", with nothing going to the internet."))
    total = sum(nar.volume.values()) or 1
    vol = [(VOLUME_LABEL.get(k, f"{k} traffic"), v * 100 / total) for k, v in nar.volume.most_common()]
    top = [f"{label[:-1]}, {pct:.0f}%)" if label.endswith(")") else f"{label} ({pct:.0f}%)"
           for label, pct in vol[:2] if pct >= 5]
    if top:
        headline.append("Most of it was " + " and ".join(top) + ".")
    groups = explain.group(an.alerts)
    concerns = []
    for g in groups:
        concerns.append(dict(severity=g["severity"], title=g["title"], count=g["count"], why=g["why"],
                             action=g["action"], who=[nar.who(s) for s in g["sources"][:3] if s],
                             example=g["examples"][0] if g["examples"] else ""))
    serious = [c for c in concerns if c["severity"] in ("high", "medium")]
    if not concerns:
        headline.append("Nothing suspicious stood out.")
    elif serious:
        c = serious[0]
        headline.append(f"{len(serious)} thing{'s' if len(serious) != 1 else ''} deserve{'' if len(serious) != 1 else 's'} "
                        f"a closer look; the most serious is {c['title'].lower()}"
                        + (f" from {c['who'][0]}." if c["who"] else "."))
    else:
        headline.append(f"Only {len(concerns)} minor oddit{'ies' if len(concerns) != 1 else 'y'} came up, nothing serious.")
    nearby = [d for d in an.discovery.ranked() if d.services or d.server]
    if nearby:
        headline.append(f"{len(nearby)} device{'s' if len(nearby) != 1 else ''} announced "
                        f"{'themselves' if len(nearby) != 1 else 'itself'} on the local network ("
                        + _list([d.title() for d in nearby], 3) + "). That chatter is normal.")

    events = nar.ordered()
    devices = []
    for h in local:
        mine = [e for e in events if e.src == h.addr and e.category != "alert"]
        if not mine and not h.rules:
            continue
        dev = an.discovery.devices.get(h.addr)
        what = dev.kind if dev is not None and dev.kind != "device" else ""
        role = ", ".join(r for r in h.roles if r not in ("passive", "client")) if h.roles else ""
        desc = " · ".join(x for x in (what, dev.os if dev else "", h.os if not (dev and dev.os) else "", role) if x)
        lines = [(e.category, nar.describe(e, short=True), shown_count(e)) for e in mine]
        if len(lines) > 8:
            extra = len(lines) - 8
            lines = lines[:8] + [("more", f"... and {extra} more kind{'s' if extra != 1 else ''} of activity", 0)]
        devices.append(dict(addr=h.addr, title=nar.who(h.addr), desc=desc, lines=lines, rules=sorted(h.rules),
                            sent=h.bytes_sent, received=h.bytes_recv,
                            weight=sum(1 for e in mine if e.category != "discovery")))
    devices.sort(key=lambda d: (-bool(d["rules"]), -d["weight"], -(d["sent"] + d["received"])))
    background = []
    n = sum(e.count for e in events if e.category == "discovery" or e.kind == "arp")
    if n:
        background.append(f"{n:,} packets were background chatter from devices finding each other "
                          "(announcements, searches and ARP), grouped into the lines above. " + BACKGROUND_NOTE)
    return dict(headline=headline, concerns=concerns, devices=devices, background=background, events=events,
                nearby=nearby, volume=vol)


def to_text(s: dict) -> str:
    """Plain text version of ``summarize`` for pipes, files and the report."""
    out = ["WHAT HAPPENED", ""] + [" ".join(s["headline"])] + [""]
    if s["concerns"]:
        out += ["WHAT TO LOOK AT", ""]
        for c in s["concerns"]:
            who = f" (from {', '.join(c['who'])})" if c["who"] else ""
            out.append(f"- [{c['severity']}] {c['title']} x{c['count']}{who}: {c['why']} {c['action']}")
        out.append("")
    if s["devices"]:
        out += ["WHO DID WHAT", ""]
        for d in s["devices"]:
            out.append(f"{d['title']}" + (f"  [{d['desc']}]" if d["desc"] else ""))
            for _cat, line, count in d["lines"]:
                out.append(f"  - {line}" + (f" (x{count})" if count > 1 else ""))
        out.append("")
    if s["nearby"]:
        out += ["DEVICES THAT ANNOUNCED THEMSELVES", ""]
        for d in s["nearby"]:
            out.append(f"- {d.title()} at {d.addr}: {', '.join(d.labels) or d.server}"
                       + (f" ({d.os})" if d.os else "") + f", {d.announcements} announcement{'s' if d.announcements != 1 else ''}")
        out.append("")
    out += s["background"]
    return "\n".join(out).rstrip() + "\n"
