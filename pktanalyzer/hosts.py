"""Host profiling: what every address on the wire is, does and talks to.

Cheap facts are collected per packet (MAC addresses, TTLs, SYN fingerprints,
names learned from DHCP and DNS answers). The rest comes from the analyzed
flows afterwards: services a host offers and uses, domains it looked up, TLS
names and User-Agents, peers, alerts and the riskiest conversation it was in.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field

from .flows import APP_BY_PORT
from .packet import Packet
from .scoring import SCANNER_RULES, is_private

LIST_CAP = 200  # bound per-host sets so a long live capture can't grow without limit
BROADCAST_MACS = {"ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"}


@dataclass
class Host:
    addr: str
    first_ts: float = 0.0
    last_ts: float = 0.0
    pkts_sent: int = 0
    pkts_recv: int = 0
    bytes_sent: int = 0
    bytes_recv: int = 0
    macs: Counter = field(default_factory=Counter)
    ttls: Counter = field(default_factory=Counter)
    syn: dict | None = None                # first SYN's window/options, for the OS guess
    names: dict = field(default_factory=dict)   # name -> where it came from (dhcp, dns, sni, http)
    # filled in by profile()
    os: str = ""
    roles: list = field(default_factory=list)
    services: dict = field(default_factory=dict)       # port/proto -> {label, clients, flows, bytes}
    closed_ports: set = field(default_factory=set)
    uses: Counter = field(default_factory=Counter)     # service label -> connections made as a client
    peers: Counter = field(default_factory=Counter)    # peer address -> bytes exchanged
    domains: Counter = field(default_factory=Counter)  # DNS names this host looked up
    nxdomains: int = 0
    sni: Counter = field(default_factory=Counter)
    user_agents: Counter = field(default_factory=Counter)
    http_hosts: Counter = field(default_factory=Counter)
    alerts_caused: Counter = field(default_factory=Counter)   # severity -> count
    alerts_targeted: Counter = field(default_factory=Counter)
    rules: set = field(default_factory=set)
    max_risk: int = 0
    flows_out: int = 0
    flows_in: int = 0
    routed: bool = False   # frames arrive from a router's MAC, so the MAC isn't this host's own

    @property
    def local(self) -> bool:
        return is_private(self.addr)

    @property
    def mac(self) -> str:
        return self.macs.most_common(1)[0][0] if self.macs else ""

    @property
    def name(self) -> str:
        for source in ("dhcp", "dns", "sni", "http"):
            for n, s in self.names.items():
                if s == source:
                    return n
        return ""

    @property
    def open_ports(self) -> list[int]:
        return sorted({int(k.split("/")[0]) for k in self.services})

    def to_dict(self) -> dict:
        return dict(addr=self.addr, name=self.name, names=self.names, mac=self.mac, routed=self.routed, macs=dict(self.macs),
                    local=self.local, os=self.os, roles=self.roles, first_ts=self.first_ts, last_ts=self.last_ts,
                    packets_sent=self.pkts_sent, packets_received=self.pkts_recv, bytes_sent=self.bytes_sent,
                    bytes_received=self.bytes_recv,
                    services=[dict(port=k, **{**v, "clients": sorted(v["clients"])}) for k, v in self.services.items()],
                    closed_ports=sorted(self.closed_ports), uses=dict(self.uses.most_common()),
                    peers=dict(self.peers.most_common(20)), domains=dict(self.domains.most_common()),
                    nxdomains=self.nxdomains, tls_sni=dict(self.sni), user_agents=dict(self.user_agents),
                    http_hosts=dict(self.http_hosts), alerts_caused=dict(self.alerts_caused),
                    alerts_targeted=dict(self.alerts_targeted), rules=sorted(self.rules), max_risk=self.max_risk,
                    flows_out=self.flows_out, flows_in=self.flows_in)


def initial_ttl(ttl: int) -> int:
    """Senders start at 32, 64, 128 or 255; the observed value is that minus the hops travelled."""
    for start in (32, 64, 128, 255):
        if ttl <= start:
            return start
    return 255


def guess_os(ttl: int | None, syn: dict | None) -> str:
    """A rough passive fingerprint from the initial TTL and the SYN's window and options."""
    if ttl is None:
        return ""
    start = initial_ttl(ttl)
    if syn:
        win, opts = syn["window"], syn["options"]
        if not opts and win <= 4096:
            return "? (crafted SYNs)"
        if start == 64:
            if win == 65535 and "ts" in opts and opts.endswith("ws"):
                return "macOS/iOS/BSD"
            if win in (29200, 64240, 65495) or (win > 5000 and opts.startswith("mss,sack,ts")):
                return "Linux"
            return "Linux/Unix"
        if start == 128:
            return "Windows"
        if start == 255:
            return "network device"
    return {64: "Unix-like", 128: "Windows", 255: "network device", 32: "embedded"}[start]


class HostProfiler:
    """Per-packet half of host profiling; ``profile(an)`` finishes the job from flows."""

    def __init__(self):
        self.hosts: dict[str, Host] = {}
        self.dhcp_names: dict[str, str] = {}    # client MAC -> hostname
        self.mac_ips: dict[str, set] = defaultdict(set)  # MAC -> IPs it sent from
        self.arp: dict[str, str] = {}           # IP -> MAC from the first ARP reply (spoofed rebinds are alerts)

    def _host(self, addr: str, ts: float) -> Host:
        h = self.hosts.get(addr)
        if h is None:
            h = self.hosts[addr] = Host(addr, first_ts=ts, last_ts=ts)
        return h

    def process(self, pkt: Packet) -> None:
        ip = pkt.ip
        arp = pkt.layer("arp")
        if ip is None and (arp is None or arp["sender_ip"] == "?"):
            return
        src, dst = pkt.src, pkt.dst
        eth = pkt.layer("ethernet")
        s = self._host(src, pkt.ts)
        s.last_ts = pkt.ts
        s.pkts_sent += 1
        s.bytes_sent += pkt.orig_len
        if eth is not None:
            s.macs[eth["src"]] += 1
            if len(self.mac_ips[eth["src"]]) < LIST_CAP:
                self.mac_ips[eth["src"]].add(src)
        if arp is not None:
            if "sender_mac" in arp.fields and (arp["op"] == 2 or arp.get("gratuitous")):
                s.macs[arp["sender_mac"]] += 1
                self.arp.setdefault(src, arp["sender_mac"])
            return
        if dst not in ("255.255.255.255", "0.0.0.0") and not dst.startswith(("224.", "239.", "ff0")):
            d = self._host(dst, pkt.ts)
            d.last_ts = pkt.ts
            d.pkts_recv += 1
            d.bytes_recv += pkt.orig_len
        # mDNS/LLMNR always use TTL 255 (or 1) whatever the OS, so they would skew the OS guess
        if src != "0.0.0.0" and not dst.startswith(("224.", "239.", "ff0")) and pkt.layer("mdns") is None:
            s.ttls[ip["ttl"]] += 1
        tcp = pkt.layer("tcp")
        # keep the first SYN with options: optionless SYNs are usually crafted by scanners
        if tcp is not None and tcp["flags.syn"] and not tcp["flags.ack"] and (s.syn is None or not s.syn["options"]):
            opts = tcp["options"]
            order = ",".join(k for k in ("mss", "sack_perm", "ts_val", "wscale") if k in opts)
            s.syn = dict(window=tcp["window"], ttl=ip["ttl"],
                         options=order.replace("sack_perm", "sack").replace("ts_val", "ts").replace("wscale", "ws"))
        dhcp = pkt.layer("dhcp")
        if dhcp is not None and dhcp.get("hostname"):
            self.dhcp_names[dhcp["client_mac"]] = dhcp["hostname"]
        d_ = pkt.layer("dns") or pkt.layer("mdns")
        if d_ is not None and d_["response"]:
            for rr in d_.get("answers", []):
                if rr["type"] in ("A", "AAAA") and isinstance(rr["data"], str):
                    h = self.hosts.get(rr["data"]) or self._host(rr["data"], pkt.ts)
                    if len(h.names) < 20:
                        h.names.setdefault(rr["name"].rstrip("."), "dns")


def profile(an) -> list[Host]:
    """Finish every host's profile from flows and alerts; most interesting hosts first."""
    from .scoring import score_flows
    prof: HostProfiler = an.hosts
    hosts = prof.hosts
    if any(f.risk is None for f in an.flows):
        score_flows(an)

    for mac, name in prof.dhcp_names.items():
        for ip in prof.mac_ips.get(mac, ()):
            if ip in hosts and ip != "0.0.0.0":
                hosts[ip].names[name] = "dhcp"

    for f in an.flows:
        c, s = hosts.get(f.client[0]), hosts.get(f.server[0])
        if c is None or s is None:
            continue
        c.flows_out += 1
        s.flows_in += 1
        c.peers[s.addr] += f.bytes
        s.peers[c.addr] += f.bytes
        port = f.server[1]
        label = f.label if f.label not in ("TCP", "UDP") else APP_BY_PORT.get(port, f"port {port}")
        if f.proto == "tcp":
            answered = "synack" in f.handshake if "syn" in f.handshake else f.s2c.packets > 0
        else:
            answered = any(d["response"] for d in f.dns) if f.dns else f.packets > 1
        if f.proto == "tcp" and f.state == "REFUSED":
            s.closed_ports.add(port)
        elif answered and port:
            svc = s.services.setdefault(f"{port}/{f.proto}", dict(label=label, clients=set(), flows=0, bytes=0))
            svc["flows"] += 1
            svc["bytes"] += f.bytes
            if len(svc["clients"]) < LIST_CAP:
                svc["clients"].add(c.addr)
            c.uses[label] += 1
        if f.risk is not None:
            c.max_risk = max(c.max_risk, f.risk.score)
            s.max_risk = max(s.max_risk, f.risk.score)
        for d in f.dns:
            if not d["response"] and d["qname"]:
                c.domains[d["qname"].rstrip(".")] += 1
            elif d["response"] and d["rcode"] == "NXDOMAIN":
                c.nxdomains += 1
        if f.tls_sni:
            c.sni[f.tls_sni] += 1
            s.names.setdefault(f.tls_sni, "sni")
        for tx in f.http:
            req = tx.get("request")
            if req:
                if req.get("user_agent"):
                    c.user_agents[req["user_agent"]] += 1
                if req.get("host"):
                    c.http_hosts[req["host"]] += 1
                    if not req["host"].split(":")[0].replace(".", "").isdigit():
                        s.names.setdefault(req["host"].split(":")[0], "http")

    scanners = set()
    for a in an.alerts:
        if a.src in hosts:
            hosts[a.src].alerts_caused[a.severity] += 1
            hosts[a.src].rules.add(a.rule)
        if a.dst in hosts:
            hosts[a.dst].alerts_targeted[a.severity] += 1
        if a.rule in SCANNER_RULES:
            scanners.add(a.src)

    # a MAC that sources traffic for several internet addresses is a router; its own IP is the one ARP binds to it
    gateway_macs = {m for m, ips in prof.mac_ips.items() if sum(1 for ip in ips if not is_private(ip)) >= 2}
    gateways = {ip for ip, mac in prof.arp.items() if mac in gateway_macs} or \
        {ip for m in gateway_macs for ip in prof.mac_ips[m] if is_private(ip)}
    for h in hosts.values():
        ttl = h.syn["ttl"] if h.syn else (h.ttls.most_common(1)[0][0] if h.ttls else None)
        if h.local or h.syn:
            h.os = guess_os(ttl, h.syn)
        h.closed_ports -= set(h.open_ports)
        h.routed = h.mac in gateway_macs and h.addr not in gateways
        h.roles = _roles(h, scanners, gateways)
    return sorted(hosts.values(), key=_interest)


def _roles(h: Host, scanners: set, gateways: set) -> list[str]:
    roles = []
    labels = {v["label"] for v in h.services.values()}
    if h.addr in scanners:
        roles.append("scanner")
    if h.addr in gateways:
        roles.append("gateway")
    if "DNS" in labels:
        roles.append("DNS server")
    if labels & {"HTTP", "HTTPS", "TLS", "HTTP-ALT"}:
        roles.append("web server")
    if "DHCP" in labels:
        roles.append("DHCP server")
    other = labels - {"DNS", "HTTP", "HTTPS", "TLS", "HTTP-ALT", "DHCP"}
    if other:
        roles.append("server (" + ", ".join(sorted(other)[:3]) + ")")
    if h.local and set(h.uses) & {"DNS", "HTTP", "HTTPS", "TLS"} and not {"gateway", "scanner"} & set(roles):
        roles.append("workstation")
    elif h.flows_out and not roles:
        roles.append("client")
    if not roles:
        roles.append("passive")
    if not h.local:
        roles.append("external")
    return roles


def _interest(h: Host) -> tuple:
    alerts = h.alerts_caused["high"] * 10 + h.alerts_caused["medium"] * 4 + h.alerts_caused["low"]
    return (-alerts, -h.max_risk, not h.local, -(h.bytes_sent + h.bytes_recv))
