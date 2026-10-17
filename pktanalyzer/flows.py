"""Conversation tracking: TCP state machine, handshake timing and stream reassembly.

Every packet with an IP 5-tuple is assigned to a :class:`Flow`. For TCP the flow
runs a passive copy of the RFC 793 state machine as seen from the wire, times the
three-way handshake, and reorders segments by sequence number so the byte stream
each side sent can be rebuilt (and fed to the HTTP parser) even when packets
arrive out of order or are retransmitted.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .http import HttpStreamParser
from .packet import Packet

WELL_KNOWN = {20, 21, 22, 23, 25, 53, 67, 68, 80, 110, 123, 143, 161, 389, 443, 445, 465, 587, 853,
              993, 995, 1433, 1883, 3306, 3389, 5222, 5353, 5432, 5900, 6379, 8000, 8080, 8443, 9200, 27017}
APP_BY_PORT = {20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP", 53: "DNS", 67: "DHCP",
               68: "DHCP", 80: "HTTP", 110: "POP3", 123: "NTP", 143: "IMAP", 161: "SNMP", 389: "LDAP",
               443: "HTTPS", 445: "SMB", 853: "DoT", 993: "IMAPS", 995: "POP3S", 1883: "MQTT",
               3306: "MySQL", 3389: "RDP", 5353: "mDNS", 5432: "Postgres", 5900: "VNC", 6379: "Redis",
               8080: "HTTP-alt", 8443: "HTTPS-alt", 27017: "MongoDB"}

STREAM_CAP = 2 * 1024 * 1024    # bytes of reassembled data kept per direction
MAX_OOO_SEGMENTS = 2048         # out-of-order segments buffered per direction
MAX_EVENTS = 2000               # packets remembered per flow for the ladder diagram


def seq_diff(a: int, b: int) -> int:
    """a - b in 32-bit sequence space (handles wraparound)."""
    d = (a - b) & 0xFFFFFFFF
    return d - (1 << 32) if d >= (1 << 31) else d


class Endpoint:
    """One direction of a TCP connection."""

    def __init__(self):
        self.isn: int | None = None
        self.next_seq: int | None = None
        self.packets = 0
        self.bytes = 0          # payload bytes on the wire, including retransmissions
        self.stream = bytearray()
        self.stream_total = 0   # in-order bytes delivered (may exceed STREAM_CAP)
        self.ooo: dict[int, bytes] = {}
        self.retransmissions = 0
        self.out_of_order = 0
        self.lost_bytes = 0     # gap skipped when the buffer overflowed
        self.fin = False
        self.fin_seq: int | None = None
        self.rst = False
        self.window = 0
        self.wscale = 0
        self.http = HttpStreamParser()

    def rel(self, seq: int) -> int:
        return seq_diff(seq, self.isn) if self.isn is not None else 0


@dataclass
class Event:
    """One packet of a flow, recorded for the ladder diagram and session export."""
    number: int
    ts: float
    direction: str
    flags: str
    seq: int
    ack: int
    length: int
    note: str = ""


@dataclass
class Flow:
    id: int
    proto: str
    client: tuple
    server: tuple
    first_ts: float
    last_ts: float
    state: str = "NEW"
    packets: int = 0
    bytes: int = 0
    handshake: dict = field(default_factory=dict)
    events: list = field(default_factory=list)
    http: list = field(default_factory=list)
    dns: list = field(default_factory=list)
    tls_sni: str | None = None
    app: str | None = None
    midstream: bool = False
    history: list = field(default_factory=list)   # state transitions (ts, state)
    c2s: Endpoint | None = None
    s2c: Endpoint | None = None
    pending_requests: list = field(default_factory=list)
    syn_retries: int = 0

    @property
    def key_str(self) -> str:
        return f"{self.client[0]}:{self.client[1]} -> {self.server[0]}:{self.server[1]}"

    @property
    def duration(self) -> float:
        return self.last_ts - self.first_ts

    @property
    def rtt(self) -> float | None:
        hs = self.handshake
        if "syn" in hs and "ack" in hs:
            return hs["ack"] - hs["syn"]
        return None

    @property
    def label(self) -> str:
        return self.app or APP_BY_PORT.get(self.server[1], self.proto.upper())

    def to_dict(self) -> dict:
        d = dict(id=self.id, proto=self.proto, client=f"{self.client[0]}:{self.client[1]}",
                 server=f"{self.server[0]}:{self.server[1]}", app=self.label, state=self.state,
                 first_ts=self.first_ts, last_ts=self.last_ts, duration=round(self.duration, 6),
                 packets=self.packets, bytes=self.bytes, midstream=self.midstream)
        if self.proto == "tcp":
            hs = {k: round(v - self.first_ts, 6) for k, v in self.handshake.items()}
            d.update(handshake=hs, rtt_ms=round(self.rtt * 1000, 3) if self.rtt is not None else None,
                     syn_retries=self.syn_retries,
                     history=[(round(t - self.first_ts, 6), s) for t, s in self.history])
            for name, ep in (("c2s", self.c2s), ("s2c", self.s2c)):
                d[name] = dict(packets=ep.packets, payload_bytes=ep.bytes, stream_bytes=ep.stream_total,
                               retransmissions=ep.retransmissions, out_of_order=ep.out_of_order,
                               lost_bytes=ep.lost_bytes, isn=ep.isn)
        if self.tls_sni:
            d["tls_sni"] = self.tls_sni
        if self.http:
            d["http"] = [_http_tx_dict(t) for t in self.http]
        if self.dns:
            d["dns"] = self.dns
        return d


def _http_tx_dict(tx: dict) -> dict:
    req, resp = tx.get("request"), tx.get("response")
    out = {}
    if req:
        out["request"] = {k: req[k] for k in ("method", "uri", "version", "headers", "body_len", "ts") if k in req}
    if resp:
        out["response"] = {k: resp[k] for k in ("status", "reason", "version", "headers", "body_len", "ts") if k in resp}
    return out


class FlowTracker:
    """Assigns packets to flows and drives each TCP connection's state machine."""

    def __init__(self, udp_timeout: float = 120.0):
        self.flows: dict[tuple, Flow] = {}
        self.by_id: dict[int, Flow] = {}
        self.next_id = 1
        self.udp_timeout = udp_timeout
        self.listeners: list = []  # callbacks(flow, kind, data) for http/dns/state events

    def _emit(self, flow: Flow, kind: str, data) -> None:
        for cb in self.listeners:
            cb(flow, kind, data)

    def process(self, pkt: Packet) -> Flow | None:
        ip = pkt.ip
        if ip is None:
            return None
        tcp, udp = pkt.layer("tcp"), pkt.layer("udp")
        if tcp is not None:
            proto, t = "tcp", tcp
        elif udp is not None:
            proto, t = "udp", udp
        else:
            proto, t = ip["proto_name"].lower(), None
        a = (ip["src"], t["sport"] if t else 0)
        b = (ip["dst"], t["dport"] if t else 0)
        key = (proto,) + (tuple(sorted((a, b))))
        flow = self.flows.get(key)
        if flow is not None and proto == "tcp" and flow.state in ("CLOSED", "RESET", "REFUSED") \
                and tcp["flags.syn"] and not tcp["flags.ack"]:
            flow = None  # port reuse: a fresh SYN after close starts a new connection
        if flow is not None and proto != "tcp" and pkt.ts - flow.last_ts > self.udp_timeout:
            flow = None
        if flow is None:
            flow = self._new_flow(key, proto, pkt, a, b, tcp)
        flow.packets += 1
        flow.bytes += pkt.orig_len
        flow.last_ts = pkt.ts
        direction = "c2s" if a == flow.client else "s2c"
        pkt.flow_id = flow.id
        pkt.direction = direction
        if proto == "tcp":
            self._tcp(flow, pkt, tcp, direction)
        else:
            if len(flow.events) < MAX_EVENTS:
                flow.events.append(Event(pkt.number, pkt.ts, direction, "", 0, 0, len(pkt.payload)))
        self._app(flow, pkt, direction)
        return flow

    def _new_flow(self, key, proto, pkt, a, b, tcp) -> Flow:
        client, server = a, b
        midstream = False
        if tcp is not None:
            if tcp["flags.syn"] and tcp["flags.ack"]:
                client, server = b, a  # we missed the SYN; the SYN-ACK sender is the server
                midstream = True
            elif not tcp["flags.syn"]:
                midstream = True
                client, server = _guess_roles(a, b)
        elif pkt.layer("udp") is not None:
            if b[1] not in WELL_KNOWN and a[1] in WELL_KNOWN:
                client, server = b, a
        flow = Flow(self.next_id, proto, client, server, pkt.ts, pkt.ts, midstream=midstream)
        if proto == "tcp":
            flow.c2s, flow.s2c = Endpoint(), Endpoint()
            flow.state = "NEW"
        else:
            flow.state = "ACTIVE"
        self.next_id += 1
        self.flows[key] = flow
        self.by_id[flow.id] = flow
        return flow

    # -- TCP ------------------------------------------------------------------
    def _set_state(self, flow: Flow, state: str, ts: float) -> None:
        if flow.state != state:
            flow.state = state
            flow.history.append((ts, state))
            self._emit(flow, "state", state)

    def _tcp(self, flow: Flow, pkt: Packet, tcp, direction: str) -> None:
        snd = flow.c2s if direction == "c2s" else flow.s2c
        rcv = flow.s2c if direction == "c2s" else flow.c2s
        syn, ack, fin, rst = tcp["flags.syn"], tcp["flags.ack"], tcp["flags.fin"], tcp["flags.rst"]
        seq, plen = tcp["seq"], len(pkt.payload)
        snd.packets += 1
        snd.bytes += plen
        snd.window = tcp["window"]
        note = ""
        ts = pkt.ts
        hs = flow.handshake

        # --- the state machine, observed passively -------------------------
        if syn and not ack:
            if snd.isn is not None and snd.isn == seq:
                flow.syn_retries += 1
                note = "SYN retransmission"
            snd.isn, snd.next_seq = seq, (seq + 1) & 0xFFFFFFFF
            snd.wscale = tcp.get("wscale", 0)
            hs.setdefault("syn", ts)
            if flow.state in ("NEW",):
                self._set_state(flow, "SYN_SENT", ts)
        elif syn and ack:
            snd.isn, snd.next_seq = seq, (seq + 1) & 0xFFFFFFFF
            snd.wscale = tcp.get("wscale", 0)
            if "synack" in hs:
                note = "SYN-ACK retransmission"
            hs.setdefault("synack", ts)
            if flow.state in ("NEW", "SYN_SENT"):
                self._set_state(flow, "SYN_RECEIVED", ts)
        elif rst:
            snd.rst = True
            if flow.state in ("SYN_SENT",) and direction == "s2c":
                self._set_state(flow, "REFUSED", ts)
                note = "connection refused"
            else:
                self._set_state(flow, "RESET", ts)
        else:
            if flow.state == "SYN_RECEIVED" and direction == "c2s" and ack:
                hs.setdefault("ack", ts)
                self._set_state(flow, "ESTABLISHED", ts)
            elif flow.state == "NEW":
                self._set_state(flow, "ESTABLISHED", ts)
            if fin and not snd.fin:
                snd.fin = True
                snd.fin_seq = (seq + plen) & 0xFFFFFFFF
                if flow.state in ("ESTABLISHED", "SYN_RECEIVED"):
                    self._set_state(flow, "FIN_WAIT", ts)
                elif flow.state == "FIN_WAIT":
                    self._set_state(flow, "CLOSING", ts)
            elif ack and rcv.fin and snd.fin and rcv.fin_seq is not None \
                    and seq_diff(tcp["ack"], rcv.fin_seq) >= 1 and flow.state == "CLOSING":
                self._set_state(flow, "CLOSED", ts)

        # --- reassembly ----------------------------------------------------
        if snd.next_seq is None and not syn:
            snd.next_seq = seq  # joined mid-stream: start the stream here
            if snd.isn is None:
                snd.isn = (seq - 1) & 0xFFFFFFFF
        if plen and not syn and not rst:
            note = self._reassemble(flow, snd, seq, pkt.payload, ts, direction) or note
        elif plen and syn:
            note = note or "data on SYN"
        if fin and snd.next_seq is not None and seq_diff((seq + plen) & 0xFFFFFFFF, snd.next_seq) == 0:
            snd.next_seq = (snd.next_seq + 1) & 0xFFFFFFFF
            for msg in snd.http.close():
                self._http_message(flow, msg, direction)

        if len(flow.events) < MAX_EVENTS:
            flow.events.append(Event(pkt.number, ts, direction, tcp["flags_str"], snd.rel(seq),
                                     rcv.rel(tcp["ack"]) if ack and rcv.isn is not None else 0, plen, note))
        pkt.rel_seq = snd.rel(seq)
        pkt.rel_ack = rcv.rel(tcp["ack"]) if ack and rcv.isn is not None else None
        if note:
            pkt.note = note  # surfaced in the Info column

    def _reassemble(self, flow: Flow, ep: Endpoint, seq: int, data: bytes, ts: float, direction: str) -> str:
        d = seq_diff(seq, ep.next_seq)
        note = ""
        if d < 0:
            if d + len(data) <= 0:
                ep.retransmissions += 1
                return "retransmission"
            data = data[-d:]  # partial overlap: keep only the new bytes
            seq = ep.next_seq
            ep.retransmissions += 1
            note = "partial retransmission"
            d = 0
        if d > 0:
            ep.out_of_order += 1
            if len(ep.ooo) < MAX_OOO_SEGMENTS:
                ep.ooo[seq] = data
            else:
                self._skip_gap(flow, ep, ts, direction)
            return "out-of-order"
        self._deliver(flow, ep, data, ts, direction)
        # drain any buffered segments that now line up
        while ep.ooo:
            progressed = False
            for s in list(ep.ooo):
                dd = seq_diff(s, ep.next_seq)
                if dd <= 0:
                    seg = ep.ooo.pop(s)
                    if dd + len(seg) > 0:
                        self._deliver(flow, ep, seg[-dd:] if dd else seg, ts, direction)
                    progressed = True
            if not progressed:
                break
        return note

    def _skip_gap(self, flow: Flow, ep: Endpoint, ts: float, direction: str) -> None:
        """Buffer overflow: accept the loss and resume at the earliest buffered segment."""
        first = min(ep.ooo, key=lambda s: seq_diff(s, ep.next_seq))
        ep.lost_bytes += seq_diff(first, ep.next_seq)
        ep.next_seq = first
        ep.http.dead = True
        self._reassemble(flow, ep, first, ep.ooo.pop(first), ts, direction)

    def _deliver(self, flow: Flow, ep: Endpoint, data: bytes, ts: float, direction: str) -> None:
        ep.next_seq = (ep.next_seq + len(data)) & 0xFFFFFFFF
        ep.stream_total += len(data)
        room = STREAM_CAP - len(ep.stream)
        if room > 0:
            ep.stream += data[:room]
        for msg in ep.http.feed(data, ts):
            self._http_message(flow, msg, direction)

    def _http_message(self, flow: Flow, msg: dict, direction: str) -> None:
        flow.app = flow.app or "HTTP"
        if msg["type"] == "request":
            tx = {"request": msg}
            flow.http.append(tx)
            flow.pending_requests.append(tx)
            peer = flow.s2c if direction == "c2s" else flow.c2s
            peer.http.request_methods.append(msg["method"])
            self._emit(flow, "http_request", msg)
        else:
            if flow.pending_requests:
                tx = flow.pending_requests.pop(0)
                tx["response"] = msg
            else:
                tx = {"response": msg}
                flow.http.append(tx)
            self._emit(flow, "http_response", tx)

    # -- per-packet application data -------------------------------------------
    def _app(self, flow: Flow, pkt: Packet, direction: str) -> None:
        d = pkt.layer("dns") or pkt.layer("mdns")
        if d is not None:
            flow.app = flow.app or ("mDNS" if d.name == "mdns" else "DNS")
            rec = dict(ts=pkt.ts, id=d["id"], response=d["response"], qname=d.get("qname"),
                       qtype=d.get("qtype"), rcode=d["rcode_name"], answers=d["answer_data"])
            if len(flow.dns) < 1000:
                flow.dns.append(rec)
            self._emit(flow, "dns", rec)
        t = pkt.layer("tls")
        if t is not None:
            flow.app = "TLS"
            if t.get("sni"):
                flow.tls_sni = t["sni"]
        if pkt.layer("dhcp") is not None:
            flow.app = "DHCP"


def _guess_roles(a: tuple, b: tuple) -> tuple[tuple, tuple]:
    """Without a SYN, assume the side on a well-known (or lower) port is the server."""
    a_srv, b_srv = a[1] in WELL_KNOWN, b[1] in WELL_KNOWN
    if a_srv and not b_srv:
        return b, a
    if b_srv and not a_srv:
        return a, b
    return (a, b) if b[1] <= a[1] else (b, a)
