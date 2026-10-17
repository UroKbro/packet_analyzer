"""Ties the pipeline together: decode -> track flows -> detect anomalies -> stats."""
from __future__ import annotations

from collections import Counter, defaultdict, deque
from typing import Iterable, Iterator

from . import dns, http, tls
from .anomalies import AnomalyDetector
from .decoder import Decoder
from .flows import FlowTracker
from .packet import Packet
from .pcap import Frame


class Analyzer:
    def __init__(self, verify_checksums: bool = True, keep_packets: bool = True,
                 detector: AnomalyDetector | None = None, history: int | None = None):
        self.decoder = Decoder(verify_checksums=verify_checksums)
        self.tracker = FlowTracker()
        self.detector = detector or AnomalyDetector()
        # stream-level findings (TLS certificates, ...) reach the detector through the tracker
        self.tracker.listeners.append(
            lambda flow, kind, data: self.detector.flow_event(self.tracker.current, flow, kind, data))
        self.keep_packets = keep_packets
        # keep every packet for offline analysis, or a ring buffer for live views
        self.packets: list[Packet] | deque = deque(maxlen=history) if history else []
        self.count = 0
        self.bytes = 0
        self.first_ts: float | None = None
        self.last_ts: float | None = None
        self.protocols: Counter = Counter()     # every layer name seen, for the hierarchy
        self.top_protocol: Counter = Counter()  # highest layer per packet
        self.talkers: Counter = Counter()       # bytes sent per address
        self.conversations: Counter = Counter()  # bytes per address pair
        self.timeline: dict[int, int] = defaultdict(int)  # packets per 100 ms bucket

    def feed(self, frame: Frame) -> Packet:
        self.count += 1
        pkt = self.decoder.decode(self.count, frame.ts, frame.data, frame.linktype, frame.orig_len)
        flow = self.tracker.process(pkt)
        self.detector.process(pkt, flow)
        self._stats(pkt)
        if self.keep_packets:
            self.packets.append(pkt)
        return pkt

    def run(self, frames: Iterable[Frame]) -> Iterator[Packet]:
        for frame in frames:
            yield self.feed(frame)

    def _stats(self, pkt: Packet) -> None:
        self.bytes += pkt.orig_len
        if self.first_ts is None:
            self.first_ts = pkt.ts
        self.last_ts = pkt.ts
        for layer in pkt.layers:
            self.protocols[layer.name] += 1
        self.top_protocol[pkt.protocol] += 1
        src, dst = pkt.src, pkt.dst
        self.talkers[src] += pkt.orig_len
        self.conversations[tuple(sorted((src, dst)))] += pkt.orig_len
        self.timeline[int((pkt.ts - self.first_ts) * 10)] += 1

    @property
    def flows(self):
        return list(self.tracker.by_id.values())

    @property
    def alerts(self):
        return self.detector.alerts


def info(pkt: Packet) -> str:
    """The one-line Info column, in the spirit of Wireshark's."""
    parts: list[str] = []
    top = pkt.layers[-1].name if pkt.layers else ""
    d = pkt.layer("dns") or pkt.layer("mdns")
    h = pkt.layer("http")
    t = pkt.layer("tls")
    tcp = pkt.layer("tcp")
    udp = pkt.layer("udp")
    if d is not None:
        parts.append(dns.summary(d.fields))
    elif h is not None:
        parts.append(http.summary(h.fields))
    elif t is not None:
        parts.append(tls.summary(t.fields))
    elif pkt.layer("dhcp") is not None:
        dh = pkt.layer("dhcp")
        parts.append(f"DHCP {dh.get('msg_type', '?')} xid=0x{dh['xid']:08x}"
                     + (f" {dh['hostname']}" if dh.get("hostname") else ""))
    elif tcp is not None:
        seq = pkt.rel_seq if pkt.rel_seq is not None else tcp["seq"]
        s = f"{tcp['sport']} → {tcp['dport']} [{tcp['flag_names']}] Seq={seq}"
        if tcp["flags.ack"]:
            s += f" Ack={pkt.rel_ack if pkt.rel_ack is not None else tcp['ack']}"
        s += f" Win={tcp['window']} Len={tcp['len']}"
        if "mss" in tcp.fields:
            s += f" MSS={tcp['mss']}"
        parts.append(s)
    elif udp is not None:
        parts.append(f"{udp['sport']} → {udp['dport']} Len={len(pkt.payload)}")
    elif top in ("icmp", "icmpv6"):
        ic = pkt.layers[-1]
        s = ic["type_name"]
        if "code_name" in ic.fields:
            s += f" ({ic['code_name']})"
        if "seq" in ic.fields:
            s += f" id=0x{ic['id']:04x} seq={ic['seq']}"
        if "orig_dport" in ic.fields:
            s += f" for {ic['orig_proto']} {ic['orig_dst']}:{ic['orig_dport']}"
        if "target" in ic.fields:
            s += f" for {ic['target']}"
        parts.append(s)
    elif top == "arp":
        a = pkt.layers[-1]
        if a.get("op") == 1:
            parts.append(f"Who has {a['target_ip']}? Tell {a['sender_ip']}")
        elif a.get("op") == 2:
            parts.append(f"{a['sender_ip']} is at {a['sender_mac']}")
        if a.get("gratuitous"):
            parts.append("(gratuitous)")
    elif pkt.ip is not None:
        ip = pkt.ip
        if ip.get("fragment") and "reassembled" not in ip.fields:
            parts.append(f"Fragmented IP protocol ({ip['proto_name']}, off={ip.get('frag_offset', 0)}, "
                         f"ID={ip.get('id', 0):04x})")
        else:
            parts.append(f"IP protocol {ip['proto_name']}")
    elif pkt.layers:
        parts.append(pkt.layers[-1].name)
    ip = pkt.ip
    if ip is not None and "reassembled" in ip.fields:
        parts.append(f"[reassembled {ip['reassembled']} bytes]")
    if pkt.note:
        parts.append(f"[{pkt.note}]")
    return " ".join(parts)
