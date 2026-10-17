"""The decoded-packet model shared by every layer of the analyzer."""
from __future__ import annotations

from typing import Any


class Layer:
    """One protocol header: its name, where it sits in the frame, and its fields.

    ``offset``/``length`` point into the original frame bytes so the hex view can
    colour each header. They are ``None`` for layers decoded from reassembled data.
    """

    __slots__ = ("name", "offset", "length", "fields")

    def __init__(self, name: str, offset: int | None, length: int | None, **fields: Any):
        self.name = name
        self.offset = offset
        self.length = length
        self.fields = fields

    def __getitem__(self, key: str) -> Any:
        return self.fields[key]

    def get(self, key: str, default: Any = None) -> Any:
        return self.fields.get(key, default)

    def __repr__(self) -> str:
        return f"<{self.name} {self.fields}>"


# Filter-language aliases: "ip" means whichever IP version the packet carries.
LAYER_ALIASES = {"ip": ("ipv4", "ipv6"), "icmp": ("icmp", "icmpv6"), "eth": ("ethernet",)}
# Wireshark-style "either direction" fields: tcp.port matches sport or dport.
EITHER_FIELDS = {"port": ("sport", "dport"), "addr": ("src", "dst"), "host": ("src", "dst")}


class Packet:
    def __init__(self, number: int, ts: float, data: bytes, linktype: int, orig_len: int):
        self.number = number
        self.ts = ts
        self.data = data
        self.linktype = linktype
        self.orig_len = orig_len
        self.layers: list[Layer] = []
        self.warnings: list[str] = []
        self.payload: bytes = b""       # transport payload (TCP/UDP data)
        self.payload_offset: int | None = None
        self.flow_id: int | None = None  # set by the flow tracker
        self.direction: str | None = None  # "c2s" or "s2c"
        self.alerts: list = []
        self.note = ""  # flow-level remark such as "retransmission"
        self.rel_seq: int | None = None  # TCP seq/ack relative to the ISN, set by the tracker
        self.rel_ack: int | None = None

    # -- layer access -------------------------------------------------------
    def add(self, layer: Layer) -> Layer:
        self.layers.append(layer)
        return layer

    def layer(self, name: str) -> Layer | None:
        names = LAYER_ALIASES.get(name, (name,))
        for layer in self.layers:
            if layer.name in names:
                return layer
        return None

    def has(self, name: str) -> bool:
        return self.layer(name) is not None

    def __contains__(self, name: str) -> bool:
        return self.has(name)

    # -- convenient views ---------------------------------------------------
    @property
    def ip(self) -> Layer | None:
        return self.layer("ip")

    @property
    def src(self) -> str:
        ip = self.ip
        if ip:
            return ip["src"]
        arp = self.layer("arp")
        if arp:
            return arp["sender_ip"]
        eth = self.layer("ethernet")
        return eth["src"] if eth else "?"

    @property
    def dst(self) -> str:
        ip = self.ip
        if ip:
            return ip["dst"]
        arp = self.layer("arp")
        if arp:
            return arp["target_ip"]
        eth = self.layer("ethernet")
        return eth["dst"] if eth else "?"

    @property
    def sport(self) -> int | None:
        t = self.layer("tcp") or self.layer("udp")
        return t["sport"] if t else None

    @property
    def dport(self) -> int | None:
        t = self.layer("tcp") or self.layer("udp")
        return t["dport"] if t else None

    @property
    def protocol(self) -> str:
        """Name of the highest decoded layer, as shown in the Protocol column."""
        for layer in reversed(self.layers):
            if layer.name not in ("ethernet", "vlan", "sll", "loopback"):
                return LAYER_DISPLAY.get(layer.name, layer.name.upper())
        return "ETH"

    @property
    def length(self) -> int:
        return self.orig_len

    # -- field lookup for filters -------------------------------------------
    def values(self, path: str) -> list[Any]:
        """All values for a dotted field path such as ``tcp.dport`` or ``dns.qname``.

        Returns a list because some paths (``ip.addr``, ``tcp.port``) match more than
        one field, and a filter comparison succeeds if any of them matches.
        """
        if path.startswith("frame."):
            key = path[6:]
            return [{"len": self.orig_len, "number": self.number, "time": self.ts,
                     "cap_len": len(self.data)}.get(key)] if key in ("len", "number", "time", "cap_len") else []
        if "." not in path:
            return [True] if self.has(path) else []
        lname, key = path.split(".", 1)
        names = LAYER_ALIASES.get(lname, (lname,))
        out: list[Any] = []
        for layer in self.layers:
            if layer.name not in names:
                continue
            if key in layer.fields:
                out.append(layer.fields[key])
            elif key in EITHER_FIELDS:
                out.extend(layer.fields[k] for k in EITHER_FIELDS[key] if k in layer.fields)
        return out

    def __repr__(self) -> str:
        return f"<Packet #{self.number} {self.protocol} {self.src} -> {self.dst}>"


LAYER_DISPLAY = {
    "ipv4": "IPv4", "ipv6": "IPv6", "icmp": "ICMP", "icmpv6": "ICMPv6", "arp": "ARP",
    "tcp": "TCP", "udp": "UDP", "dns": "DNS", "mdns": "MDNS", "http": "HTTP", "tls": "TLS",
    "igmp": "IGMP", "dhcp": "DHCP",
}
