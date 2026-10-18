"""Hand-written decoders for the link, network and transport layers.

Every header is unpacked with ``struct`` straight from the frame bytes. Each
decoder records a :class:`Layer` with its offset in the frame, then hands the
rest of the bytes to the next protocol up the stack, the same way the OSI
encapsulation is peeled apart on a real host.
"""
from __future__ import annotations

import socket
import struct

from . import dns, http, tls
from .packet import Layer, Packet, printable
from .pcap import (LINKTYPE_ETHERNET, LINKTYPE_IPV4, LINKTYPE_IPV6, LINKTYPE_LINUX_SLL,
                   LINKTYPE_NULL, LINKTYPE_RAW)

ETHERTYPES = {0x0800: "IPv4", 0x0806: "ARP", 0x86DD: "IPv6", 0x8100: "802.1Q", 0x88A8: "802.1ad",
              0x8035: "RARP", 0x88CC: "LLDP", 0x8863: "PPPoE-D", 0x8864: "PPPoE-S"}
IP_PROTOS = {0: "HOPOPT", 1: "ICMP", 2: "IGMP", 4: "IPIP", 6: "TCP", 17: "UDP", 41: "IPv6",
             47: "GRE", 50: "ESP", 51: "AH", 58: "ICMPv6", 89: "OSPF", 132: "SCTP"}
TCP_FLAGS = [(0x01, "FIN", "F"), (0x02, "SYN", "S"), (0x04, "RST", "R"), (0x08, "PSH", "P"),
             (0x10, "ACK", "."), (0x20, "URG", "U"), (0x40, "ECE", "E"), (0x80, "CWR", "W"),
             (0x100, "NS", "N")]
ICMP_TYPES = {0: "Echo Reply", 3: "Destination Unreachable", 4: "Source Quench", 5: "Redirect",
              8: "Echo Request", 9: "Router Advertisement", 10: "Router Solicitation",
              11: "Time Exceeded", 12: "Parameter Problem", 13: "Timestamp", 14: "Timestamp Reply"}
ICMP_UNREACH = {0: "net unreachable", 1: "host unreachable", 2: "protocol unreachable",
                3: "port unreachable", 4: "fragmentation needed", 13: "administratively prohibited"}
ICMPV6_TYPES = {1: "Destination Unreachable", 2: "Packet Too Big", 3: "Time Exceeded",
                128: "Echo Request", 129: "Echo Reply", 133: "Router Solicitation",
                134: "Router Advertisement", 135: "Neighbor Solicitation", 136: "Neighbor Advertisement"}
IPV6_EXT_HEADERS = {0, 43, 44, 51, 60}
DNS_PORTS = {53, 5353, 5355}


class Truncated(Exception):
    pass


def mac_str(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


def ip4_str(b: bytes) -> str:
    return socket.inet_ntop(socket.AF_INET, b)


def ip6_str(b: bytes) -> str:
    return socket.inet_ntop(socket.AF_INET6, b)


def inet_checksum(data: bytes) -> int:
    """RFC 1071 one's-complement sum. A correct header sums (with checksum) to 0."""
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def tcp_flags_str(flags: int) -> str:
    """tcpdump-style flag string, e.g. ``S.`` for SYN-ACK or ``P.`` for PSH-ACK."""
    s = "".join(ch for bit, _, ch in TCP_FLAGS if flags & bit and ch != ".")
    return (s + "." if flags & 0x10 else s) or "none"


def tcp_flag_names(flags: int) -> str:
    return ",".join(name for bit, name, _ in TCP_FLAGS if flags & bit) or "<none>"


class Defragmenter:
    """Reassembles fragmented IP datagrams (RFC 791 / RFC 8200).

    Fragments are keyed by (src, dst, id, proto). A datagram is complete once the
    last fragment (MF=0) has arrived and the byte ranges cover it without gaps.
    Overlapping fragments, the trick behind teardrop-style attacks, are reported.
    """

    TIMEOUT = 30.0
    MAX_DATAGRAM = 65535 + 40

    def __init__(self):
        self.pending: dict[tuple, dict] = {}

    def add(self, key: tuple, ts: float, offset: int, data: bytes, more: bool) -> tuple[bytes | None, list[str]]:
        warnings: list[str] = []
        self._expire(ts)
        entry = self.pending.setdefault(key, {"frags": [], "total": None, "ts": ts, "count": 0})
        entry["count"] += 1
        end = offset + len(data)
        if end > self.MAX_DATAGRAM:
            warnings.append(f"fragment ends past 65535 bytes (offset {offset}, ping-of-death pattern)")
        for o, d in entry["frags"]:
            if offset < o + len(d) and o < end:
                warnings.append(f"overlapping IP fragment at offset {offset} (overlaps {o}-{o + len(d)})")
                break
        entry["frags"].append((offset, data))
        if not more:
            entry["total"] = end
        if entry["total"] is None:
            return None, warnings
        buf = bytearray(entry["total"])
        covered = 0
        for o, d in sorted(entry["frags"]):
            if o > covered:
                return None, warnings  # still a hole
            buf[o:o + len(d)] = d[: max(0, entry["total"] - o)]
            covered = max(covered, o + len(d))
        if covered < entry["total"]:
            return None, warnings
        del self.pending[key]
        return bytes(buf), warnings

    def _expire(self, now: float) -> None:
        stale = [k for k, v in self.pending.items() if now - v["ts"] > self.TIMEOUT]
        for k in stale:
            del self.pending[k]


class Decoder:
    """Turns raw frames into :class:`Packet` objects with a full layer stack."""

    def __init__(self, verify_checksums: bool = True):
        self.verify_checksums = verify_checksums
        self.defrag = Defragmenter()

    def decode(self, number: int, ts: float, data: bytes, linktype: int, orig_len: int | None = None) -> Packet:
        pkt = Packet(number, ts, data, linktype, orig_len if orig_len is not None else len(data))
        n = len(data)
        try:
            if linktype == LINKTYPE_ETHERNET:
                self.ethernet(pkt, data, 0, n)
            elif linktype in (LINKTYPE_RAW, LINKTYPE_IPV4, LINKTYPE_IPV6):
                self.ip_any(pkt, data, 0, n)
            elif linktype == LINKTYPE_LINUX_SLL:
                self.sll(pkt, data, 0, n)
            elif linktype == LINKTYPE_NULL:
                self.loopback(pkt, data, 0, n)
            else:
                pkt.warnings.append(f"unsupported link type {linktype}")
        except Truncated as e:
            pkt.warnings.append(f"truncated {e}")
        except (struct.error, IndexError, ValueError) as e:
            pkt.warnings.append(f"malformed packet ({e})")
        return pkt

    # -- link layer ---------------------------------------------------------
    def ethernet(self, pkt: Packet, buf: bytes, off: int, end: int) -> None:
        if end - off < 14:
            raise Truncated("Ethernet header")
        dst, src = buf[off:off + 6], buf[off + 6:off + 12]
        (etype,) = struct.unpack_from("!H", buf, off + 12)
        layer = pkt.add(Layer("ethernet", off, 14, dst=mac_str(dst), src=mac_str(src), type=etype,
                              type_name=ETHERTYPES.get(etype, f"0x{etype:04x}")))
        off += 14
        # 802.1Q / QinQ VLAN tags sit between the MACs and the real EtherType
        while etype in (0x8100, 0x88A8):
            if end - off < 4:
                raise Truncated("VLAN tag")
            tci, etype = struct.unpack_from("!HH", buf, off)
            pkt.add(Layer("vlan", off, 4, id=tci & 0x0FFF, priority=tci >> 13, dei=bool(tci & 0x1000),
                          type=etype, type_name=ETHERTYPES.get(etype, f"0x{etype:04x}")))
            off += 4
        if etype <= 1500:
            layer.fields["type_name"] = "802.3 length"
            return
        self.ethertype(pkt, etype, buf, off, end)

    def sll(self, pkt: Packet, buf: bytes, off: int, end: int) -> None:
        if end - off < 16:
            raise Truncated("Linux SLL header")
        ptype, arphrd, alen = struct.unpack_from("!HHH", buf, off)
        addr = buf[off + 6:off + 6 + min(alen, 8)]
        (etype,) = struct.unpack_from("!H", buf, off + 14)
        pkt.add(Layer("sll", off, 16, packet_type=ptype, src=mac_str(addr), type=etype))
        self.ethertype(pkt, etype, buf, off + 16, end)

    def loopback(self, pkt: Packet, buf: bytes, off: int, end: int) -> None:
        if end - off < 4:
            raise Truncated("loopback header")
        family = struct.unpack_from("<I", buf, off)[0]
        if family > 0xFFFF:
            family = struct.unpack_from(">I", buf, off)[0]
        pkt.add(Layer("loopback", off, 4, family=family))
        self.ip_any(pkt, buf, off + 4, end)

    def ethertype(self, pkt: Packet, etype: int, buf: bytes, off: int, end: int) -> None:
        if etype == 0x0800:
            self.ipv4(pkt, buf, off, end)
        elif etype == 0x86DD:
            self.ipv6(pkt, buf, off, end)
        elif etype == 0x0806:
            self.arp(pkt, buf, off, end)

    def arp(self, pkt: Packet, buf: bytes, off: int, end: int) -> None:
        if end - off < 28:
            raise Truncated("ARP")
        htype, ptype, hlen, plen, op = struct.unpack_from("!HHBBH", buf, off)
        if hlen != 6 or plen != 4:
            pkt.add(Layer("arp", off, end - off, op=op, sender_ip="?", target_ip="?"))
            return
        p = off + 8
        smac, sip, tmac, tip = buf[p:p + 6], buf[p + 6:p + 10], buf[p + 10:p + 16], buf[p + 16:p + 20]
        pkt.add(Layer("arp", off, 28, op=op, op_name={1: "request", 2: "reply"}.get(op, str(op)),
                      sender_mac=mac_str(smac), sender_ip=ip4_str(sip),
                      target_mac=mac_str(tmac), target_ip=ip4_str(tip),
                      gratuitous=sip == tip))

    # -- network layer ------------------------------------------------------
    def ip_any(self, pkt: Packet, buf: bytes, off: int, end: int) -> None:
        if end <= off:
            raise Truncated("IP header")
        version = buf[off] >> 4
        if version == 4:
            self.ipv4(pkt, buf, off, end)
        elif version == 6:
            self.ipv6(pkt, buf, off, end)
        else:
            pkt.warnings.append(f"unknown IP version {version}")

    def ipv4(self, pkt: Packet, buf: bytes, off: int, end: int) -> None:
        if end - off < 20:
            raise Truncated("IPv4 header")
        vihl, tos, total_len, ident, flags_frag, ttl, proto, csum = struct.unpack_from("!BBHHHBBH", buf, off)
        version, ihl = vihl >> 4, (vihl & 0x0F) * 4
        if version != 4 or ihl < 20:
            raise ValueError(f"bad IPv4 header (version {version}, ihl {ihl})")
        if end - off < ihl:
            raise Truncated("IPv4 options")
        src, dst = buf[off + 12:off + 16], buf[off + 16:off + 20]
        csum_ok = inet_checksum(buf[off:off + ihl]) == 0 if self.verify_checksums else None
        df, mf = bool(flags_frag & 0x4000), bool(flags_frag & 0x2000)
        frag_off = (flags_frag & 0x1FFF) * 8
        ip_end = off + total_len
        if total_len < ihl:
            pkt.warnings.append(f"IPv4 total length {total_len} shorter than header")
            ip_end = end
        elif ip_end > end:
            if pkt.orig_len > len(pkt.data):
                pkt.warnings.append("frame cut short by snaplen")
            else:
                pkt.warnings.append(f"IPv4 length {total_len} exceeds frame")
            ip_end = end
        layer = pkt.add(Layer("ipv4", off, ihl, version=4, ihl=ihl, tos=tos, dscp=tos >> 2, ecn=tos & 3,
                              len=total_len, id=ident, df=df, mf=mf, frag_offset=frag_off, ttl=ttl,
                              proto=proto, proto_name=IP_PROTOS.get(proto, str(proto)),
                              checksum=csum, checksum_ok=csum_ok, src=ip4_str(src), dst=ip4_str(dst),
                              options=buf[off + 20:off + ihl].hex() if ihl > 20 else ""))
        if csum_ok is False:
            pkt.warnings.append("bad IPv4 header checksum")
        if mf or frag_off:
            layer.fields["fragment"] = True
            data, warns = self.defrag.add((4, src, dst, ident, proto), pkt.ts, frag_off,
                                          buf[off + ihl:ip_end], mf)
            pkt.warnings.extend(warns)
            if data is None:
                return
            layer.fields["reassembled"] = len(data)
            self.ip_payload(pkt, proto, data, 0, len(data), src, dst, in_frame=False)
            return
        self.ip_payload(pkt, proto, buf, off + ihl, ip_end, src, dst)

    def ipv6(self, pkt: Packet, buf: bytes, off: int, end: int) -> None:
        if end - off < 40:
            raise Truncated("IPv6 header")
        vtcfl, plen, nxt, hlim = struct.unpack_from("!IHBB", buf, off)
        src, dst = buf[off + 8:off + 24], buf[off + 24:off + 40]
        layer = pkt.add(Layer("ipv6", off, 40, version=6, tclass=(vtcfl >> 20) & 0xFF,
                              flow_label=vtcfl & 0xFFFFF, len=plen, next_header=nxt, hop_limit=hlim,
                              ttl=hlim, src=ip6_str(src), dst=ip6_str(dst)))
        p = off + 40
        ip_end = min(end, p + plen) if plen else end
        frag = None
        # Walk the extension header chain until we reach an upper-layer protocol
        while nxt in IPV6_EXT_HEADERS:
            if ip_end - p < 8:
                raise Truncated("IPv6 extension header")
            if nxt == 44:  # Fragment header
                n2, _, offmf, ident = struct.unpack_from("!BBHI", buf, p)
                frag = (offmf & 0xFFF8, bool(offmf & 1), ident)
                nxt, p = n2, p + 8
            elif nxt == 51:  # AH: length in 4-octet units
                nxt, p = buf[p], p + (buf[p + 1] + 2) * 4
            else:
                nxt, p = buf[p], p + (buf[p + 1] + 1) * 8
        layer.fields["proto"] = nxt
        layer.fields["proto_name"] = IP_PROTOS.get(nxt, str(nxt))
        if frag:
            frag_off, more, ident = frag
            layer.fields.update(fragment=True, frag_offset=frag_off, mf=more, id=ident)
            if frag_off or more:
                data, warns = self.defrag.add((6, src, dst, ident, nxt), pkt.ts, frag_off, buf[p:ip_end], more)
                pkt.warnings.extend(warns)
                if data is None:
                    return
                layer.fields["reassembled"] = len(data)
                self.ip_payload(pkt, nxt, data, 0, len(data), src, dst, in_frame=False)
                return
        self.ip_payload(pkt, nxt, buf, p, ip_end, src, dst)

    def ip_payload(self, pkt: Packet, proto: int, buf: bytes, off: int, end: int,
                   src: bytes, dst: bytes, in_frame: bool = True) -> None:
        if proto == 6:
            self.tcp(pkt, buf, off, end, src, dst, in_frame)
        elif proto == 17:
            self.udp(pkt, buf, off, end, src, dst, in_frame)
        elif proto == 1:
            self.icmp(pkt, buf, off, end, in_frame)
        elif proto == 58:
            self.icmpv6(pkt, buf, off, end, in_frame)
        elif proto == 2 and end - off >= 8:
            t, _, _, group = struct.unpack_from("!BBH4s", buf, off)
            pkt.add(Layer("igmp", off if in_frame else None, 8, type=t, group=ip4_str(group)))

    def _pseudo_checksum_ok(self, buf: bytes, off: int, end: int, src: bytes, dst: bytes, proto: int,
                            pkt: Packet) -> bool | None:
        if not self.verify_checksums or pkt.orig_len > len(pkt.data):
            return None
        seg = buf[off:end]
        if len(src) == 4:
            pseudo = src + dst + struct.pack("!BBH", 0, proto, len(seg))
        else:
            pseudo = src + dst + struct.pack("!I3xB", len(seg), proto)
        return inet_checksum(pseudo + seg) == 0

    # -- transport layer ----------------------------------------------------
    def tcp(self, pkt: Packet, buf: bytes, off: int, end: int, src: bytes, dst: bytes, in_frame: bool) -> None:
        if end - off < 20:
            raise Truncated("TCP header")
        sport, dport, seq, ack, off_flags, win, csum, urg = struct.unpack_from("!HHIIHHHH", buf, off)
        hlen = (off_flags >> 12) * 4
        flags = off_flags & 0x1FF
        if hlen < 20:
            raise ValueError(f"bad TCP data offset {hlen}")
        if end - off < hlen:
            raise Truncated("TCP options")
        options = parse_tcp_options(buf[off + 20:off + hlen])
        csum_ok = self._pseudo_checksum_ok(buf, off, end, src, dst, 6, pkt)
        fields = dict(sport=sport, dport=dport, seq=seq, ack=ack, hdr_len=hlen, flags=flags,
                      flags_str=tcp_flags_str(flags), flag_names=tcp_flag_names(flags),
                      window=win, checksum=csum, checksum_ok=csum_ok, urgent=urg, options=options,
                      len=end - off - hlen)
        for bit, name, _ in TCP_FLAGS:
            fields["flags." + name.lower()] = bool(flags & bit)
        for k in ("mss", "wscale", "sack_perm"):
            if k in options:
                fields[k] = options[k]
        pkt.add(Layer("tcp", off if in_frame else None, hlen, **fields))
        if csum_ok is False:
            pkt.warnings.append("bad TCP checksum")
        pkt.payload = bytes(buf[off + hlen:end])
        pkt.payload_offset = off + hlen if in_frame else None
        if pkt.payload:
            self.app_tcp(pkt, sport, dport)

    def udp(self, pkt: Packet, buf: bytes, off: int, end: int, src: bytes, dst: bytes, in_frame: bool) -> None:
        if end - off < 8:
            raise Truncated("UDP header")
        sport, dport, length, csum = struct.unpack_from("!HHHH", buf, off)
        udp_end = min(end, off + length) if length >= 8 else end
        csum_ok = None
        if csum != 0 or len(src) == 16:  # checksum 0 means "not computed" for IPv4
            csum_ok = self._pseudo_checksum_ok(buf, off, udp_end, src, dst, 17, pkt)
        pkt.add(Layer("udp", off if in_frame else None, 8, sport=sport, dport=dport, len=length,
                      checksum=csum, checksum_ok=csum_ok))
        if csum_ok is False:
            pkt.warnings.append("bad UDP checksum")
        pkt.payload = bytes(buf[off + 8:udp_end])
        pkt.payload_offset = off + 8 if in_frame else None
        if pkt.payload:
            self.app_udp(pkt, sport, dport)

    def icmp(self, pkt: Packet, buf: bytes, off: int, end: int, in_frame: bool) -> None:
        if end - off < 8:
            raise Truncated("ICMP header")
        t, code, csum, rest = struct.unpack_from("!BBHI", buf, off)
        fields = dict(type=t, code=code, type_name=ICMP_TYPES.get(t, f"type {t}"), checksum=csum,
                      checksum_ok=inet_checksum(buf[off:end]) == 0 if self.verify_checksums else None)
        if t in (0, 8, 13, 14):
            fields.update(id=rest >> 16, seq=rest & 0xFFFF)
        if t == 3:
            fields["code_name"] = ICMP_UNREACH.get(code, f"code {code}")
        if t in (3, 11) and end - off >= 28:
            # Quoted original datagram: lets us say *which* connection failed
            inner = Decoder(verify_checksums=False).decode(0, 0, bytes(buf[off + 8:end]), LINKTYPE_RAW)
            if inner.ip:
                fields["orig_src"], fields["orig_dst"] = inner.ip["src"], inner.ip["dst"]
                fields["orig_proto"] = inner.ip["proto_name"]
                if inner.dport is not None:
                    fields["orig_sport"], fields["orig_dport"] = inner.sport, inner.dport
        pkt.add(Layer("icmp", off if in_frame else None, 8, **fields))
        pkt.payload = bytes(buf[off + 8:end])
        pkt.payload_offset = off + 8 if in_frame else None

    def icmpv6(self, pkt: Packet, buf: bytes, off: int, end: int, in_frame: bool) -> None:
        if end - off < 4:
            raise Truncated("ICMPv6 header")
        t, code, csum = struct.unpack_from("!BBH", buf, off)
        fields = dict(type=t, code=code, type_name=ICMPV6_TYPES.get(t, f"type {t}"), checksum=csum)
        if t in (128, 129) and end - off >= 8:
            fields["id"], fields["seq"] = struct.unpack_from("!HH", buf, off + 4)
        if t in (135, 136) and end - off >= 24:
            fields["target"] = ip6_str(buf[off + 8:off + 24])
        pkt.add(Layer("icmpv6", off if in_frame else None, 4, **fields))

    # -- application layer (per-packet, best effort) ------------------------
    def app_tcp(self, pkt: Packet, sport: int, dport: int) -> None:
        data = pkt.payload
        if sport in DNS_PORTS or dport in DNS_PORTS:
            if len(data) > 2:
                (mlen,) = struct.unpack_from("!H", data, 0)
                if mlen <= len(data) - 2:
                    self._add_dns(pkt, data[2:2 + mlen], sport, dport, 2)
            return
        head = http.parse_head(data)
        if head is not None:
            pkt.add(Layer("http", pkt.payload_offset, head.pop("_head_len"), **head))
            return
        hello = tls.parse(data)
        if hello is not None:
            pkt.add(Layer("tls", pkt.payload_offset, len(data), **hello))

    def app_udp(self, pkt: Packet, sport: int, dport: int) -> None:
        if sport in DNS_PORTS or dport in DNS_PORTS:
            self._add_dns(pkt, pkt.payload, sport, dport, 0)
        elif {sport, dport} & {67, 68} and len(pkt.payload) >= 240:
            info = parse_dhcp(pkt.payload)
            if info:
                pkt.add(Layer("dhcp", pkt.payload_offset, len(pkt.payload), **info))

    def _add_dns(self, pkt: Packet, data: bytes, sport: int, dport: int, skip: int) -> None:
        try:
            msg = dns.parse(data)
        except dns.DNSError as e:
            pkt.warnings.append(f"malformed DNS ({e})")
            return
        name = "mdns" if 5353 in (sport, dport) else "dns"
        off = pkt.payload_offset + skip if pkt.payload_offset is not None else None
        pkt.add(Layer(name, off, len(data), **msg))


def parse_tcp_options(raw: bytes) -> dict:
    opts: dict = {}
    i = 0
    while i < len(raw):
        kind = raw[i]
        if kind == 0:
            break
        if kind == 1:
            i += 1
            continue
        if i + 1 >= len(raw):
            break
        length = raw[i + 1]
        if length < 2 or i + length > len(raw):
            opts["malformed"] = True
            break
        val = raw[i + 2:i + length]
        if kind == 2 and length == 4:
            opts["mss"] = struct.unpack("!H", val)[0]
        elif kind == 3 and length == 3:
            opts["wscale"] = val[0]
        elif kind == 4:
            opts["sack_perm"] = True
        elif kind == 5:
            opts["sack"] = [struct.unpack_from("!II", val, j) for j in range(0, len(val) - 7, 8)]
        elif kind == 8 and length == 10:
            opts["ts_val"], opts["ts_ecr"] = struct.unpack("!II", val)
        else:
            opts[f"opt{kind}"] = val.hex()
        i += length
    return opts


DHCP_TYPES = {1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 4: "DECLINE", 5: "ACK", 6: "NAK", 7: "RELEASE", 8: "INFORM"}


def parse_dhcp(data: bytes) -> dict | None:
    if data[236:240] != b"\x63\x82\x53\x63":  # magic cookie
        return None
    op, _, _, _, xid = struct.unpack_from("!BBBBI", data, 0)
    info = dict(op=op, xid=xid, client_ip=ip4_str(data[12:16]), your_ip=ip4_str(data[16:20]),
                client_mac=mac_str(data[28:34]))
    i = 240
    while i < len(data) and data[i] != 255:
        code = data[i]
        if code == 0:
            i += 1
            continue
        if i + 1 >= len(data):
            break
        ln = data[i + 1]
        val = data[i + 2:i + 2 + ln]
        if code == 53 and val:
            info["msg_type"] = DHCP_TYPES.get(val[0], str(val[0]))
        elif code == 12:
            info["hostname"] = printable(val.decode("ascii", "replace"))
        elif code == 50 and ln == 4:
            info["requested_ip"] = ip4_str(val)
        i += 2 + ln
    return info
