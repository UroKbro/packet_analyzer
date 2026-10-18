"""DNS message dissector (RFC 1035), including name compression pointers."""
from __future__ import annotations

import socket
import struct

from .packet import printable

TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 13: "HINFO", 15: "MX", 16: "TXT",
         28: "AAAA", 33: "SRV", 35: "NAPTR", 41: "OPT", 43: "DS", 46: "RRSIG", 47: "NSEC",
         48: "DNSKEY", 64: "SVCB", 65: "HTTPS", 99: "SPF", 255: "ANY", 257: "CAA"}
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}
OPCODES = {0: "QUERY", 1: "IQUERY", 2: "STATUS", 4: "NOTIFY", 5: "UPDATE"}


class DNSError(Exception):
    pass


def type_name(t: int) -> str:
    return TYPES.get(t, f"TYPE{t}")


def read_name(data: bytes, off: int) -> tuple[str, int]:
    """Decode a possibly-compressed domain name; return (name, offset after it).

    A length byte with the top two bits set is a 14-bit pointer back into the
    message. We follow at most 32 pointers so a malicious loop cannot hang us.
    """
    labels: list[str] = []
    jumps = 0
    end_off = None
    while True:
        if off >= len(data):
            raise DNSError("name runs past end of message")
        ln = data[off]
        if ln & 0xC0 == 0xC0:
            if off + 1 >= len(data):
                raise DNSError("truncated compression pointer")
            if end_off is None:
                end_off = off + 2
            off = ((ln & 0x3F) << 8) | data[off + 1]
            jumps += 1
            if jumps > 32:
                raise DNSError("compression pointer loop")
            continue
        if ln & 0xC0:
            raise DNSError(f"bad label type 0x{ln:02x}")
        off += 1
        if ln == 0:
            break
        if off + ln > len(data):
            raise DNSError("label runs past end of message")
        labels.append(printable(data[off:off + ln].decode("ascii", "backslashreplace")))
        off += ln
    return ".".join(labels) or ".", end_off if end_off is not None else off


def _rdata(data: bytes, off: int, rtype: int, rdlen: int):
    rd = data[off:off + rdlen]
    if rtype == 1 and rdlen == 4:
        return socket.inet_ntop(socket.AF_INET, rd)
    if rtype == 28 and rdlen == 16:
        return socket.inet_ntop(socket.AF_INET6, rd)
    if rtype in (2, 5, 12):
        return read_name(data, off)[0]
    if rtype == 15:
        pref = struct.unpack_from("!H", data, off)[0]
        return f"{pref} {read_name(data, off + 2)[0]}"
    if rtype == 16:
        parts, i = [], 0
        while i < len(rd):
            n = rd[i]
            parts.append(printable(rd[i + 1:i + 1 + n].decode("utf-8", "replace")))
            i += 1 + n
        return " ".join(f'"{p}"' for p in parts)
    if rtype == 33:
        prio, weight, port = struct.unpack_from("!HHH", data, off)
        return f"{prio} {weight} {port} {read_name(data, off + 6)[0]}"
    if rtype == 6:
        mname, p = read_name(data, off)
        rname, p = read_name(data, p)
        serial = struct.unpack_from("!I", data, p)[0]
        return f"{mname} {rname} serial={serial}"
    return rd.hex()


def parse(data: bytes) -> dict:
    if len(data) < 12:
        raise DNSError("message shorter than 12-byte header")
    ident, flags, qd, an, ns, ar = struct.unpack_from("!HHHHHH", data, 0)
    msg = dict(id=ident, response=bool(flags & 0x8000), opcode=OPCODES.get((flags >> 11) & 0xF, str((flags >> 11) & 0xF)),
               aa=bool(flags & 0x400), tc=bool(flags & 0x200), rd=bool(flags & 0x100), ra=bool(flags & 0x80),
               rcode=flags & 0xF, rcode_name=RCODES.get(flags & 0xF, str(flags & 0xF)),
               qdcount=qd, ancount=an, nscount=ns, arcount=ar)
    off = 12
    questions = []
    for _ in range(min(qd, 64)):
        name, off = read_name(data, off)
        if off + 4 > len(data):
            raise DNSError("truncated question")
        qtype, qclass = struct.unpack_from("!HH", data, off)
        off += 4
        questions.append(dict(name=name, type=type_name(qtype), qtype=qtype, qclass=qclass & 0x7FFF))
    sections = {"answers": [], "authority": [], "additional": []}
    for key, count in (("answers", an), ("authority", ns), ("additional", ar)):
        for _ in range(min(count, 256)):
            if off >= len(data):
                break
            name, off = read_name(data, off)
            if off + 10 > len(data):
                raise DNSError("truncated resource record")
            rtype, rclass, ttl, rdlen = struct.unpack_from("!HHIH", data, off)
            off += 10
            if off + rdlen > len(data):
                raise DNSError("resource record data runs past end")
            if rtype != 41:  # skip EDNS0 OPT pseudo-records
                sections[key].append(dict(name=name, type=type_name(rtype), ttl=ttl,
                                          data=_rdata(data, off, rtype, rdlen)))
            off += rdlen
    msg["questions"] = questions
    msg.update(sections)
    if questions:
        msg["qname"] = questions[0]["name"]
        msg["qtype"] = questions[0]["type"]
    msg["answer_data"] = [a["data"] for a in sections["answers"]]
    return msg


def summary(msg: dict) -> str:
    q = f"{msg.get('qtype', '?')} {msg.get('qname', '?')}"
    if not msg["response"]:
        return f"Standard query 0x{msg['id']:04x} {q}"
    if msg["rcode"]:
        return f"Response 0x{msg['id']:04x} {q} {msg['rcode_name']}"
    ans = ", ".join(f"{a['type']} {a['data']}" for a in msg["answers"][:3])
    more = f" (+{len(msg['answers']) - 3})" if len(msg["answers"]) > 3 else ""
    return f"Response 0x{msg['id']:04x} {q} -> {ans or 'no answers'}{more}"
