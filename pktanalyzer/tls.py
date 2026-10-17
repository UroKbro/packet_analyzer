"""Just enough TLS record parsing to name the protocol and pull out the SNI.

Most real traffic is HTTPS, so even without decryption the ClientHello's
server_name extension tells you which site a connection was for.
"""
from __future__ import annotations

import struct

CONTENT_TYPES = {20: "ChangeCipherSpec", 21: "Alert", 22: "Handshake", 23: "ApplicationData", 24: "Heartbeat"}
HANDSHAKE_TYPES = {1: "ClientHello", 2: "ServerHello", 4: "NewSessionTicket", 8: "EncryptedExtensions",
                   11: "Certificate", 12: "ServerKeyExchange", 13: "CertificateRequest",
                   14: "ServerHelloDone", 15: "CertificateVerify", 16: "ClientKeyExchange", 20: "Finished"}
VERSIONS = {0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2", 0x0304: "TLS 1.3"}


def parse(data: bytes) -> dict | None:
    if len(data) < 5:
        return None
    ctype, ver, length = struct.unpack_from("!BHH", data, 0)
    if ctype not in CONTENT_TYPES or ver >> 8 != 3 or length > 18432:
        return None
    info: dict = dict(content_type=CONTENT_TYPES[ctype], record_version=VERSIONS.get(ver, hex(ver)),
                      record_len=length)
    if ctype == 22 and len(data) >= 9:
        htype = data[5]
        info["handshake"] = HANDSHAKE_TYPES.get(htype, f"type {htype}")
        if htype in (1, 2):
            try:
                _parse_hello(data[9:5 + length], htype == 1, info)
            except (struct.error, IndexError):
                info["truncated"] = True
    if ctype == 24:
        info["heartbeat"] = True
    return info


def _parse_hello(body: bytes, client: bool, info: dict) -> None:
    (ver,) = struct.unpack_from("!H", body, 0)
    info["hello_version"] = VERSIONS.get(ver, hex(ver))
    p = 2 + 32  # version + random
    sid_len = body[p]
    p += 1 + sid_len
    if client:
        (cs_len,) = struct.unpack_from("!H", body, p)
        info["cipher_suites"] = cs_len // 2
        p += 2 + cs_len
        p += 1 + body[p]  # compression methods
    else:
        (info["cipher_suite"],) = struct.unpack_from("!H", body, p)
        p += 3
    if p + 2 > len(body):
        return
    (ext_total,) = struct.unpack_from("!H", body, p)
    p += 2
    end = min(len(body), p + ext_total)
    while p + 4 <= end:
        etype, elen = struct.unpack_from("!HH", body, p)
        ext = body[p + 4:p + 4 + elen]
        if etype == 0 and client and len(ext) >= 5:  # server_name
            name_len = struct.unpack_from("!H", ext, 3)[0]
            info["sni"] = ext[5:5 + name_len].decode("ascii", "replace")
        elif etype == 16 and len(ext) >= 3:  # ALPN
            alpn, q = [], 2
            while q < len(ext):
                n = ext[q]
                alpn.append(ext[q + 1:q + 1 + n].decode("ascii", "replace"))
                q += 1 + n
            info["alpn"] = ",".join(alpn)
        elif etype == 43:  # supported_versions
            if client and ext:
                vers = [struct.unpack_from("!H", ext, 1 + i)[0] for i in range(0, ext[0], 2)]
                if 0x0304 in vers:
                    info["offers_tls13"] = True
            elif len(ext) >= 2:
                info["hello_version"] = VERSIONS.get(struct.unpack("!H", ext[:2])[0], "?")
        p += 4 + elen


def summary(info: dict) -> str:
    s = info.get("handshake") or info["content_type"]
    if "sni" in info:
        s += f" SNI={info['sni']}"
    if info.get("handshake") == "ServerHello" and info.get("hello_version"):
        s += f" ({info['hello_version']})"
    return s
