"""TLS dissection without decryption.

Most real traffic is HTTPS. Even without keys, the handshake is in the clear up
to the point keys are agreed: the ClientHello names the site (SNI) and offers
ciphers, the ServerHello picks the version and cipher suite, and in TLS 1.2 and
older the server's certificate chain follows in plain sight.
"""
from __future__ import annotations

import struct

from . import x509
from .packet import printable

CONTENT_TYPES = {20: "ChangeCipherSpec", 21: "Alert", 22: "Handshake", 23: "ApplicationData", 24: "Heartbeat"}
HANDSHAKE_TYPES = {1: "ClientHello", 2: "ServerHello", 4: "NewSessionTicket", 8: "EncryptedExtensions",
                   11: "Certificate", 12: "ServerKeyExchange", 13: "CertificateRequest",
                   14: "ServerHelloDone", 15: "CertificateVerify", 16: "ClientKeyExchange", 20: "Finished"}
VERSIONS = {0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2", 0x0304: "TLS 1.3"}
OLD_VERSIONS = {"SSL 3.0", "TLS 1.0", "TLS 1.1"}
CIPHER_SUITES = {
    0x0000: "TLS_NULL_WITH_NULL_NULL", 0x0001: "TLS_RSA_WITH_NULL_MD5", 0x0002: "TLS_RSA_WITH_NULL_SHA",
    0x0003: "TLS_RSA_EXPORT_WITH_RC4_40_MD5", 0x0004: "TLS_RSA_WITH_RC4_128_MD5", 0x0005: "TLS_RSA_WITH_RC4_128_SHA",
    0x0008: "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA", 0x0009: "TLS_RSA_WITH_DES_CBC_SHA",
    0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA", 0x0016: "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
    0x0018: "TLS_DH_anon_WITH_RC4_128_MD5", 0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
    0x0033: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA", 0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
    0x0039: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA", 0x003C: "TLS_RSA_WITH_AES_128_CBC_SHA256",
    0x003D: "TLS_RSA_WITH_AES_256_CBC_SHA256", 0x0067: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
    0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256", 0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
    0x009E: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", 0x009F: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    0x00FF: "TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
    0x1301: "TLS_AES_128_GCM_SHA256", 0x1302: "TLS_AES_256_GCM_SHA384", 0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0xC009: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", 0xC00A: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    0xC011: "TLS_ECDHE_RSA_WITH_RC4_128_SHA", 0xC012: "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
    0xC013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", 0xC014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    0xC023: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", 0xC024: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
    0xC027: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", 0xC028: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
    0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", 0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", 0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", 0xCCA9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
}
WEAK_MARKERS = ("NULL", "EXPORT", "RC4", "_DES_", "DES40", "3DES", "_MD5", "anon")
ALERT_DESCRIPTIONS = {0: "close_notify", 10: "unexpected_message", 20: "bad_record_mac", 40: "handshake_failure",
                      42: "bad_certificate", 43: "unsupported_certificate", 44: "certificate_revoked",
                      45: "certificate_expired", 46: "certificate_unknown", 47: "illegal_parameter",
                      48: "unknown_ca", 50: "decode_error", 51: "decrypt_error", 70: "protocol_version",
                      71: "insufficient_security", 80: "internal_error", 86: "inappropriate_fallback",
                      90: "user_canceled", 112: "unrecognized_name", 116: "certificate_required",
                      120: "no_application_protocol"}


def cipher_name(code: int) -> str:
    return CIPHER_SUITES.get(code, f"0x{code:04X}")


def is_weak_cipher(name: str) -> bool:
    return any(m in name for m in WEAK_MARKERS)


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
    if ctype == 21 and len(data) >= 7 and length == 2:
        info["alert_level"] = "fatal" if data[5] == 2 else "warning"
        info["alert"] = ALERT_DESCRIPTIONS.get(data[6], str(data[6]))
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
        info["cipher"] = cipher_name(info["cipher_suite"])
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
            info["sni"] = printable(ext[5:5 + name_len].decode("ascii", "replace"))
        elif etype == 16 and len(ext) >= 3:  # ALPN
            alpn, q = [], 2
            while q < len(ext):
                n = ext[q]
                alpn.append(printable(ext[q + 1:q + 1 + n].decode("ascii", "replace")))
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
    if "alert" in info:
        s += f" ({info['alert_level']} {info['alert']})"
    if "sni" in info:
        s += f" SNI={info['sni']}"
    if info.get("handshake") == "ServerHello" and info.get("hello_version"):
        s += f" ({info['hello_version']}"
        s += f", {info['cipher']})" if info.get("cipher") else ")"
    return s


class TlsStreamParser:
    """Reads one direction of a reassembled TCP stream as TLS records.

    Handshake messages can span several records and records can span several
    TCP segments, so both are buffered until complete. Parsing stops at
    ChangeCipherSpec (everything after it is encrypted) or at the first byte
    that isn't a TLS record header.
    """

    MAX_BUFFER = 256 * 1024

    def __init__(self):
        self.buf = bytearray()
        self.hs = bytearray()
        self.dead = False
        self.encrypted = False

    def feed(self, data: bytes) -> list[dict]:
        if self.dead:
            return []
        self.buf += data
        out: list[dict] = []
        while len(self.buf) >= 5:
            ctype, ver, length = struct.unpack_from("!BHH", self.buf, 0)
            if ctype not in CONTENT_TYPES or ver >> 8 != 3 or length > 18432 + 2048:
                self.dead = True
                break
            if len(self.buf) < 5 + length:
                if len(self.buf) > self.MAX_BUFFER:
                    self.dead = True
                break
            rec = bytes(self.buf[5:5 + length])
            del self.buf[:5 + length]
            if ctype == 20:
                self.encrypted = True
            elif ctype == 21 and not self.encrypted and len(rec) >= 2:
                out.append(dict(type="Alert", level="fatal" if rec[0] == 2 else "warning",
                                description=ALERT_DESCRIPTIONS.get(rec[1], str(rec[1]))))
            elif ctype == 22 and not self.encrypted:
                self.hs += rec
                out.extend(self._handshake_messages())
            elif ctype == 23:
                self.encrypted = True
                self.dead = True  # application data from here on; nothing more to learn
                break
        return out

    def _handshake_messages(self) -> list[dict]:
        out = []
        while len(self.hs) >= 4:
            htype = self.hs[0]
            ln = int.from_bytes(self.hs[1:4], "big")
            if len(self.hs) < 4 + ln:
                break
            body = bytes(self.hs[4:4 + ln])
            del self.hs[:4 + ln]
            msg: dict = dict(type=HANDSHAKE_TYPES.get(htype, f"type {htype}"))
            try:
                if htype in (1, 2):
                    _parse_hello(body, htype == 1, msg)
                elif htype == 11:
                    msg["certs"] = _parse_certificates(body)
            except (struct.error, IndexError, x509.DERError, ValueError) as e:
                msg["error"] = str(e)
            out.append(msg)
        return out


def _parse_certificates(body: bytes) -> list[dict]:
    """TLS 1.2 Certificate message: 3-byte total length, then 3-byte length + DER per certificate."""
    total = int.from_bytes(body[0:3], "big")
    p, end = 3, min(len(body), 3 + total)
    certs = []
    while p + 3 <= end:
        ln = int.from_bytes(body[p:p + 3], "big")
        der = body[p + 3:p + 3 + ln]
        p += 3 + ln
        try:
            certs.append(x509.parse_certificate(der))
        except (x509.DERError, IndexError, ValueError) as e:
            certs.append(dict(error=f"unparsable certificate ({e})", size=len(der)))
    return certs
