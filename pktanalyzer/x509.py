"""A small DER/ASN.1 reader that pulls the useful fields out of X.509 certificates.

Certificates are nested TLV (tag, length, value) structures. We walk them by
hand to get the subject, issuer, validity window, SANs, key type and size,
signature algorithm and fingerprints. Signatures are not verified: this is for
inspection, not trust decisions.
"""
from __future__ import annotations

import calendar
import hashlib

OID_NAMES = {
    "2.5.4.3": "CN", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "ST", "2.5.4.10": "O", "2.5.4.11": "OU",
    "1.2.840.113549.1.9.1": "emailAddress",
}
SIG_ALGS = {
    "1.2.840.113549.1.1.4": "md5WithRSAEncryption", "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption", "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
    "1.2.840.113549.1.1.13": "sha512WithRSAEncryption", "1.2.840.113549.1.1.10": "rsassa-pss",
    "1.2.840.10045.4.1": "ecdsa-with-SHA1", "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
    "1.2.840.10045.4.3.3": "ecdsa-with-SHA384", "1.2.840.10045.4.3.4": "ecdsa-with-SHA512", "1.3.101.112": "Ed25519",
}
KEY_ALGS = {"1.2.840.113549.1.1.1": "RSA", "1.2.840.10045.2.1": "EC", "1.3.101.112": "Ed25519",
            "1.3.101.110": "X25519", "1.2.840.10040.4.1": "DSA"}
CURVES = {"1.2.840.10045.3.1.7": "P-256", "1.3.132.0.34": "P-384", "1.3.132.0.35": "P-521"}
EXT_SAN, EXT_BASIC = "2.5.29.17", "2.5.29.19"


class DERError(Exception):
    pass


def tlv(b: bytes, off: int) -> tuple[int, int, int]:
    """Read one TLV at ``off``; return (tag, value_start, value_end)."""
    if off + 2 > len(b):
        raise DERError("truncated TLV")
    tag = b[off]
    ln = b[off + 1]
    off += 2
    if ln & 0x80:
        n = ln & 0x7F
        if n == 0 or n > 4 or off + n > len(b):
            raise DERError("bad length")
        ln = int.from_bytes(b[off:off + n], "big")
        off += n
    if off + ln > len(b):
        raise DERError("value runs past end")
    return tag, off, off + ln


def children(b: bytes, start: int, end: int) -> list[tuple[int, int, int]]:
    out, off = [], start
    while off < end:
        tag, vs, ve = tlv(b, off)
        out.append((tag, vs, ve))
        off = ve
    return out


def oid(b: bytes) -> str:
    if not b:
        return ""
    parts = [b[0] // 40, b[0] % 40]
    v = 0
    for byte in b[1:]:
        v = (v << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(v)
            v = 0
    return ".".join(map(str, parts))


def _string(tag: int, raw: bytes) -> str:
    if tag == 0x1E:  # BMPString
        return raw.decode("utf-16-be", "replace")
    return raw.decode("utf-8", "replace")


def parse_name(b: bytes, start: int, end: int) -> tuple[dict, str]:
    """RDNSequence → ({'CN': ..., 'O': ...}, 'CN=..., O=...')."""
    fields: dict[str, str] = {}
    parts = []
    for _, ss, se in children(b, start, end):          # SET
        for _, as_, ae in children(b, ss, se):          # AttributeTypeAndValue SEQUENCE
            items = children(b, as_, ae)
            if len(items) < 2:
                continue
            name = OID_NAMES.get(oid(b[items[0][1]:items[0][2]]), oid(b[items[0][1]:items[0][2]]))
            value = _string(items[1][0], b[items[1][1]:items[1][2]])
            fields.setdefault(name, value)
            parts.append(f"{name}={value}")
    return fields, ", ".join(parts)


def parse_time(tag: int, raw: bytes) -> float:
    s = raw.decode("ascii").rstrip("Z")
    if tag == 0x17:  # UTCTime YYMMDDHHMM[SS]
        year = int(s[:2])
        year += 2000 if year < 50 else 1900
        rest = s[2:]
    else:            # GeneralizedTime YYYYMMDDHHMM[SS]
        year = int(s[:4])
        rest = s[4:]
    rest = rest.split(".")[0].ljust(10, "0")
    mon, day, hh, mm, ss = (int(rest[i:i + 2]) for i in range(0, 10, 2))
    return float(calendar.timegm((year, mon, day, hh, mm, ss, 0, 0, 0)))


def _fp(data: bytes, algo: str) -> str:
    return ":".join(f"{x:02X}" for x in hashlib.new(algo, data).digest())


def parse_certificate(der: bytes) -> dict:
    """Parse one DER certificate into a flat dict of the fields worth showing."""
    _, cs, ce = tlv(der, 0)
    cert_parts = children(der, cs, ce)
    if len(cert_parts) < 3:
        raise DERError("not a certificate")
    _, ts, te = cert_parts[0]
    tbs = children(der, ts, te)
    i = 0
    version = 1
    if tbs[0][0] == 0xA0:  # [0] EXPLICIT version
        _, vs, ve = tlv(der, tbs[0][1])
        version = int.from_bytes(der[vs:ve], "big") + 1
        i = 1
    serial = der[tbs[i][1]:tbs[i][2]].hex()
    issuer_f, issuer = parse_name(der, tbs[i + 2][1], tbs[i + 2][2])
    validity = children(der, tbs[i + 3][1], tbs[i + 3][2])
    not_before = parse_time(validity[0][0], der[validity[0][1]:validity[0][2]])
    not_after = parse_time(validity[1][0], der[validity[1][1]:validity[1][2]])
    subject_f, subject = parse_name(der, tbs[i + 4][1], tbs[i + 4][2])

    spki = children(der, tbs[i + 5][1], tbs[i + 5][2])
    alg = children(der, spki[0][1], spki[0][2])
    key_oid = oid(der[alg[0][1]:alg[0][2]])
    key_alg = KEY_ALGS.get(key_oid, key_oid)
    key_bits = None
    curve = None
    if key_alg == "RSA":
        bits_start = spki[1][1] + 1  # skip the BIT STRING's unused-bits byte
        _, ks, ke = tlv(der, bits_start)
        n_tag, ns, ne = children(der, ks, ke)[0]
        n = der[ns:ne].lstrip(b"\x00")
        key_bits = len(n) * 8 - (8 - n[0].bit_length()) if n else 0
    elif key_alg == "EC" and len(alg) > 1:
        curve = CURVES.get(oid(der[alg[1][1]:alg[1][2]]), oid(der[alg[1][1]:alg[1][2]]))
        key_bits = {"P-256": 256, "P-384": 384, "P-521": 521}.get(curve)

    sans: list[str] = []
    is_ca = False
    for tag, vs, ve in tbs[i + 6:]:
        if tag != 0xA3:  # [3] extensions
            continue
        _, xs, xe = tlv(der, vs)
        for _, es, ee in children(der, xs, xe):
            ext = children(der, es, ee)
            ext_oid = oid(der[ext[0][1]:ext[0][2]])
            value = ext[-1]  # OCTET STRING wrapping the extension's own DER
            if ext_oid == EXT_SAN:
                _, ss, se = tlv(der, value[1])
                for gtag, gs, ge in children(der, ss, se):
                    if gtag == 0x82:
                        sans.append(der[gs:ge].decode("ascii", "replace"))
                    elif gtag == 0x87:
                        raw = der[gs:ge]
                        sans.append(".".join(map(str, raw)) if len(raw) == 4 else raw.hex())
            elif ext_oid == EXT_BASIC:
                _, bs, be = tlv(der, value[1])
                inner = children(der, bs, be)
                is_ca = bool(inner and inner[0][0] == 0x01 and der[inner[0][1]] != 0)

    sig_alg_parts = children(der, cert_parts[1][1], cert_parts[1][2])
    sig_alg = oid(der[sig_alg_parts[0][1]:sig_alg_parts[0][2]])
    cert_der = der[:ce]
    return dict(version=version, serial=serial, subject=subject, subject_cn=subject_f.get("CN", ""),
                subject_o=subject_f.get("O", ""), issuer=issuer, issuer_cn=issuer_f.get("CN", ""),
                issuer_o=issuer_f.get("O", ""), not_before=not_before, not_after=not_after, sans=sans,
                key_alg=key_alg, key_bits=key_bits, curve=curve, sig_alg=SIG_ALGS.get(sig_alg, sig_alg),
                is_ca=is_ca, self_signed=issuer == subject, sha1=_fp(cert_der, "sha1"),
                sha256=_fp(cert_der, "sha256"), size=len(cert_der))


def name_matches(hostname: str, cert: dict) -> bool:
    """RFC 6125-style check: does the certificate cover this hostname (wildcards in the left label only)?"""
    host = hostname.lower().rstrip(".")
    names = cert["sans"] or ([cert["subject_cn"]] if cert["subject_cn"] else [])
    for name in names:
        name = name.lower().rstrip(".")
        if name == host:
            return True
        if name.startswith("*.") and "." in host and host.split(".", 1)[1] == name[2:]:
            return True
    return False
