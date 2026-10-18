"""Reading and writing capture files by hand: classic libpcap and pcapng.

Both formats are parsed with ``struct`` straight from the file bytes, so the
analyzer can open anything tcpdump or Wireshark saves without libpcap.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import BinaryIO, Iterator

# Link-layer header types (https://www.tcpdump.org/linktypes.html)
LINKTYPE_NULL = 0          # BSD loopback (macOS lo0)
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101         # raw IPv4/IPv6, no link header
LINKTYPE_LINUX_SLL = 113   # Linux "cooked" capture (tcpdump -i any)
LINKTYPE_IPV4 = 228
LINKTYPE_IPV6 = 229

PCAP_MAGIC_US = 0xA1B2C3D4
PCAP_MAGIC_NS = 0xA1B23C4D
PCAPNG_SHB = 0x0A0D0D0A
PCAPNG_BOM = 0x1A2B3C4D

# Largest record we will allocate. Real snaplens top out at 256 KiB; a 4 GiB
# length field means the file is corrupt, not that we should try to read it.
MAX_RECORD = 64 * 1024 * 1024
MAX_TS = 253402300799.0  # 9999-12-31: past this datetime() refuses to format a corrupt timestamp


@dataclass
class Frame:
    """One captured frame exactly as it came off the wire (or out of a file)."""
    ts: float
    data: bytes
    linktype: int
    orig_len: int


class CaptureFormatError(Exception):
    pass


def open_capture(path: str) -> Iterator[Frame]:
    """Yield frames from a .pcap or .pcapng file, sniffing the format from its magic."""
    with open(path, "rb") as f:
        head = f.read(4)
        f.seek(0)
        if len(head) < 4:
            raise CaptureFormatError(f"{path}: file too short to be a capture")
        (magic_be,) = struct.unpack(">I", head)
        (magic_le,) = struct.unpack("<I", head)
        try:
            if magic_be == PCAPNG_SHB:
                yield from _read_pcapng(f)
            elif {magic_be, magic_le} & {PCAP_MAGIC_US, PCAP_MAGIC_NS}:
                yield from _read_pcap(f)
            else:
                raise CaptureFormatError(f"{path}: not a pcap or pcapng file (magic {head.hex()})")
        except (struct.error, IndexError) as e:
            raise CaptureFormatError(f"{path}: corrupt capture file ({e})") from None


def _read_pcap(f: BinaryIO) -> Iterator[Frame]:
    # Global header: magic, major, minor, thiszone, sigfigs, snaplen, network
    hdr = f.read(24)
    if len(hdr) < 24:
        raise CaptureFormatError("pcap global header is truncated")
    (magic,) = struct.unpack("<I", hdr[:4])
    if magic in (PCAP_MAGIC_US, PCAP_MAGIC_NS):
        endian = "<"
    else:
        endian = ">"
        (magic,) = struct.unpack(">I", hdr[:4])
    divisor = 1e9 if magic == PCAP_MAGIC_NS else 1e6
    _, _, _, _, _, linktype = struct.unpack(endian + "HHiIII", hdr[4:24])
    rec = struct.Struct(endian + "IIII")
    while True:
        rh = f.read(16)
        if len(rh) < 16:
            return
        ts_sec, ts_frac, incl_len, orig_len = rec.unpack(rh)
        if incl_len > MAX_RECORD:
            raise CaptureFormatError(f"corrupt pcap record length {incl_len}")
        data = f.read(incl_len)
        if len(data) < incl_len:
            return  # truncated final record, as tcpdump does when killed mid-write
        yield Frame(min(ts_sec + ts_frac / divisor, MAX_TS), data, linktype, orig_len)


def _read_pcapng(f: BinaryIO) -> Iterator[Frame]:
    endian = "<"
    interfaces: list[tuple[int, float]] = []  # (linktype, seconds per timestamp unit)
    while True:
        bh = f.read(8)
        if len(bh) < 8:
            return
        (btype,) = struct.unpack(endian + "I", bh[:4])
        if btype == PCAPNG_SHB:
            # Section header: the byte-order magic tells us the endianness of the section
            bom = f.read(4)
            if len(bom) < 4:
                return
            (bom_le,) = struct.unpack("<I", bom)
            if bom_le == PCAPNG_BOM:
                endian = "<"
            elif struct.unpack(">I", bom)[0] == PCAPNG_BOM:
                endian = ">"
            else:
                raise CaptureFormatError("corrupt pcapng section header (bad byte-order magic)")
            (blen,) = struct.unpack(endian + "I", bh[4:8])
            if blen < 28 or blen > MAX_RECORD or blen % 4:
                raise CaptureFormatError(f"corrupt pcapng section header length {blen}")
            f.read(blen - 12)
            interfaces = []
            continue
        (blen,) = struct.unpack(endian + "I", bh[4:8])
        if blen < 12 or blen > MAX_RECORD:
            raise CaptureFormatError(f"corrupt pcapng block length {blen}")
        body = f.read(blen - 12)
        if len(body) < blen - 12:
            return  # truncated final block
        f.read(4)  # trailing copy of the block length
        if btype == 1:  # Interface Description Block
            linktype, _, _snaplen = struct.unpack_from(endian + "HHI", body, 0)
            interfaces.append((linktype, _if_tsresol(body[8:], endian)))
        elif btype == 6:  # Enhanced Packet Block
            if_id, ts_hi, ts_lo, cap_len, orig_len = struct.unpack_from(endian + "IIIII", body, 0)
            linktype, unit = interfaces[if_id] if if_id < len(interfaces) else (LINKTYPE_ETHERNET, 1e-6)
            ts = min(((ts_hi << 32) | ts_lo) * unit, MAX_TS)
            yield Frame(ts, bytes(body[20:20 + cap_len]), linktype, orig_len)
        elif btype == 3:  # Simple Packet Block (no timestamp)
            (orig_len,) = struct.unpack_from(endian + "I", body, 0)
            linktype = interfaces[0][0] if interfaces else LINKTYPE_ETHERNET
            yield Frame(0.0, bytes(body[4:4 + orig_len]), linktype, orig_len)
        elif btype == 2:  # obsolete Packet Block
            if_id, _drops, ts_hi, ts_lo, cap_len, orig_len = struct.unpack_from(endian + "HHIIII", body, 0)
            linktype, unit = interfaces[if_id] if if_id < len(interfaces) else (LINKTYPE_ETHERNET, 1e-6)
            yield Frame(min(((ts_hi << 32) | ts_lo) * unit, MAX_TS), bytes(body[20:20 + cap_len]), linktype, orig_len)
        # Every other block type (name resolution, stats, custom) is skipped.


def _if_tsresol(opts: bytes, endian: str) -> float:
    """Read the if_tsresol option (code 9); default is microseconds."""
    off = 0
    while off + 4 <= len(opts):
        code, length = struct.unpack_from(endian + "HH", opts, off)
        if code == 0:
            break
        if code == 9 and length >= 1:
            v = opts[off + 4]
            return 2.0 ** -(v & 0x7F) if v & 0x80 else 10.0 ** -v
        off += 4 + ((length + 3) & ~3)
    return 1e-6


class PcapWriter:
    """Write frames to a classic microsecond pcap that any tool can open."""

    def __init__(self, path: str, linktype: int = LINKTYPE_ETHERNET, snaplen: int = 262144):
        self._f = open(path, "wb")
        self._f.write(struct.pack("<IHHiIII", PCAP_MAGIC_US, 2, 4, 0, 0, snaplen, linktype))
        self.linktype = linktype

    def write(self, ts: float, data: bytes, orig_len: int | None = None) -> None:
        sec = int(ts)
        usec = int(round((ts - sec) * 1e6))
        if usec >= 1_000_000:
            sec, usec = sec + 1, usec - 1_000_000
        self._f.write(struct.pack("<IIII", sec, usec, len(data), orig_len or len(data)))
        self._f.write(data)

    def close(self) -> None:
        self._f.close()

    def __enter__(self) -> "PcapWriter":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
