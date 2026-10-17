"""Live capture from a raw socket.

On Linux an ``AF_PACKET`` socket hands us every Ethernet frame on an interface,
link header included. macOS has no ``AF_PACKET``; there we read the BPF device
(``/dev/bpf*``) directly, which is what libpcap does underneath. Both need root.
"""
from __future__ import annotations

import fcntl
import os
import socket
import struct
import sys
import time
from typing import Iterator

from .pcap import LINKTYPE_ETHERNET, LINKTYPE_NULL, Frame

ETH_P_ALL = 0x0003
SOL_PACKET = 263
PACKET_ADD_MEMBERSHIP = 1
PACKET_MR_PROMISC = 1
PACKET_OUTGOING = 4


class CaptureError(Exception):
    pass


def list_interfaces() -> list[str]:
    try:
        return [name for _, name in socket.if_nameindex()]
    except OSError:
        return []


def default_interface() -> str:
    names = list_interfaces()
    for prefix in ("en0", "eth0", "wlan0", "en", "eth", "wl"):
        for n in names:
            if n.startswith(prefix):
                return n
    non_lo = [n for n in names if not n.startswith("lo")]
    return non_lo[0] if non_lo else (names[0] if names else "lo")


def live_frames(iface: str | None = None, promisc: bool = True, stop_after: float | None = None,
                poll: float = 0.25) -> Iterator[Frame | None]:
    """Yield frames as they arrive; yield ``None`` on idle ticks so a UI can redraw."""
    iface = iface or default_interface()
    if sys.platform.startswith("linux"):
        yield from _linux(iface, promisc, stop_after, poll)
    elif sys.platform == "darwin" or "bsd" in sys.platform:
        yield from _bpf(iface, promisc, stop_after, poll)
    else:
        raise CaptureError(f"live capture is not supported on {sys.platform}; capture with Wireshark/tcpdump "
                           "and open the file with `pktanalyzer read`")


def _permission_hint() -> str:
    return "raw sockets need root: run with sudo (or give python CAP_NET_RAW on Linux)"


def _linux(iface: str, promisc: bool, stop_after: float | None, poll: float) -> Iterator[Frame | None]:
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    except PermissionError:
        raise CaptureError(_permission_hint()) from None
    try:
        s.bind((iface, 0))
    except OSError as e:
        s.close()
        raise CaptureError(f"cannot bind to interface {iface!r}: {e} (available: {', '.join(list_interfaces())})") from None
    if promisc:
        try:
            idx = socket.if_nametoindex(iface)
            mreq = struct.pack("iHH8s", idx, PACKET_MR_PROMISC, 0, b"")
            s.setsockopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP, mreq)
        except OSError:
            pass  # promiscuous mode is a nice-to-have
    s.settimeout(poll)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
    deadline = time.time() + stop_after if stop_after else None
    loopback = iface.startswith("lo")
    try:
        while deadline is None or time.time() < deadline:
            try:
                data, addr = s.recvfrom(65535)
            except socket.timeout:
                yield None
                continue
            if loopback and addr[2] == PACKET_OUTGOING:
                continue  # on lo every packet is seen leaving and arriving; keep one copy
            yield Frame(time.time(), data, LINKTYPE_ETHERNET, len(data))
    finally:
        s.close()


# BSD/macOS BPF ioctls (from <net/bpf.h>)
BIOCSETIF = 0x8020426C
BIOCIMMEDIATE = 0x80044270
BIOCGBLEN = 0x40044266
BIOCSBLEN = 0xC0044266
BIOCPROMISC = 0x20004269
BIOCGDLT = 0x4004426A
BIOCSRTIMEOUT = 0x8010426D


def _bpf(iface: str, promisc: bool, stop_after: float | None, poll: float) -> Iterator[Frame | None]:
    fd = None
    last_err = None
    for i in range(256):
        try:
            fd = os.open(f"/dev/bpf{i}", os.O_RDONLY)
            break
        except PermissionError:
            raise CaptureError(_permission_hint()) from None
        except OSError as e:  # busy or missing; try the next device
            last_err = e
            continue
    if fd is None:
        raise CaptureError(f"no free /dev/bpf device ({last_err})")
    try:
        fcntl.ioctl(fd, BIOCSBLEN, struct.pack("I", 1 << 20))
        fcntl.ioctl(fd, BIOCSETIF, struct.pack("16s16x", iface.encode()))
        fcntl.ioctl(fd, BIOCIMMEDIATE, struct.pack("I", 1))
        fcntl.ioctl(fd, BIOCSRTIMEOUT, struct.pack("qi4x", 0, int(poll * 1e6)))
        if promisc:
            try:
                fcntl.ioctl(fd, BIOCPROMISC)
            except OSError:
                pass
        blen = struct.unpack("I", fcntl.ioctl(fd, BIOCGBLEN, b"\0" * 4))[0]
        dlt = struct.unpack("I", fcntl.ioctl(fd, BIOCGDLT, b"\0" * 4))[0]
    except OSError as e:
        os.close(fd)
        raise CaptureError(f"cannot attach BPF to {iface!r}: {e}") from None
    linktype = LINKTYPE_ETHERNET if dlt == 1 else LINKTYPE_NULL if dlt == 0 else dlt
    deadline = time.time() + stop_after if stop_after else None
    try:
        while deadline is None or time.time() < deadline:
            buf = os.read(fd, blen)
            if not buf:
                yield None
                continue
            off = 0
            # Each record: struct bpf_hdr { timeval32 ts; u32 caplen; u32 datalen; u16 hdrlen; } + data,
            # padded to a 4-byte boundary (BPF_WORDALIGN)
            while off + 18 <= len(buf):
                sec, usec, caplen, datalen, hdrlen = struct.unpack_from("IIIIH", buf, off)
                data = buf[off + hdrlen:off + hdrlen + caplen]
                yield Frame(sec + usec / 1e6, bytes(data), linktype, datalen)
                off += (hdrlen + caplen + 3) & ~3
    finally:
        os.close(fd)
