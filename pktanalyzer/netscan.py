"""Active network diagnostics: look up an address, find the devices on your own
network, scan a host's open ports, list nearby Wi-Fi and run a plain-English
security check.

Unlike the rest of pktanalyzer, which only reads capture files, everything here
reaches out onto the network. It is all read-only — it looks, it never attacks,
cracks or changes anything — but you should still use it only on networks you
own or are explicitly authorised to test.

The functions that touch the network are thin wrappers; the parsing and
classification they rely on is pure, so it can be tested without a network.
"""
from __future__ import annotations

import concurrent.futures
import ipaddress
import os
import platform
import re
import select
import shutil
import socket
import struct
import subprocess
import sys
import time
from dataclasses import dataclass, field

from .flows import APP_BY_PORT

# A friendly name for a port, extending the analyzer's own table with a few more
# that matter for a security check.
PORT_NAMES = {**APP_BY_PORT, 111: "RPC", 135: "MS-RPC", 139: "NetBIOS", 515: "LPD", 548: "AFP",
              631: "IPP", 1900: "SSDP", 2049: "NFS", 2323: "Telnet-alt", 5000: "UPnP/Flask",
              5060: "SIP", 5555: "ADB", 7547: "TR-069", 8008: "HTTP-alt", 8888: "HTTP-alt",
              9100: "JetDirect", 32400: "Plex", 49152: "UPnP"}

# Ports that commonly scan as open; a sensible default for a quick look.
COMMON_PORTS = (21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 515, 548, 554, 587, 631,
                993, 995, 1433, 1883, 2049, 2323, 3306, 3389, 5000, 5060, 5432, 5555, 5900, 5901,
                6379, 7547, 8000, 8008, 8080, 8443, 8888, 9100, 9200, 27017, 32400, 49152)

# Open ports worth flagging in the security check: port -> (severity, plain-English note).
RISKY_PORTS = {
    23: ("high", "Telnet is open — logins and passwords cross the network in the clear. Disable it; use SSH."),
    2323: ("high", "A Telnet-style service is open — likely unencrypted logins. Turn it off."),
    21: ("medium", "FTP is open — often sends passwords and files unencrypted. Prefer SFTP/HTTPS."),
    3389: ("high", "Remote Desktop (RDP) is reachable — a common target. Restrict it to a VPN if you need it."),
    5900: ("high", "Screen sharing (VNC) is reachable — make sure it needs a strong password, or close it."),
    5901: ("high", "Screen sharing (VNC) is reachable — make sure it needs a strong password, or close it."),
    445: ("medium", "Windows file sharing (SMB) is exposed — keep it off the open internet and patched."),
    139: ("medium", "Legacy NetBIOS file sharing is exposed — usually safe to disable."),
    135: ("medium", "Windows RPC is exposed — should not be reachable from outside your network."),
    5555: ("high", "Android debug bridge (ADB) is open — anyone nearby could control the device. Turn off USB/Wi-Fi debugging."),
    7547: ("medium", "The TR-069 remote-management port is open — a known router weak spot. Check your router's firmware."),
    1433: ("high", "A Microsoft SQL Server is reachable — databases should never be open to the network."),
    3306: ("high", "A MySQL database is reachable — databases should never be open to the network."),
    5432: ("high", "A PostgreSQL database is reachable — databases should never be open to the network."),
    6379: ("high", "A Redis server is reachable — Redis has no password by default; lock it down now."),
    9200: ("high", "An Elasticsearch server is reachable — these leak data when left open. Restrict it."),
    27017: ("high", "A MongoDB database is reachable — databases should never be open to the network."),
    161: ("medium", "SNMP is open — default community strings expose device details. Change or disable them."),
    9100: ("low", "A printer's raw-print port is open — fine on a home network, worth closing elsewhere."),
}

# How many addresses we are willing to sweep or scan, and how many at once.
MAX_SWEEP_HOSTS = 1024
MAX_SCAN_PORTS = 4096
DEFAULT_WORKERS = 128


# ---------------------------------------------------------------------------
# small pure helpers (no network) -- these carry the logic the I/O relies on
# ---------------------------------------------------------------------------
def port_service(port: int, banner: str = "") -> str:
    """A short service name for a port, refined by its banner when we have one."""
    name = PORT_NAMES.get(port, "")
    b = banner.lower()
    if b.startswith("ssh-"):
        return "SSH"
    if b.startswith("http/") or "<html" in b or "server:" in b:
        return name or "HTTP"
    if "220" in b[:4] and ("ftp" in b or "smtp" in b):
        return "FTP" if "ftp" in b else "SMTP"
    return name or f"port {port}"


def port_risk(port: int, banner: str = "") -> tuple[str, str]:
    """(severity, note) for an open port; ('', '') if it is not noteworthy."""
    sev, note = RISKY_PORTS.get(port, ("", ""))
    if not note:
        return "", ""
    return sev, note


def classify_wifi_security(flags: str) -> str:
    """Turn a driver's capability flags into a one-word security level."""
    f = flags.upper()
    if "WPA3" in f or "SAE" in f:
        return "WPA3"
    if "WPA2" in f or "RSN" in f:
        return "WPA2"
    if "WPA" in f:
        return "WPA"
    if "WEP" in f:
        return "WEP (weak)"
    if not f or "OPEN" in f or "ESS" in f and "PRIVACY" not in f:
        return "Open (no password)"
    return "Open (no password)"


def channel_from_freq(mhz: int) -> int:
    """Wi-Fi channel number from a frequency in MHz (2.4 and 5 GHz bands)."""
    if 2412 <= mhz <= 2472:
        return (mhz - 2407) // 5
    if mhz == 2484:
        return 14
    if 5000 <= mhz <= 5900:
        return (mhz - 5000) // 5
    if 5955 <= mhz <= 7115:  # 6 GHz
        return (mhz - 5950) // 5
    return 0


def signal_bars(dbm: int) -> str:
    """A 0-4 bar strength indicator from an RSSI in dBm."""
    if dbm >= -55:
        n = 4
    elif dbm >= -67:
        n = 3
    elif dbm >= -75:
        n = 2
    elif dbm >= -85:
        n = 1
    else:
        n = 0
    return "▰" * n + "▱" * (4 - n)


def guess_prefixlen(ip: str) -> int:
    """The network size to assume when we can't read the real netmask. A /24
    (254 hosts) matches almost every home and small-office network and keeps the
    sweep quick; pass an explicit range to `discover` for anything larger."""
    return 24


# ---------------------------------------------------------------------------
# address lookup and ownership (whois)
# ---------------------------------------------------------------------------
@dataclass
class Lookup:
    query: str
    ip: str = ""
    names: list[str] = field(default_factory=list)     # reverse-DNS names
    addresses: list[str] = field(default_factory=list)  # forward-resolved addresses
    owner: str = ""
    netname: str = ""
    country: str = ""
    is_private: bool = False
    error: str = ""


def resolve(query: str) -> Lookup:
    """Resolve a hostname or IP both ways: name<->address and reverse DNS."""
    lk = Lookup(query=query.strip())
    q = lk.query
    try:
        ipaddress.ip_address(q)
        lk.ip = q
    except ValueError:
        try:
            infos = socket.getaddrinfo(q, None)
            lk.addresses = sorted({i[4][0] for i in infos})
            lk.ip = lk.addresses[0] if lk.addresses else ""
        except (socket.gaierror, OSError) as e:
            lk.error = f"could not resolve {q!r}: {e}"
            return lk
    if lk.ip:
        try:
            addr = ipaddress.ip_address(lk.ip)
            lk.is_private = addr.is_private or addr.is_link_local or addr.is_loopback
        except ValueError:
            pass
        try:
            host, aliases, _ = socket.gethostbyaddr(lk.ip)
            lk.names = [host] + [a for a in aliases if a != host]
        except (socket.herror, socket.gaierror, OSError):
            pass
    return lk


def _whois_query(server: str, query: str, timeout: float) -> str:
    with socket.create_connection((server, 43), timeout=timeout) as s:
        s.sendall((query + "\r\n").encode())
        chunks = []
        while True:
            try:
                data = s.recv(4096)
            except socket.timeout:
                break
            if not data:
                break
            chunks.append(data)
            if sum(len(c) for c in chunks) > 256 * 1024:
                break
    return b"".join(chunks).decode("utf-8", "replace")


def parse_whois(text: str) -> dict:
    """Pull the owner, network name and country out of a whois reply."""
    out = {"owner": "", "netname": "", "country": "", "refer": ""}
    fields = {
        "owner": ("org-name", "orgname", "organisation", "organization", "owner", "descr"),
        "netname": ("netname",),
        "country": ("country",),
        "refer": ("refer", "whois"),
    }
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("%", "#")) or ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower()
        value = value.strip()
        for name, keys in fields.items():
            if key in keys and value and not out[name]:
                out[name] = value
    return out


def whois(ip: str, timeout: float = 5.0) -> dict:
    """Look up who owns an IP, following IANA's referral to the right registry."""
    try:
        first = _whois_query("whois.iana.org", ip, timeout)
    except OSError as e:
        return {"owner": "", "netname": "", "country": "", "error": str(e)}
    info = parse_whois(first)
    refer = info.get("refer", "")
    if refer:
        try:
            second = _whois_query(refer, ip, timeout)
            deeper = parse_whois(second)
            for k in ("owner", "netname", "country"):
                if deeper.get(k):
                    info[k] = deeper[k]
        except OSError:
            pass
    info.pop("refer", None)
    return info


def lookup(query: str, do_whois: bool = True, timeout: float = 5.0) -> Lookup:
    """Full address lookup: resolve, then (for public IPs) find the owner."""
    lk = resolve(query)
    if lk.ip and do_whois and not lk.is_private:
        info = whois(lk.ip, timeout)
        lk.owner, lk.netname, lk.country = info.get("owner", ""), info.get("netname", ""), info.get("country", "")
    return lk


# ---------------------------------------------------------------------------
# traceroute (needs root for the raw socket; degrades to a clear message)
# ---------------------------------------------------------------------------
@dataclass
class Hop:
    ttl: int
    ip: str = ""
    name: str = ""
    rtt_ms: float | None = None


def traceroute(host: str, max_hops: int = 30, timeout: float = 2.0,
               resolve_names: bool = True) -> list[Hop]:
    """Trace the path to a host with ICMP echo and increasing TTL.

    Raises PermissionError if raw sockets are not available (run with sudo).
    """
    dest = socket.gethostbyname(host)
    hops: list[Hop] = []
    ident = os.getpid() & 0xFFFF
    recv = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    send = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    recv.settimeout(timeout)
    try:
        for ttl in range(1, max_hops + 1):
            send.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
            pkt = _icmp_echo(ident, ttl)
            start = time.time()
            send.sendto(pkt, (dest, 0))
            hop = Hop(ttl=ttl)
            deadline = start + timeout
            while time.time() < deadline:
                ready, _, _ = select.select([recv], [], [], max(0, deadline - time.time()))
                if not ready:
                    break
                try:
                    data, addr = recv.recvfrom(1024)
                except socket.timeout:
                    break
                src = addr[0]
                kind = data[20] if len(data) > 20 else None
                if kind in (0, 11):  # echo reply, or time exceeded from a router
                    hop.ip = src
                    hop.rtt_ms = (time.time() - start) * 1000
                    break
            hops.append(hop)
            if hop.ip == dest:
                break
    finally:
        recv.close()
        send.close()
    if resolve_names:
        for hop in hops:
            if hop.ip:
                try:
                    hop.name = socket.gethostbyaddr(hop.ip)[0]
                except (socket.herror, OSError):
                    pass
    return hops


def _icmp_echo(ident: int, seq: int) -> bytes:
    head = struct.pack("!BBHHH", 8, 0, 0, ident, seq)
    payload = b"pktanalyzer"
    chk = _checksum(head + payload)
    return struct.pack("!BBHHH", 8, 0, chk, ident, seq) + payload


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return (~total) & 0xFFFF


# ---------------------------------------------------------------------------
# the local network: our own address, and the ARP cache the OS already has
# ---------------------------------------------------------------------------
def local_ipv4() -> str:
    """Our own LAN address, found by asking the OS which source it would use."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))  # no packet is sent for a UDP connect
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def local_network(ip: str | None = None) -> ipaddress.IPv4Network:
    ip = ip or local_ipv4()
    return ipaddress.ip_network(f"{ip}/{guess_prefixlen(ip)}", strict=False)


def parse_arp_table(text: str) -> dict[str, str]:
    """IP -> MAC from the output of ``arp -an`` or the contents of /proc/net/arp."""
    table: dict[str, str] = {}
    mac_re = re.compile(r"(?:[0-9a-fA-F]{1,2}[:-]){5}[0-9a-fA-F]{1,2}")
    ip_re = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")
    for line in text.splitlines():
        ip_m = ip_re.search(line)
        mac_m = mac_re.search(line)
        if not ip_m or not mac_m:
            continue
        mac = mac_m.group(0).lower().replace("-", ":")
        parts = [p.zfill(2) for p in mac.split(":")]
        if mac == "00:00:00:00:00:00" or len(parts) != 6:
            continue
        table[ip_m.group(0)] = ":".join(parts)
    return table


def arp_table() -> dict[str, str]:
    """Read the MAC addresses the OS has already learned, without sending anything."""
    if sys.platform.startswith("linux") and os.path.exists("/proc/net/arp"):
        try:
            with open("/proc/net/arp") as f:
                return parse_arp_table(f.read())
        except OSError:
            return {}
    arp = shutil.which("arp")
    if arp:
        try:
            out = subprocess.run([arp, "-an"], capture_output=True, text=True, timeout=5)
            return parse_arp_table(out.stdout)
        except (OSError, subprocess.SubprocessError):
            return {}
    return {}


# ---------------------------------------------------------------------------
# finding live devices and scanning ports -- plain TCP connect, no root needed
# ---------------------------------------------------------------------------
@dataclass
class Host:
    ip: str
    mac: str = ""
    name: str = ""
    responded_on: int = 0        # the port whose answer proved it is up
    open_ports: list[int] = field(default_factory=list)


def _tcp_open(ip: str, port: int, timeout: float) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((ip, port)) == 0
    except OSError:
        return False


def discover(network: ipaddress.IPv4Network | None = None, timeout: float = 0.4,
             workers: int = DEFAULT_WORKERS, probe_ports: tuple[int, ...] = (80, 443, 22, 445, 53, 139, 5000),
             progress=None) -> list[Host]:
    """Find live hosts on a network by a quick TCP touch on a few common ports,
    then label each with its reverse-DNS name and the MAC the OS already knows."""
    network = network or local_network()
    addrs = [str(h) for h in network.hosts()]
    if len(addrs) > MAX_SWEEP_HOSTS:
        raise ValueError(f"{network} has {len(addrs)} addresses; that is more than {MAX_SWEEP_HOSTS}. "
                         "Give a smaller range, e.g. a /24.")
    arp = arp_table()
    live: dict[str, Host] = {}

    def probe(ip: str) -> None:
        for port in probe_ports:
            if _tcp_open(ip, port, timeout):
                live[ip] = Host(ip=ip, responded_on=port)
                return
        if ip in arp:  # answered an ARP earlier even if no port is open
            live[ip] = Host(ip=ip)

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futs = [pool.submit(probe, ip) for ip in addrs]
        done = 0
        for _ in concurrent.futures.as_completed(futs):
            done += 1
            if progress:
                progress(done, len(addrs))
    for ip, host in live.items():
        host.mac = arp.get(ip, "")
        try:
            host.name = socket.gethostbyaddr(ip)[0]
        except (socket.herror, OSError):
            host.name = ""
    return [live[ip] for ip in sorted(live, key=lambda a: ipaddress.ip_address(a))]


@dataclass
class ScanResult:
    host: str
    ip: str
    open_ports: list[tuple[int, str, str]] = field(default_factory=list)  # (port, service, banner)
    error: str = ""


def _grab_banner(ip: str, port: int, timeout: float) -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) != 0:
                return ""
            if port in (80, 8080, 8000, 8008, 8888):
                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            try:
                data = s.recv(256)
            except socket.timeout:
                return ""
            return data.decode("latin-1", "replace").strip()
    except OSError:
        return ""


def scan_ports(host: str, ports: tuple[int, ...] = COMMON_PORTS, timeout: float = 0.6,
               workers: int = DEFAULT_WORKERS, banners: bool = True, progress=None) -> ScanResult:
    """TCP connect scan of a host: which ports accept a connection, and the
    service each one looks like. It connects and disconnects, nothing more."""
    if len(ports) > MAX_SCAN_PORTS:
        raise ValueError(f"{len(ports)} ports is more than {MAX_SCAN_PORTS}.")
    try:
        ip = socket.gethostbyname(host)
    except OSError as e:
        return ScanResult(host=host, ip="", error=f"could not resolve {host!r}: {e}")
    found: list[tuple[int, str, str]] = []

    def check(port: int):
        if _tcp_open(ip, port, timeout):
            banner = _grab_banner(ip, port, timeout) if banners else ""
            return (port, port_service(port, banner), banner)
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futs = [pool.submit(check, p) for p in ports]
        done = 0
        for fut in concurrent.futures.as_completed(futs):
            done += 1
            if progress:
                progress(done, len(ports))
            r = fut.result()
            if r:
                found.append(r)
    found.sort()
    return ScanResult(host=host, ip=ip, open_ports=found)


# ---------------------------------------------------------------------------
# nearby Wi-Fi networks (read-only; parsing is pure, the command run is thin)
# ---------------------------------------------------------------------------
@dataclass
class WifiNetwork:
    ssid: str
    bssid: str = ""
    signal_dbm: int | None = None
    channel: int = 0
    security: str = ""


def parse_nmcli_wifi(text: str) -> list[WifiNetwork]:
    """Parse ``nmcli -t -f SSID,BSSID,SIGNAL,CHAN,SECURITY device wifi list``."""
    nets = []
    for line in text.splitlines():
        if not line.strip():
            continue
        # nmcli escapes ':' in the BSSID as '\:', so split on unescaped colons
        fields = re.split(r"(?<!\\):", line)
        fields = [f.replace("\\:", ":") for f in fields]
        if len(fields) < 5:
            continue
        ssid, bssid, signal, chan, security = fields[0], fields[1], fields[2], fields[3], ":".join(fields[4:])
        pct = int(signal) if signal.isdigit() else None
        dbm = (pct // 2) - 100 if pct is not None else None  # nmcli reports 0-100%; map back to dBm
        nets.append(WifiNetwork(ssid=ssid or "(hidden)", bssid=bssid,
                                signal_dbm=dbm, channel=int(chan) if chan.isdigit() else 0,
                                security=classify_wifi_security(security) if security.strip() else "Open (no password)"))
    return nets


def parse_iw_scan(text: str) -> list[WifiNetwork]:
    """Parse the output of ``iw dev <iface> scan`` (Linux, needs root)."""
    nets: list[WifiNetwork] = []
    cur: WifiNetwork | None = None
    flags = ""
    for raw in text.splitlines():
        line = raw.strip()
        m = re.match(r"BSS ([0-9a-fA-F:]{17})", line)
        if m:
            if cur:
                cur.security = classify_wifi_security(flags)
                nets.append(cur)
            cur = WifiNetwork(ssid="(hidden)", bssid=m.group(1).lower())
            flags = ""
            continue
        if cur is None:
            continue
        if line.startswith("SSID:"):
            cur.ssid = line[5:].strip() or "(hidden)"
        elif line.startswith("signal:"):
            m = re.search(r"(-?\d+(?:\.\d+)?)\s*dBm", line)
            if m:
                cur.signal_dbm = int(float(m.group(1)))
        elif line.startswith("freq:"):
            m = re.search(r"(\d+)", line)
            if m:
                cur.channel = channel_from_freq(int(m.group(1)))
        elif "WPA" in line or "RSN" in line or "WEP" in line or "Privacy" in line:
            flags += " " + line
    if cur:
        cur.security = classify_wifi_security(flags)
        nets.append(cur)
    return nets


def parse_airport_scan(text: str) -> list[WifiNetwork]:
    """Parse macOS ``airport -s`` columns: SSID BSSID RSSI CHANNEL HT CC SECURITY."""
    nets = []
    lines = [l for l in text.splitlines() if l.strip()]
    for line in lines[1:]:  # skip the header row
        m = re.search(r"([0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5})\s+(-?\d+)\s+(\d+)", line)
        if not m:
            continue
        bssid, rssi, chan = m.group(1), int(m.group(2)), int(m.group(3))
        ssid = line[:m.start()].strip()
        security = line[m.end():].strip()
        nets.append(WifiNetwork(ssid=ssid or "(hidden)", bssid=bssid.lower(), signal_dbm=rssi,
                                channel=chan, security=classify_wifi_security(security)))
    return nets


# macOS 14+ dropped `airport`; this is the old path, still present on many machines.
_AIRPORT = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"


def wifi_scan(timeout: float = 20.0) -> tuple[list[WifiNetwork], str]:
    """List nearby Wi-Fi networks. Returns (networks, note); note explains any
    reason the list is empty (tool missing, needs root, etc.)."""
    system = platform.system()
    if system == "Linux":
        nmcli = shutil.which("nmcli")
        if nmcli:
            try:
                out = subprocess.run([nmcli, "-t", "-f", "SSID,BSSID,SIGNAL,CHAN,SECURITY", "device", "wifi", "list"],
                                     capture_output=True, text=True, timeout=timeout)
                nets = parse_nmcli_wifi(out.stdout)
                if nets:
                    return nets, ""
            except (OSError, subprocess.SubprocessError):
                pass
        iw = shutil.which("iw")
        if iw:
            iface = _wifi_iface_linux(iw)
            if iface:
                try:
                    out = subprocess.run([iw, "dev", iface, "scan"], capture_output=True, text=True, timeout=timeout)
                    if out.returncode != 0 and "Operation not permitted" in out.stderr:
                        return [], "Wi-Fi scanning with iw needs root — try: sudo pktanalyzer wifi"
                    return parse_iw_scan(out.stdout), ""
                except (OSError, subprocess.SubprocessError):
                    pass
        return [], "No Wi-Fi scanner found (install NetworkManager's nmcli, or iw)."
    if system == "Darwin":
        if os.path.exists(_AIRPORT):
            try:
                out = subprocess.run([_AIRPORT, "-s"], capture_output=True, text=True, timeout=timeout)
                nets = parse_airport_scan(out.stdout)
                if nets:
                    return nets, ""
            except (OSError, subprocess.SubprocessError):
                pass
        return [], ("This macOS version no longer lets command-line tools list every nearby network. "
                    "Hold Option and click the Wi-Fi menu to see them, or run: wdutil info")
    return [], f"Wi-Fi scanning is not supported on {system}."


def _wifi_iface_linux(iw: str) -> str:
    try:
        out = subprocess.run([iw, "dev"], capture_output=True, text=True, timeout=5)
        m = re.search(r"Interface (\S+)", out.stdout)
        return m.group(1) if m else ""
    except (OSError, subprocess.SubprocessError):
        return ""


# ---------------------------------------------------------------------------
# the security check: tie the scans together into plain-English findings
# ---------------------------------------------------------------------------
@dataclass
class AuditFinding:
    severity: str          # high / medium / low / info
    host: str
    message: str


SEV_RANK = {"high": 0, "medium": 1, "low": 2, "info": 3}


def audit_hosts(scans: list[ScanResult]) -> list[AuditFinding]:
    """Turn a set of port scans into a ranked list of plain-English findings."""
    findings: list[AuditFinding] = []
    for sc in scans:
        where = sc.host if sc.host == sc.ip or not sc.ip else f"{sc.host} ({sc.ip})"
        if sc.error:
            findings.append(AuditFinding("info", where, sc.error))
            continue
        if not sc.open_ports:
            findings.append(AuditFinding("info", where, "No open ports found — nothing exposed."))
            continue
        for port, service, _banner in sc.open_ports:
            sev, note = port_risk(port)
            if note:
                findings.append(AuditFinding(sev, where, f"{service} (port {port}): {note}"))
        risky = sum(1 for p, _, _ in sc.open_ports if RISKY_PORTS.get(p, ("", ""))[1])
        if not risky:
            ports = ", ".join(f"{p} {s}" for p, s, _ in sc.open_ports[:8])
            findings.append(AuditFinding("info", where, f"Open ports look ordinary: {ports}."))
    findings.sort(key=lambda f: SEV_RANK.get(f.severity, 9))
    return findings
