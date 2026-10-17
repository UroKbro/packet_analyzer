"""Local-network discovery chatter, translated into plain English.

Phones, TVs, speakers and printers constantly tell each other what they are
over mDNS/Bonjour (UDP 5353) and SSDP/UPnP (UDP 1900). The raw records are
dense ("model=AppleTV14,1" "features=0x4A7FDFD5,..."), so this module turns
them into devices with a readable name, model and list of services.
"""
from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field

# service type -> (short label, what offering it means, what searching for it means)
SERVICES = {
    "_airplay": ("AirPlay", "can receive AirPlay video and screen mirroring", "AirPlay screens (Apple TVs, smart TVs)"),
    "_raop": ("AirPlay audio", "can play AirPlay audio", "AirPlay speakers"),
    "_companion-link": ("Apple device link", "lets nearby iPhones and Macs control it and hand off to it",
                        "Apple devices to pair with (remote control, Handoff)"),
    "_mediaremotetv": ("Apple TV remote", "can be controlled by the Remote app", "Apple TVs to control"),
    "_touch-able": ("iTunes Remote", "can be controlled by the Remote app", "media players to control"),
    "_rdlink": ("Apple Continuity", "shares Continuity features with the owner's other Apple devices",
                "the owner's other Apple devices"),
    "_apple-mobdev2": ("Wi-Fi sync", "can sync with a Mac over Wi-Fi", "iPhones and iPads to sync"),
    "_remotepairing": ("device pairing", "is open to pairing with the owner's Mac", "devices to pair with"),
    "_sleep-proxy": ("sleep proxy", "answers for sleeping devices so they can be woken on demand", "a sleep proxy"),
    "_device-info": ("device info", "publishes its hardware model", "device models"),
    "_homekit": ("HomeKit", "is part of a HomeKit home", "HomeKit homes"),
    "_hap": ("HomeKit accessory", "is a HomeKit smart-home accessory", "HomeKit accessories"),
    "_matter": ("Matter", "is a Matter smart-home device", "Matter smart-home devices"),
    "_matterc": ("Matter setup", "is a Matter device waiting to be set up", "Matter devices to set up"),
    "_meshcop": ("Thread border router", "runs a Thread smart-home network", "Thread networks"),
    "_trel": ("Thread link", "relays Thread smart-home traffic over Wi-Fi", "Thread routers"),
    "_srpl-tls": ("Thread registry", "keeps the Thread service list in sync", "Thread service registries"),
    "_googlecast": ("Google Cast", "can be cast to (Chromecast, Google/Nest speaker, Android TV)",
                    "Chromecasts and Google Cast speakers"),
    "_googlezone": ("Google speaker group", "is in a Google speaker group", "Google speaker groups"),
    "_androidtvremote2": ("Android TV remote", "can be controlled from a phone", "Android TVs to control"),
    "_amzn-wplay": ("Fire TV", "is an Amazon Fire TV device", "Fire TV devices"),
    "_spotify-connect": ("Spotify Connect", "can play Spotify", "Spotify speakers"),
    "_sonos": ("Sonos", "is a Sonos speaker", "Sonos speakers"),
    "_nvstream": ("game streaming", "can stream PC games", "game-streaming PCs"),
    "_ipp": ("printing", "is a printer", "printers"),
    "_ipps": ("printing", "is a printer", "printers"),
    "_printer": ("printing", "is a printer", "printers"),
    "_pdl-datastream": ("printing", "is a printer", "printers"),
    "_uscan": ("scanning", "is a scanner", "scanners"),
    "_scanner": ("scanning", "is a scanner", "scanners"),
    "_smb": ("file sharing", "shares files (SMB)", "shared folders"),
    "_afpovertcp": ("file sharing", "shares files (AFP)", "shared folders"),
    "_adisk": ("Time Machine", "is a Time Machine backup disk", "Time Machine backup disks"),
    "_ssh": ("SSH", "accepts SSH remote logins", "computers that accept SSH"),
    "_sftp-ssh": ("SFTP", "accepts SFTP file transfers", "SFTP servers"),
    "_rfb": ("screen sharing", "allows screen sharing (VNC)", "screens to share"),
    "_http": ("web page", "has a built-in web page", "devices with a web page"),
    "_workstation": ("computer", "is a computer", "computers"),
    "_airport": ("AirPort", "is an AirPort Wi-Fi base station", "AirPort base stations"),
    "_hue": ("Philips Hue", "is a Philips Hue bridge", "Hue bridges"),
    "_services": ("service list", "lists its services", "every kind of service on the network"),
}

APPLE_MODELS = {
    "AppleTV14,1": "Apple TV 4K 3rd gen", "J255AP": "Apple TV 4K 3rd gen",
    "AppleTV11,1": "Apple TV 4K 2nd gen", "J305AP": "Apple TV 4K 2nd gen",
    "AppleTV6,2": "Apple TV 4K", "J105aAP": "Apple TV 4K", "AppleTV5,3": "Apple TV HD", "J42dAP": "Apple TV HD",
    "AudioAccessory1,1": "HomePod", "AudioAccessory1,2": "HomePod", "AudioAccessory5,1": "HomePod mini",
    "B520AP": "HomePod mini", "AudioAccessory6,1": "HomePod 2nd gen",
}
MODEL_PREFIXES = (("AppleTV", "Apple TV"), ("AudioAccessory", "HomePod"), ("iPhone", "iPhone"), ("iPad", "iPad"),
                  ("iPod", "iPod touch"), ("MacBookAir", "MacBook Air"), ("MacBookPro", "MacBook Pro"),
                  ("MacBook", "MacBook"), ("Macmini", "Mac mini"), ("MacPro", "Mac Pro"), ("iMac", "iMac"),
                  ("Mac", "Mac"), ("Watch", "Apple Watch"), ("RealityDevice", "Apple Vision Pro"))
OS_FOR = {"Apple TV": "tvOS", "HomePod": "HomePod software", "iPhone": "iOS", "iPad": "iPadOS", "Mac": "macOS",
          "MacBook": "macOS", "iMac": "macOS", "Apple Watch": "watchOS"}

# what the TXT keys Apple, Google and printers publish actually mean
TXT_KEYS = {
    "model": "hardware model", "md": "model", "am": "model", "rpMd": "model", "ty": "printer model",
    "deviceid": "device ID (its network MAC address)", "id": "device ID", "btaddr": "Bluetooth address",
    "features": "bitmask of the AirPlay features it supports", "fex": "more AirPlay feature bits (encoded)",
    "flags": "status bits (busy, needs a PIN, ...)", "pk": "public key used to pair securely",
    "pi": "pairing identity (a random ID)", "psi": "pairing service ID", "gid": "home/group ID shared with its group",
    "igl": "1 = it leads its speaker/TV group", "gcgl": "1 = its group contains the group leader",
    "acl": "access control (0 = anyone on the network may use it)", "srcvers": "AirPlay software version",
    "osvers": "operating system version", "protovers": "AirPlay protocol version", "vv": "internal version",
    "rpVr": "remote protocol version", "rpBA": "Bluetooth address (rotates for privacy)", "rpFl": "status bits",
    "rpHN": "hashed device name (for privacy)", "rpHI": "hashed device ID", "rpAD": "authentication tag",
    "rpHA": "hashed account ID", "rpMac": "1 = it is a Mac", "fn": "friendly name", "ve": "version",
    "rs": "what it is playing", "st": "status", "ca": "capabilities", "note": "location note",
    "adminurl": "settings web page", "rp": "print queue", "pdl": "file formats it prints", "UUID": "unique ID",
    "sf": "status flags", "ff": "feature flags", "ci": "accessory category", "c#": "configuration number",
    "s#": "state number", "sh": "setup hash",
}
HAP_CATEGORIES = {1: "accessory", 2: "bridge", 3: "fan", 5: "light", 6: "lock", 7: "outlet", 8: "switch",
                  9: "thermostat", 10: "sensor", 11: "security system", 17: "camera", 18: "doorbell",
                  26: "speaker", 31: "TV", 32: "router"}

SSDP_TARGETS = {
    "ssdp:all": "every UPnP device", "upnp:rootdevice": "any UPnP device",
    "urn:dial-multiscreen-org:service:dial:1": "smart TVs and cast devices (DIAL)",
    "roku:ecp": "Roku players",
    "urn:schemas-upnp-org:device:mediarenderer:1": "media players and speakers",
    "urn:schemas-upnp-org:device:mediaserver:1": "media servers",
    "urn:schemas-upnp-org:device:internetgatewaydevice:1": "the router (to open ports with UPnP)",
    "urn:schemas-upnp-org:service:wanipconnection:1": "the router (to open ports with UPnP)",
    "urn:schemas-upnp-org:device:basic:1": "UPnP devices", "urn:schemas-sonos-com:service:queue:1": "Sonos speakers",
}

# what announcing an SSDP target says about the device
SSDP_OFFERS = {
    "urn:dial-multiscreen-org:service:dial:1": "can be cast to (DIAL: smart TVs, streaming sticks)",
    "urn:schemas-upnp-org:device:mediarenderer:1": "can play media sent to it",
    "urn:schemas-upnp-org:device:mediaserver:1": "shares media files",
    "urn:schemas-upnp-org:device:internetgatewaydevice:1": "is the router and lets apps open ports (UPnP)",
    "urn:schemas-upnp-org:service:wanipconnection:1": "is the router and lets apps open ports (UPnP)",
    "roku:ecp": "is a Roku player",
}
VENDORS = ("Samsung", "LG", "Sony", "Roku", "Sonos", "Philips", "Panasonic", "Vizio", "TCL", "Hisense", "Xbox",
           "Microsoft-Windows", "Synology", "QNAP", "Plex", "Kodi", "Amazon", "Google", "Chromecast", "Denon",
           "Yamaha", "Bose", "HP", "Canon", "Epson", "Brother", "Netgear", "TP-Link", "ASUS", "Linksys", "ubiquiti",
           "MiniUPnP", "Ring", "Nanoleaf", "Wemo")


def ssdp_vendor(server: str) -> str:
    low = server.lower()
    for v in VENDORS:
        if v.lower() in low:
            return {"Microsoft-Windows": "Windows", "MiniUPnP": "router"}.get(v, v)
    return ""


def ssdp_offer(target: str) -> str:
    return SSDP_OFFERS.get(target.lower(), "")


TXT_PART = re.compile(r'"((?:[^"\\]|\\.)*)"')


def parse_txt(data: str) -> dict:
    """``"a=1" "b=2"`` (as the DNS dissector prints TXT data) -> {"a": "1", "b": "2"}."""
    out = {}
    for part in TXT_PART.findall(data or ""):
        k, _, v = part.partition("=")
        if k and k not in out:
            out[k] = v
    return out


def split_service(name: str) -> tuple[str, str] | None:
    """``Living Room._airplay._tcp.local`` -> ("Living Room", "_airplay"); ``_airplay._tcp.local`` -> ("", ...)."""
    labels = name.rstrip(".").split(".")
    for i in range(len(labels) - 1):
        if labels[i].startswith("_") and labels[i + 1] in ("_tcp", "_udp"):
            inst = ".".join(labels[:i])
            if inst.endswith("._sub") or inst.startswith("_"):  # subtype browse: _foo._sub._airplay._tcp
                inst = ""
            return inst, labels[i]
    return None


def clean_instance(inst: str) -> str:
    """AirPlay audio names are ``MAC@Name``; strip the ID part. Unescape ``\\032`` style bytes."""
    inst = re.sub(r"\\(\d{3})", lambda m: chr(int(m.group(1))), inst).replace("\\", "")
    if "@" in inst:
        inst = inst.split("@", 1)[1]
    return inst.strip()


def model_name(model: str) -> str:
    if not model:
        return ""
    if model in APPLE_MODELS:
        return APPLE_MODELS[model]
    for prefix, name in MODEL_PREFIXES:
        if model.startswith(prefix) and (len(model) == len(prefix) or model[len(prefix)].isdigit()):
            return name
    return model


def service_label(svc: str) -> str:
    return SERVICES[svc][0] if svc in SERVICES else svc.lstrip("_")


def service_meaning(svc: str) -> str:
    return SERVICES[svc][1] if svc in SERVICES else f"offers the '{svc.lstrip('_')}' service"


def search_meaning(svc: str) -> str:
    return SERVICES[svc][2] if svc in SERVICES else f"'{svc.lstrip('_')}' services"


@dataclass
class Device:
    """One machine that announced itself over mDNS or SSDP, keyed by the address it announced from."""
    addr: str
    first_ts: float
    last_ts: float
    names: Counter = field(default_factory=Counter)
    hostname: str = ""
    model: str = ""
    services: dict = field(default_factory=dict)   # "_airplay" -> {"port": 7000, "txt": {...}}
    addrs: set = field(default_factory=set)         # other addresses it announced for itself
    announcements: int = 0
    goodbyes: int = 0
    server: str = ""                                # SSDP SERVER header
    upnp: set = field(default_factory=set)          # SSDP NT values

    @property
    def name(self) -> str:
        return self.names.most_common(1)[0][0] if self.names else self.hostname.removesuffix(".local")

    @property
    def model_name(self) -> str:
        return model_name(self.model)

    @property
    def os(self) -> str:
        mn = self.model_name
        family = next((fam for k, fam in OS_FOR.items() if mn.startswith(k)), "OS")
        for svc in self.services.values():
            if svc["txt"].get("osvers"):
                return f"{family} {svc['txt']['osvers']}"
        return ""

    @property
    def kind(self) -> str:
        """What sort of thing this is, in a couple of words."""
        if self.model_name:
            return self.model_name
        svcs = set(self.services)
        for keys, label in (({"_googlecast"}, "Google Cast device"), ({"_amzn-wplay"}, "Fire TV"),
                            ({"_sonos"}, "Sonos speaker"), ({"_ipp", "_ipps", "_printer", "_pdl-datastream"}, "printer"),
                            ({"_hap"}, "HomeKit accessory"), ({"_matter", "_matterc"}, "smart-home device"),
                            ({"_airplay", "_raop"}, "AirPlay device"), ({"_companion-link", "_rdlink"}, "Apple device"),
                            ({"_smb", "_afpovertcp", "_workstation", "_ssh"}, "computer")):
            if svcs & keys:
                return label
        if self.server or self.upnp:
            vendor = ssdp_vendor(self.server)
            dial = any("dial" in t.lower() for t in self.upnp)
            if vendor == "router" or any("internetgateway" in t.lower() for t in self.upnp):
                return "router"
            return f"{vendor} {'smart TV or streaming device' if dial else 'device'}".strip() if vendor or dial \
                else "UPnP device"
        return "device"

    @property
    def labels(self) -> list[str]:
        out = []
        for svc in self.services:
            lbl = service_label(svc)
            if lbl not in out and svc not in ("_device-info", "_services"):
                out.append(lbl)
        for t in sorted(self.upnp):
            offer = ssdp_offer(t)
            lbl = "casting (DIAL)" if "dial" in t.lower() else offer.split(" (")[0] if offer else ""
            if lbl and lbl not in out:
                out.append(lbl)
        return out

    def title(self) -> str:
        name, kind = self.name, self.kind
        if name and kind != "device" and kind.lower() not in name.lower():
            return f"{name} ({kind})"
        return name or kind

    def to_dict(self) -> dict:
        return dict(addr=self.addr, name=self.name, hostname=self.hostname, model=self.model,
                    model_name=self.model_name, kind=self.kind, os=self.os, services=self.labels,
                    addresses=sorted(self.addrs), announcements=self.announcements, server=self.server,
                    first_ts=self.first_ts, last_ts=self.last_ts,
                    txt={service_label(k): v["txt"] for k, v in self.services.items() if v["txt"]})


def interpret_mdns(msg: dict) -> dict:
    """Pull the useful bits out of one mDNS message.

    Returns ``dict(response, instances={svc: name}, services={svc: None} (ordered), hostnames=set, addrs=set, txt={svc: {...}},
    ports={svc: port}, asks=[svc], goodbye)``.
    """
    out = dict(response=msg.get("response", False), instances={}, services={}, hostnames=set(), addrs=set(),
               txt={}, ports={}, asks=[], goodbye=False, model="")
    records = msg.get("answers", []) + msg.get("authority", []) + msg.get("additional", [])
    for q in msg.get("questions", []):
        sp = split_service(q["name"])
        if sp and sp[1] not in out["asks"]:
            out["asks"].append(sp[1])
    for rr in records:
        name, rtype, data = rr["name"], rr["type"], rr["data"]
        if rr.get("ttl") == 0 and rtype in ("PTR", "SRV"):
            out["goodbye"] = True
        if rtype in ("A", "AAAA") and isinstance(data, str):
            out["hostnames"].add(name.rstrip("."))
            out["addrs"].add(data)
            continue
        sp = split_service(name) if rtype != "PTR" else split_service(data) if isinstance(data, str) else None
        if rtype == "PTR" and sp is None:
            continue  # reverse lookup (in-addr.arpa) or a plain browse list
        if sp is None:
            continue
        inst, svc = sp
        if svc == "_services":
            continue
        out["services"][svc] = None
        if inst:
            out["instances"].setdefault(svc, clean_instance(inst))
        if rtype == "TXT" and isinstance(data, str):
            txt = parse_txt(data)
            out["txt"].setdefault(svc, {}).update(txt)
            for key in ("model", "rpMd", "md", "am", "ty"):
                if txt.get(key) and not out["model"]:
                    out["model"] = txt[key]
        elif rtype == "SRV" and isinstance(data, str):
            parts = data.split()
            if len(parts) == 4:
                out["ports"][svc] = int(parts[2])
                out["hostnames"].add(parts[3].rstrip("."))
    if out["txt"].get("_googlecast", {}).get("fn"):
        out["instances"]["_googlecast"] = out["txt"]["_googlecast"]["fn"]
    return out


def mdns_summary(msg: dict) -> str:
    """One readable line for a packet list."""
    m = interpret_mdns(msg)
    if not m["response"]:
        if m["asks"]:
            return "mDNS: looking for " + ", ".join(search_meaning(s) for s in m["asks"][:3])
        names = [q["name"] for q in msg.get("questions", [])][:2]
        return "mDNS query " + ", ".join(names) if names else "mDNS query"
    if not m["services"]:
        hn = ", ".join(sorted(m["hostnames"])[:2])
        return f"mDNS: {hn} is at {', '.join(sorted(m['addrs'])[:2])}" if hn else "mDNS response"
    name = next(iter(m["instances"].values()), "") or next(iter(m["hostnames"]), "a device")
    model = model_name(m["model"])
    who = f"{name} ({model})" if model and model.lower() not in name.lower() else name
    labels = []
    for s in sorted(m["services"]):
        lbl = service_label(s)
        if lbl not in labels and s != "_device-info":
            labels.append(lbl)
    verb = "is leaving the network; withdrew" if m["goodbye"] else "announces"
    return f"mDNS: {who} {verb} {', '.join(labels) or 'its details'}"


def parse_ssdp(payload: bytes) -> dict | None:
    try:
        text = payload.decode("utf-8", "replace")
    except Exception:  # pragma: no cover - decode with replace never raises
        return None
    lines = text.split("\r\n") if "\r\n" in text else text.split("\n")
    first = lines[0].strip()
    if not (first.startswith(("M-SEARCH", "NOTIFY")) or first.startswith("HTTP/1.1 200")):
        return None
    headers = {}
    for ln in lines[1:]:
        k, sep, v = ln.partition(":")
        if sep:
            headers[k.strip().lower()] = v.strip()
    kind = "search" if first.startswith("M-SEARCH") else "notify" if first.startswith("NOTIFY") else "reply"
    target = headers.get("st") or headers.get("nt") or ""
    return dict(kind=kind, target=target, server=headers.get("server", ""), location=headers.get("location", ""),
                byebye=headers.get("nts", "") == "ssdp:byebye")


def ssdp_target(target: str) -> str:
    t = target.lower()
    if t in SSDP_TARGETS:
        return SSDP_TARGETS[t]
    if t.startswith("uuid:"):
        return "one specific device"
    m = re.match(r"urn:[^:]+:(device|service):([^:]+)", t)
    return f"{m.group(2)} {m.group(1)}s" if m else (target or "UPnP devices")


def ssdp_summary(s: dict) -> str:
    if s["kind"] == "search":
        return f"SSDP: searching for {ssdp_target(s['target'])}"
    vendor = ssdp_vendor(s["server"])
    who = f"a {vendor} device" if vendor else "a UPnP device"
    if s["byebye"]:
        return f"SSDP: {who} is leaving the network"
    offer = ssdp_offer(s["target"])
    return f"SSDP: {who} announces it {offer}" if offer else f"SSDP: {who} announces {ssdp_target(s['target'])}"


class Discovery:
    """Collects the devices that announced themselves and what everyone searched for."""

    def __init__(self):
        self.devices: dict[str, Device] = {}
        self.searches: dict[str, Counter] = {}   # address -> Counter of service types / SSDP targets looked for
        self.packets = 0

    def _device(self, addr: str, ts: float) -> Device:
        d = self.devices.get(addr)
        if d is None:
            d = self.devices[addr] = Device(addr, ts, ts)
        d.last_ts = ts
        return d

    def _find(self, src: str, m: dict) -> Device:
        """The same device often announces from its IPv4 and IPv6 addresses; its A/AAAA records tie them together."""
        d = self.devices.get(src)
        if d is None:
            d = next((self.devices[a] for a in m["addrs"] if a in self.devices), None)
            if d is None and m["hostnames"]:
                d = next((x for x in self.devices.values() if x.hostname in m["hostnames"]), None)
            if d is not None:
                self.devices[src] = d
        if d is None:
            # file it under its IPv4 address when it says what that is
            v4 = sorted(a for a in m["addrs"] if "." in a)
            d = self._device(v4[0] if v4 and ":" in src else src, m.get("ts", 0.0))
            self.devices[src] = d
        return d

    def process(self, pkt) -> dict | None:
        """Update from one packet; returns what it said (for the narrator) or None if it wasn't discovery."""
        layer = pkt.layer("mdns")
        if layer is not None:
            self.packets += 1
            m = interpret_mdns(layer.fields)
            m["ts"] = pkt.ts
            if not m["response"]:
                if m["asks"]:
                    c = self.searches.setdefault(pkt.src, Counter())
                    for s in m["asks"]:
                        c[s] += 1
                return dict(proto="mdns", m=m)
            if not (m["services"] or m["hostnames"]):
                return dict(proto="mdns", m=m)
            d = self._find(pkt.src, m)
            d.last_ts = pkt.ts
            d.announcements += 1
            d.goodbyes += m["goodbye"]
            for svc in m["services"]:
                entry = d.services.setdefault(svc, dict(port=None, txt={}))
                entry["txt"].update(m["txt"].get(svc, {}))
                if svc in m["ports"]:
                    entry["port"] = m["ports"][svc]
            for inst in m["instances"].values():
                if inst:
                    d.names[inst] += 1
            if m["model"] and (not d.model or d.model_name == d.model):
                d.model = m["model"]
            if m["hostnames"] and not d.hostname:
                d.hostname = sorted(m["hostnames"])[0]
            for a in m["addrs"] | {pkt.src}:
                if a != d.addr:
                    d.addrs.add(a)
                self.devices.setdefault(a, d)
            return dict(proto="mdns", m=m, device=d)
        udp = pkt.layer("udp")
        if udp is not None and 1900 in (udp["sport"], udp["dport"]) and pkt.payload:
            s = parse_ssdp(pkt.payload)
            if s is None:
                return None
            self.packets += 1
            if s["kind"] == "search":
                self.searches.setdefault(pkt.src, Counter())[s["target"] or "ssdp:all"] += 1
                return dict(proto="ssdp", s=s)
            d = self._device(pkt.src, pkt.ts)
            d.announcements += 1
            d.server = d.server or s["server"]
            if s["target"]:
                d.upnp.add(s["target"])
            return dict(proto="ssdp", s=s, device=d)
        return None

    def name_for(self, addr: str) -> str:
        d = self.devices.get(addr)
        if d is None:
            for dev in self.devices.values():
                if addr in dev.addrs:
                    d = dev
                    break
        return d.title() if d is not None and (d.names or d.model or d.hostname) else ""

    def unique(self) -> list[Device]:
        return list({id(d): d for d in self.devices.values()}.values())

    def ranked(self) -> list[Device]:
        return sorted(self.unique(), key=lambda d: (-len(d.services), -d.announcements))


def explain_txt(txt: dict) -> list[tuple[str, str, str]]:
    """[(key, value, meaning)] with a decoded model and HomeKit category where we know them."""
    rows = []
    for k, v in txt.items():
        meaning = TXT_KEYS.get(k, "")
        if k in ("model", "rpMd", "md", "am") and model_name(v) != v:
            meaning = f"model: {model_name(v)}"
        elif k == "ci" and v.isdigit():
            meaning = f"accessory category: {HAP_CATEGORIES.get(int(v), v)}"
        elif k == "acl" and v not in ("0", ""):
            meaning = "access control: restricted (only some people may use it)"
        rows.append((k, v, meaning))
    return rows
