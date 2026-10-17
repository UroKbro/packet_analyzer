"""Export what the analyzer learned: flows, packets, alerts, DNS/HTTP logs, raw streams."""
from __future__ import annotations

import csv
import json
import os
import re

from .analyzer import Analyzer, info
from .flows import Flow
from .packet import Packet
from .pcap import PcapWriter
from .scoring import score_flows


def _safe(v):
    if isinstance(v, (bytes, bytearray)):
        return v.hex()
    if isinstance(v, dict):
        return {k: _safe(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [_safe(x) for x in v]
    return v


def packet_dict(pkt: Packet) -> dict:
    return dict(number=pkt.number, ts=pkt.ts, len=pkt.orig_len, src=pkt.src, dst=pkt.dst,
                sport=pkt.sport, dport=pkt.dport, protocol=pkt.protocol, info=info(pkt), flow=pkt.flow_id,
                direction=pkt.direction, warnings=pkt.warnings, alerts=[a.rule for a in pkt.alerts],
                layers={layer.name: _safe(layer.fields) for layer in pkt.layers})


def export_all(an: Analyzer, out_dir: str, packets: list[Packet] | None = None, write_streams: bool = True) -> dict:
    """Write a session bundle to ``out_dir`` and return the paths written."""
    os.makedirs(out_dir, exist_ok=True)
    score_flows(an)
    packets = list(an.packets) if packets is None else packets
    written = {}

    p = os.path.join(out_dir, "flows.json")
    with open(p, "w") as f:
        json.dump([_safe(fl.to_dict()) for fl in an.flows], f, indent=2, default=str)
    written["flows.json"] = p

    p = os.path.join(out_dir, "flows.csv")
    with open(p, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["id", "proto", "app", "client", "server", "state", "packets", "bytes", "first_ts",
                    "duration", "rtt_ms", "c2s_bytes", "s2c_bytes", "retransmissions", "sni", "risk", "risk_level",
                    "risk_reasons"])
        for fl in an.flows:
            c2s = fl.c2s.stream_total if fl.c2s else ""
            s2c = fl.s2c.stream_total if fl.s2c else ""
            rt = fl.c2s.retransmissions + fl.s2c.retransmissions if fl.c2s else ""
            w.writerow([fl.id, fl.proto, fl.label, f"{fl.client[0]}:{fl.client[1]}", f"{fl.server[0]}:{fl.server[1]}",
                        fl.state, fl.packets, fl.bytes, f"{fl.first_ts:.6f}", f"{fl.duration:.6f}",
                        f"{fl.rtt * 1000:.3f}" if fl.rtt is not None else "", c2s, s2c, rt, fl.tls_sni or "",
                        fl.risk.score, fl.risk.level, "; ".join(fl.risk.reasons)])
    written["flows.csv"] = p

    p = os.path.join(out_dir, "packets.jsonl")
    with open(p, "w") as f:
        for pkt in packets:
            f.write(json.dumps(packet_dict(pkt), default=str) + "\n")
    written["packets.jsonl"] = p

    p = os.path.join(out_dir, "alerts.json")
    with open(p, "w") as f:
        json.dump([a.to_dict() for a in an.alerts], f, indent=2)
    written["alerts.json"] = p

    from .hosts import profile
    p = os.path.join(out_dir, "hosts.json")
    with open(p, "w") as f:
        json.dump([h.to_dict() for h in profile(an)], f, indent=2, default=str)
    written["hosts.json"] = p

    dns_log = [dict(flow=fl.id, client=fl.client[0], server=fl.server[0], **d) for fl in an.flows for d in fl.dns]
    if dns_log:
        p = os.path.join(out_dir, "dns.json")
        with open(p, "w") as f:
            json.dump(dns_log, f, indent=2, default=str)
        written["dns.json"] = p

    http_log = [dict(flow=fl.id, client=f"{fl.client[0]}:{fl.client[1]}", server=f"{fl.server[0]}:{fl.server[1]}",
                     **tx) for fl in an.flows for tx in fl.to_dict().get("http", [])]
    if http_log:
        p = os.path.join(out_dir, "http.json")
        with open(p, "w") as f:
            json.dump(http_log, f, indent=2, default=str)
        written["http.json"] = p

    if packets:
        p = os.path.join(out_dir, "packets.pcap")
        with PcapWriter(p, packets[0].linktype) as w:
            for pkt in packets:
                w.write(pkt.ts, pkt.data, pkt.orig_len)
        written["packets.pcap"] = p

    if write_streams:
        n = 0
        sdir = os.path.join(out_dir, "streams")
        for fl in an.flows:
            n += write_flow_streams(fl, sdir)
        if n:
            written["streams/"] = sdir
    return written


def _flow_name(fl: Flow) -> str:
    raw = f"{fl.id:04d}_{fl.label}_{fl.client[0]}_{fl.client[1]}-{fl.server[0]}_{fl.server[1]}"
    return re.sub(r"[^A-Za-z0-9._-]", "_", raw)


def write_flow_streams(fl: Flow, sdir: str) -> int:
    """Write each direction's reassembled bytes, plus HTTP bodies, for one TCP flow."""
    if fl.proto != "tcp" or not (fl.c2s.stream or fl.s2c.stream):
        return 0
    os.makedirs(sdir, exist_ok=True)
    base = os.path.join(sdir, _flow_name(fl))
    for name, ep in (("client", fl.c2s), ("server", fl.s2c)):
        if ep.stream:
            with open(f"{base}.{name}.bin", "wb") as f:
                f.write(ep.stream)
    for i, tx in enumerate(fl.http):
        resp = tx.get("response")
        if resp and resp.get("body"):
            ctype = resp.get("content_type", "").split(";")[0]
            ext = {"text/html": "html", "application/json": "json", "text/plain": "txt", "image/png": "png",
                   "image/jpeg": "jpg", "application/javascript": "js", "text/css": "css"}.get(ctype, "bin")
            with open(f"{base}.http{i + 1}.{ext}", "wb") as f:
                f.write(resp["body"])
    return 1
