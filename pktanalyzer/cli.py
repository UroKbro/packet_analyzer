"""Command-line entry point: ``python -m pktanalyzer <command> ...``."""
from __future__ import annotations

import argparse
import os
import sys
import time

from rich.live import Live
from rich.panel import Panel
from rich.rule import Rule
from rich.text import Text

from . import __version__, scoring, timeline, ui
from .analyzer import Analyzer
from .capture import CaptureError, default_interface, list_interfaces, live_frames
from .craft import write_sample
from .export import export_all
from .filters import FilterError, compile_filter
from .pcap import CaptureFormatError, PcapWriter, open_capture

con = ui.console

FILTER_HELP = ('display filter, e.g. "tcp and port 443", "dns.qname contains google", '
               '"ip.src == 10.0.0.0/8 && tcp.flags.syn", "http.method == POST", "alerts"')


def _analyze(path: str, keep: bool = True, checksums: bool = True) -> Analyzer:
    an = Analyzer(verify_checksums=checksums, keep_packets=keep)
    with con.status(f"[cyan]Decoding {os.path.basename(path)}…", spinner="dots"):
        for _ in an.run(open_capture(path)):
            pass
    return an


def cmd_read(args) -> None:
    pred = compile_filter(args.filter)
    an = Analyzer(verify_checksums=not args.no_checksums, keep_packets=False)
    printer = ui.PacketPrinter(absolute_time=args.absolute)
    shown = 0
    for pkt in an.run(open_capture(args.file)):
        if not pred(pkt):
            continue
        shown += 1
        if args.verbose:
            con.print(ui.packet_detail(pkt, show_hex=args.hex))
        else:
            printer.print(pkt)
            if args.hex:
                con.print(ui.hexdump(pkt))
        if args.count and shown >= args.count:
            break
    con.print(Rule(style="grey35"))
    con.print(Text(f"{shown} of {an.count} packets shown · {len(an.flows)} flows · {len(an.alerts)} alerts",
                   style="grey62"))


def cmd_show(args) -> None:
    an = _analyze(args.file)
    for n in args.numbers:
        if not 1 <= n <= len(an.packets):
            con.print(f"[red]No packet #{n} (capture has {len(an.packets)})")
            continue
        con.print(ui.packet_detail(an.packets[n - 1], show_hex=not args.no_hex))


def cmd_stats(args) -> None:
    an = _analyze(args.file, keep=False, checksums=not args.no_checksums)
    ui.print_stats(an, os.path.basename(args.file))


def cmd_flows(args) -> None:
    an = _analyze(args.file, keep=False)
    scoring.score_flows(an)
    flows = an.flows
    if args.filter:
        pred = compile_filter(args.filter)
        an2 = Analyzer(keep_packets=False)
        ids = {p.flow_id for p in an2.run(open_capture(args.file)) if pred(p)}
        flows = [f for f in flows if f.id in ids]
    key = {"bytes": lambda f: -f.bytes, "packets": lambda f: -f.packets, "time": lambda f: f.first_ts,
           "duration": lambda f: -f.duration, "risk": lambda f: (-f.risk.score, f.first_ts)}[args.sort]
    con.print(ui.flows_table(sorted(flows, key=key), limit=args.limit))


def cmd_follow(args) -> None:
    an = _analyze(args.file, keep=False)
    flow = an.tracker.by_id.get(args.flow)
    if flow is None:
        con.print(f"[red]No flow {args.flow}. Run `flows` to list them.")
        sys.exit(1)
    scoring.score_flows(an)
    if flow.proto == "tcp":
        con.print(ui.handshake_panel(flow))
    con.print(Rule(f"Conversation ladder · flow {flow.id}", style="grey42"))
    con.print(ui.ladder(flow, limit=args.limit))
    if flow.http:
        con.print(ui.http_table([flow]))
    if flow.dns:
        con.print(ui.dns_table([flow]))
    if flow.proto == "tcp" and not args.no_stream:
        con.print(Rule("Reassembled stream", style="grey42"))
        con.print(ui.stream_view(flow, max_bytes=args.bytes))


def cmd_timeline(args) -> None:
    an = _analyze(args.file, keep=False)
    kinds = timeline.KINDS if args.all else timeline.DEFAULT_KINDS
    if args.kinds:
        kinds = tuple(k.strip() for k in args.kinds.split(","))
        bad = [k for k in kinds if k not in timeline.KINDS]
        if bad:
            con.print(f"[red]Unknown kind(s): {', '.join(bad)}. Choose from {', '.join(timeline.KINDS)}")
            sys.exit(2)
    events = timeline.build(an, kinds, host=args.host, flow_id=args.flow, collapse=not args.no_collapse)
    con.print(timeline.render(an, events, con.width))
    con.print(Text(f"{len(events)} events · {sum(e.count for e in events)} occurrences", style="grey62"))


def cmd_risk(args) -> None:
    an = _analyze(args.file, keep=False)
    flows = scoring.score_flows(an)
    if args.min:
        flows = [f for f in flows if f.risk.score >= args.min]
    con.print(ui.risk_table(flows, limit=args.limit, show_all=args.all))


def cmd_alerts(args) -> None:
    an = _analyze(args.file, keep=False, checksums=True)
    if not an.alerts:
        con.print(Panel(Text("No suspicious traffic detected.", style="green3"), border_style="green3"))
        return
    con.print(ui.alerts_table(an.alerts, an.first_ts))


def cmd_export(args) -> None:
    an = _analyze(args.file)
    packets = list(an.packets)
    if args.filter:
        pred = compile_filter(args.filter)
        packets = [p for p in packets if pred(p)]
    written = export_all(an, args.out, packets, write_streams=not args.no_streams)
    con.print(f"[green3]Exported {len(packets)} packets, {len(an.flows)} flows, {len(an.alerts)} alerts to "
              f"[bold]{args.out}[/]")
    for name, path in written.items():
        con.print(f"  [grey62]•[/] {name:<14} [grey50]{path}")


def cmd_sample(args) -> None:
    n = write_sample(args.out)
    con.print(f"[green3]Wrote {n} packets to [bold]{args.out}[/]. Try:[/]")
    for c in ("read", "stats", "flows", "alerts", "live -r"):
        con.print(f"  python -m pktanalyzer {c} {args.out}")
    con.print(f"  python -m pktanalyzer follow {args.out} 2")


def cmd_interfaces(args) -> None:
    default = default_interface()
    for name in list_interfaces():
        con.print(f"  {'[bold cyan]*' if name == default else ' '} {name}[/]")


def _live_source(args):
    if args.read:
        def replay():
            prev = None
            for frame in open_capture(args.read):
                if args.speed and prev is not None:
                    delay = (frame.ts - prev) / args.speed
                    if delay > 0:
                        time.sleep(min(delay, 2.0))
                prev = frame.ts
                yield frame
        return replay(), os.path.basename(args.read)
    iface = args.interface or default_interface()
    return live_frames(iface, promisc=not args.no_promisc, stop_after=args.duration), iface


def cmd_capture(args) -> None:
    """Print packets as they arrive, tcpdump-style."""
    pred = compile_filter(args.filter)
    frames, source = _live_source(args)
    an = Analyzer(verify_checksums=args.checksums, keep_packets=False)
    printer = ui.PacketPrinter(absolute_time=True)
    writer = PcapWriter(args.write) if args.write else None
    con.print(f"[grey62]Capturing on [bold]{source}[/] · Ctrl-C to stop")
    shown = 0
    try:
        for frame in frames:
            if frame is None:
                continue
            if writer:
                writer.write(frame.ts, frame.data, frame.orig_len)
            pkt = an.feed(frame)
            if pred(pkt):
                shown += 1
                if args.verbose:
                    con.print(ui.packet_detail(pkt, show_hex=False))
                else:
                    printer.print(pkt)
                if args.count and shown >= args.count:
                    break
    except KeyboardInterrupt:
        pass
    finally:
        if writer:
            writer.close()
    con.print(Rule(style="grey35"))
    con.print(f"[grey62]{an.count} packets captured, {shown} shown, {len(an.alerts)} alerts"
              + (f", saved to [bold]{args.write}" if args.write else ""))


def cmd_live(args) -> None:
    """Full-screen dashboard over a live interface or a replayed capture file."""
    pred = compile_filter(args.filter)
    frames, source = _live_source(args)
    an = Analyzer(verify_checksums=args.checksums, keep_packets=False)
    dash = ui.Dashboard(an, source, pred)
    writer = PcapWriter(args.write) if args.write else None
    last = 0.0
    try:
        with Live(dash.render(), console=con, screen=True, refresh_per_second=8, transient=False) as live:
            for frame in frames:
                if frame is not None:
                    if writer:
                        writer.write(frame.ts, frame.data, frame.orig_len)
                    dash.add(an.feed(frame))
                now = time.time()
                if now - last > 0.12:
                    live.update(dash.render())
                    last = now
            live.update(dash.render())
            if args.read:
                # replay finished: keep the final picture up until the user quits
                while True:
                    time.sleep(0.25)
                    live.update(dash.render())
    except KeyboardInterrupt:
        pass
    finally:
        if writer:
            writer.close()
    ui.print_stats(an, source)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="pktanalyzer",
                                description="A from-scratch packet sniffer and protocol analyzer.")
    p.add_argument("--version", action="version", version=f"pktanalyzer {__version__}")
    sub = p.add_subparsers(dest="command", required=True, metavar="command")

    r = sub.add_parser("read", help="list packets in a pcap/pcapng file")
    r.add_argument("file")
    r.add_argument("-f", "--filter", help=FILTER_HELP)
    r.add_argument("-c", "--count", type=int, help="stop after N matching packets")
    r.add_argument("-v", "--verbose", action="store_true", help="show the full layer tree for each packet")
    r.add_argument("-x", "--hex", action="store_true", help="add a colour-coded hex dump")
    r.add_argument("--absolute", action="store_true", help="wall-clock timestamps instead of relative")
    r.add_argument("--no-checksums", action="store_true", help="skip checksum validation")
    r.set_defaults(func=cmd_read)

    s = sub.add_parser("show", help="dissect specific packets in detail")
    s.add_argument("file")
    s.add_argument("numbers", type=int, nargs="+", metavar="N")
    s.add_argument("--no-hex", action="store_true")
    s.set_defaults(func=cmd_show)

    st = sub.add_parser("stats", help="summary: protocols, talkers, conversations, HTTP, DNS, alerts")
    st.add_argument("file")
    st.add_argument("--no-checksums", action="store_true")
    st.set_defaults(func=cmd_stats)

    fl = sub.add_parser("flows", help="list conversations with TCP state and handshake RTT")
    fl.add_argument("file")
    fl.add_argument("-f", "--filter", help="only flows containing a matching packet")
    fl.add_argument("--sort", choices=["bytes", "packets", "time", "duration", "risk"], default="time")
    fl.add_argument("-n", "--limit", type=int)
    fl.set_defaults(func=cmd_flows)

    fo = sub.add_parser("follow", help="ladder diagram + reassembled stream for one flow")
    fo.add_argument("file")
    fo.add_argument("flow", type=int, help="flow ID from the `flows` command")
    fo.add_argument("-n", "--limit", type=int, default=200, help="max packets in the ladder")
    fo.add_argument("--bytes", type=int, default=4000, help="max stream bytes to print per direction")
    fo.add_argument("--no-stream", action="store_true")
    fo.set_defaults(func=cmd_follow)

    tl = sub.add_parser("timeline", help="time-ordered view of handshakes, DNS, HTTP, TLS, resets and alerts")
    tl.add_argument("file")
    tl.add_argument("-k", "--kinds", help="comma-separated: " + ",".join(timeline.KINDS))
    tl.add_argument("--all", action="store_true", help="include connection closes too")
    tl.add_argument("--host", help="only events involving this IP")
    tl.add_argument("--flow", type=int, help="only events of this flow")
    tl.add_argument("--no-collapse", action="store_true", help="don't merge bursts of refusals/retransmissions")
    tl.set_defaults(func=cmd_timeline)

    rk = sub.add_parser("risk", help="rank conversations by a 0-100 risk score, with reasons")
    rk.add_argument("file")
    rk.add_argument("-n", "--limit", type=int, default=25)
    rk.add_argument("--min", type=int, help="only flows scoring at least this")
    rk.add_argument("--all", action="store_true", help="include flows that scored 0")
    rk.set_defaults(func=cmd_risk)

    al = sub.add_parser("alerts", help="run the anomaly detector and list findings")
    al.add_argument("file")
    al.set_defaults(func=cmd_alerts)

    ex = sub.add_parser("export", help="write flows/packets/alerts/DNS/HTTP as JSON+CSV, streams and a pcap")
    ex.add_argument("file")
    ex.add_argument("-o", "--out", default="export", help="output directory (default: ./export)")
    ex.add_argument("-f", "--filter", help="only export matching packets (flows are always complete)")
    ex.add_argument("--no-streams", action="store_true")
    ex.set_defaults(func=cmd_export)

    for name, func, hlp in (("capture", cmd_capture, "sniff live traffic and print packets (needs sudo)"),
                            ("live", cmd_live, "live full-screen dashboard (needs sudo, or -r to replay a file)")):
        c = sub.add_parser(name, help=hlp)
        c.add_argument("-i", "--interface", help=f"interface (default: {default_interface()})")
        c.add_argument("-r", "--read", metavar="FILE", help="replay a capture file instead of sniffing")
        c.add_argument("--speed", type=float, default=1.0 if name == "live" else 0,
                       help="replay speed multiplier (0 = as fast as possible)")
        c.add_argument("-f", "--filter", help=FILTER_HELP)
        c.add_argument("-w", "--write", metavar="FILE", help="also save raw frames to a pcap")
        c.add_argument("-t", "--duration", type=float, help="stop after N seconds")
        c.add_argument("--no-promisc", action="store_true", help="don't put the interface in promiscuous mode")
        c.add_argument("--checksums", action="store_true",
                       help="validate checksums (off by default live: NIC offload makes outgoing ones look wrong)")
        if name == "capture":
            c.add_argument("-c", "--count", type=int)
            c.add_argument("-v", "--verbose", action="store_true")
        c.set_defaults(func=func)

    sa = sub.add_parser("sample", help="generate a demo pcap with normal traffic and attacks")
    sa.add_argument("out", nargs="?", default="sample.pcap")
    sa.set_defaults(func=cmd_sample)

    i = sub.add_parser("interfaces", help="list network interfaces")
    i.set_defaults(func=cmd_interfaces)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        args.func(args)
    except FilterError as e:
        con.print(f"[bold red]Filter error:[/] {e}")
        return 2
    except (CaptureError, CaptureFormatError, FileNotFoundError) as e:
        con.print(f"[bold red]Error:[/] {e}")
        return 1
    except BrokenPipeError:
        pass
    except KeyboardInterrupt:
        return 130
    return 0
