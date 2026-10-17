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

from . import __version__, diff, explain, hosts, report, scoring, timeline, ui
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
        an.finish()
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


def cmd_summary(args) -> None:
    from . import story
    an = _analyze(args.file, keep=False)
    s = story.summarize(an)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(story.to_text(s))
        con.print(f"[green3]Wrote the summary to [bold]{args.out}[/]")
        return
    if args.text:
        sys.stdout.write(story.to_text(s))
        return
    con.print(ui.story_view(an, con.width, s))


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
    if flow.tls:
        con.print(ui.cert_panel(flow))
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
    con.print(ui.timeline_view(an, events, con.width))
    con.print(Text(f"{len(events)} events · {sum(e.count for e in events)} occurrences", style="grey62"))


def cmd_risk(args) -> None:
    an = _analyze(args.file, keep=False)
    flows = scoring.score_flows(an)
    if args.min:
        flows = [f for f in flows if f.risk.score >= args.min]
    con.print(ui.risk_table(flows, limit=args.limit, show_all=args.all))


def cmd_hosts(args) -> None:
    an = _analyze(args.file, keep=False)
    profiles = hosts.profile(an)
    if args.addr:
        match = [h for h in profiles if h.addr == args.addr or args.addr in h.names or args.addr in h.macs]
        if not match:
            con.print(f"[red]No host matches {args.addr!r}.[/] Known: " + ", ".join(h.addr for h in profiles[:12]))
            raise SystemExit(1)
        for h in match:
            con.print(ui.host_panel(h, an.first_ts))
        return
    if not args.all:
        profiles = [h for h in profiles if h.local or h.alerts_caused or h.services or h.max_risk]
    con.print(ui.hosts_table(profiles, args.n))
    con.print("[grey50]Run [bold]hosts FILE ADDRESS[/] for the full profile of one host.")


def cmd_diff(args) -> None:
    d = diff.diff_files(args.before, args.after, lambda p: _analyze(p, keep=False))
    con.print(ui.diff_view(d))
    if args.json:
        import json
        with open(args.json, "w") as f:
            json.dump(d, f, indent=2, default=str)
        con.print(f"[grey50]Differences written to {args.json}")


def cmd_hunt(args) -> None:
    an = _analyze(args.file, keep=False)
    findings = [x for x in an.findings if x.score >= args.min]
    con.print(ui.hunt_view(findings, an.first_ts or 0, an.last_ts or 0, con.width))
    hidden = len(an.findings) - len(findings)
    if hidden:
        con.print(f"[grey50]{hidden} weaker pattern(s) below score {args.min} hidden; use --min 0 to see them.")


def cmd_tls(args) -> None:
    an = _analyze(args.file, keep=False)
    flows = [f for f in an.flows if f.tls or f.tls_sni]
    if not flows:
        con.print("[grey62]No TLS sessions found.")
        return
    con.print(ui.tls_table(flows))
    if args.certs:
        for f in flows:
            if f.tls.get("certs"):
                con.print(ui.cert_panel(f))


def cmd_alerts(args) -> None:
    an = _analyze(args.file, keep=False, checksums=True)
    if not an.alerts:
        con.print(Panel(Text("No suspicious traffic detected.", style="green3"), border_style="green3"))
        return
    if args.explain:
        con.print(ui.alert_explanations(explain.group(an.alerts), an.first_ts))
    else:
        con.print(ui.alerts_table(an.alerts, an.first_ts))


def cmd_report(args) -> None:
    an = _analyze(args.file)
    path = report.write_report(an, args.file, args.out)
    con.print(f"[green3]Incident report written to [bold]{path}[/] "
              f"[grey50]({os.path.getsize(path) // 1024} KB, {len(an.alerts)} alerts, {len(an.flows)} flows)")


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


def _interactive() -> bool:
    return sys.stdin.isatty() and sys.stdout.isatty()


def cmd_explore(args) -> None:
    an = _analyze(args.file)
    if not _interactive():
        con.print("[yellow]The explorer needs an interactive terminal; showing the summary instead.[/]")
        ui.print_stats(an, args.file)
        return
    from .explorer import run
    run(an, args.file, con)


def cmd_demo(args) -> None:
    import tempfile
    folder = tempfile.mkdtemp(prefix="pktanalyzer-demo-")
    path = os.path.join(folder, "c2-demo.pcap" if args.c2 else "demo.pcap")
    if args.c2:
        from .craft import write_c2_sample
        write_c2_sample(path)
    else:
        write_sample(path)
    con.print(f"[green3]Made a demo capture at [bold]{path}[/][/]")
    args.file = path
    cmd_explore(args)


WELCOME = [
    ("Try it on demo traffic", "pktanalyzer demo", "a scan, ARP spoofing, a phishing site and more"),
    ("…or a hacked laptop", "pktanalyzer demo --c2", "beaconing and data leaving the network"),
    ("Open a capture file", "pktanalyzer capture.pcap", "browse it with the keyboard (? shows the keys)"),
    ("Explain a capture simply", "pktanalyzer summary capture.pcap", "what happened, in plain English"),
    ("Watch your network live", "sudo pktanalyzer live", "full-screen dashboard"),
    ("Record traffic to a file", "sudo pktanalyzer capture -w out.pcap", "Ctrl-C to stop"),
    ("Narrate live traffic", "sudo pktanalyzer capture --plain", "one readable line per new activity"),
    ("Make a shareable report", "pktanalyzer report capture.pcap", "one HTML file"),
    ("Compare two captures", "pktanalyzer diff before.pcap after.pcap", "what appeared or changed"),
    ("Every command", "pktanalyzer --help", ""),
]


def welcome() -> None:
    from rich.table import Table
    t = Table.grid(padding=(0, 3))
    t.add_column(style="bold cyan", no_wrap=True)
    t.add_column()
    for what, cmd, note in WELCOME:
        t.add_row(cmd, Text.assemble((what, "bold"), (f"\n{note}" if note else "", "grey62")))
    con.print(Panel(t, title=f"[bold]pktanalyzer {__version__}[/] · a packet analyzer you can read",
                    subtitle="only capture networks you own or may monitor", border_style="cyan",
                    title_align="left", padding=(1, 2)))


def cmd_sample(args) -> None:
    if args.c2:
        from .craft import write_c2_sample
        n = write_c2_sample(args.out)
        con.print(f"[green3]Wrote {n} packets to [bold]{args.out}[/]. Try:[/]\n  python -m pktanalyzer hunt {args.out}")
        return
    n = write_sample(args.out, baseline=args.baseline)
    con.print(f"[green3]Wrote {n} packets to [bold]{args.out}[/]. Try:[/]")
    if args.baseline:
        con.print(f"  python -m pktanalyzer sample after.pcap && python -m pktanalyzer diff {args.out} after.pcap")
        return
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
    con.print(f"[grey62]Capturing on [bold]{source}[/] · Ctrl-C to stop"
              + (" · one line per new kind of activity, repeats are counted" if args.plain else ""))
    shown = 0
    told: set = set()
    try:
        for frame in frames:
            if frame is None:
                continue
            if writer:
                writer.write(frame.ts, frame.data, frame.orig_len)
            pkt = an.feed(frame)
            if args.plain:
                for ev in an.narrator.recent(5):
                    # a new web connection is told once its TLS/HTTP request names the site
                    if ev.key in told or not pred(pkt) or (ev.kind == "connect" and set(ev.items) <= {80, 443}):
                        continue
                    told.add(ev.key)
                    shown += 1
                    con.print(ui.story_line(an.narrator, ev, con.width, None, wrap=True))
                if args.count and shown >= args.count:
                    break
                continue
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
    if an.count:
        con.print(ui.story_view(an, con.width))


def cmd_live(args) -> None:
    """Full-screen dashboard over a live interface or a replayed capture file."""
    import contextlib
    pred = compile_filter(args.filter)
    frames, source = _live_source(args)
    an = Analyzer(verify_checksums=args.checksums, keep_packets=False)
    dash = ui.Dashboard(an, source, pred)
    writer = PcapWriter(args.write) if args.write else None
    explore_after = False
    if _interactive():
        from .explorer import KeyReader
        reader = KeyReader()
        dash.keys = True
    else:
        reader = contextlib.nullcontext()

    def pressed(timeout: float = 0.0) -> list[str]:
        return reader.read(timeout) if dash.keys else []

    last = 0.0
    try:
        with reader, Live(dash.render(), console=con, screen=True, refresh_per_second=8, transient=False) as live:
            quit_now = False
            for frame in frames:
                if frame is not None:
                    if writer:
                        writer.write(frame.ts, frame.data, frame.orig_len)
                    dash.add(an.feed(frame))
                now = time.time()
                if now - last > 0.12:
                    for k in pressed():
                        if k == "q":
                            quit_now = True
                        elif k == " ":
                            dash.paused = not dash.paused
                        elif k == "s":
                            dash.story = not dash.story
                    # a paused replay stops reading; a paused live capture keeps counting but freezes the view
                    while dash.paused and args.read and not quit_now:
                        live.update(dash.render())
                        for k in pressed(0.25):
                            if k == "q":
                                quit_now = True
                            elif k == " ":
                                dash.paused = False
                            elif k == "s":
                                dash.story = not dash.story
                    if quit_now:
                        break
                    if not dash.paused:
                        live.update(dash.render())
                    last = now
            dash.paused = False
            live.update(dash.render())
            if args.read and not quit_now and dash.keys:
                # replay finished: keep the final picture up until the user quits
                dash.finished = True
                while True:
                    live.update(dash.render())
                    keys = pressed(0.25)
                    if "q" in keys:
                        break
                    if "e" in keys:
                        explore_after = True
                        break
                    if "s" in keys:
                        dash.story = not dash.story
    except KeyboardInterrupt:
        pass
    finally:
        if writer:
            writer.close()
    if explore_after:
        from .explorer import run
        run(_analyze(args.read), args.read, con)
        return
    ui.print_stats(an, source)
    if an.count:
        con.print(ui.story_view(an, con.width))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pktanalyzer", description="A from-scratch packet sniffer and protocol analyzer.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="examples:\n  pktanalyzer demo                    explore demo traffic with the keyboard\n"
               "  pktanalyzer capture.pcap            explore a capture (same as: explore capture.pcap)\n"
               "  pktanalyzer summary capture.pcap    what happened, in plain English\n"
               "  sudo pktanalyzer live               live dashboard\n"
               "  pktanalyzer report capture.pcap     HTML incident report\n"
               "  pktanalyzer COMMAND -h              help for one command")
    p.add_argument("--version", action="version", version=f"pktanalyzer {__version__}")
    sub = p.add_subparsers(dest="command", required=True, metavar="command")

    xp = sub.add_parser("explore", help="browse a capture interactively with the keyboard (? shows the keys)")
    xp.add_argument("file")
    xp.set_defaults(func=cmd_explore)

    dm = sub.add_parser("demo", help="make a demo capture and open it in the explorer")
    dm.add_argument("--c2", action="store_true", help="a compromised host (beaconing, exfiltration) instead")
    dm.set_defaults(func=cmd_demo)

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

    su = sub.add_parser("summary", help="what happened in plain English: who did what, what to worry about")
    su.add_argument("file")
    su.add_argument("--text", action="store_true", help="plain text without colours or boxes")
    su.add_argument("-o", "--out", metavar="FILE", help="write the plain-text summary to a file")
    su.set_defaults(func=cmd_summary)

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

    ho = sub.add_parser("hosts", help="profile every host: names, MAC, OS guess, role, services, lookups, alerts")
    ho.add_argument("file")
    ho.add_argument("addr", nargs="?", help="show the full profile of one IP, MAC or hostname")
    ho.add_argument("-n", type=int, help="show only the first N hosts")
    ho.add_argument("--all", action="store_true", help="include idle external hosts")
    ho.set_defaults(func=cmd_hosts)

    df = sub.add_parser("diff", help="compare two captures: new/missing flows, DNS, TLS, alerts, ports, bandwidth")
    df.add_argument("before")
    df.add_argument("after")
    df.add_argument("--json", metavar="FILE", help="also write the differences as JSON")
    df.set_defaults(func=cmd_diff)

    hu = sub.add_parser("hunt", help="look for beaconing (C2 check-ins) and data exfiltration")
    hu.add_argument("file")
    hu.add_argument("--min", type=int, default=45, help="minimum score to show (default 45)")
    hu.set_defaults(func=cmd_hunt)

    ts_ = sub.add_parser("tls", help="TLS sessions: SNI, version, cipher suite and certificate details")
    ts_.add_argument("file")
    ts_.add_argument("--certs", action="store_true", help="print every certificate chain in full")
    ts_.set_defaults(func=cmd_tls)

    al = sub.add_parser("alerts", help="run the anomaly detector and list findings")
    al.add_argument("file")
    al.add_argument("-e", "--explain", action="store_true", help="group alerts by rule with why it matters and what to do")
    al.set_defaults(func=cmd_alerts)

    rp = sub.add_parser("report", help="write a self-contained HTML incident report")
    rp.add_argument("file")
    rp.add_argument("-o", "--out", default="report.html", help="output file (default: ./report.html)")
    rp.set_defaults(func=cmd_report)

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
            c.add_argument("-p", "--plain", action="store_true",
                           help="print what is happening in plain English instead of raw packets")
        c.set_defaults(func=func)

    sa = sub.add_parser("sample", help="generate a demo pcap with normal traffic and attacks")
    sa.add_argument("--baseline", action="store_true", help="write the same network on a quiet day (for diff)")
    sa.add_argument("--c2", action="store_true", help="write a compromised host: beaconing and exfiltration (for hunt)")
    sa.add_argument("out", nargs="?", default="sample.pcap")
    sa.set_defaults(func=cmd_sample)

    i = sub.add_parser("interfaces", help="list network interfaces")
    i.set_defaults(func=cmd_interfaces)
    return p


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        welcome()
        return 0
    parser = build_parser()
    commands = next(a.choices for a in parser._actions if isinstance(a, argparse._SubParsersAction))
    if argv[0] not in commands and not argv[0].startswith("-") and os.path.isfile(argv[0]):
        argv.insert(0, "explore")  # `pktanalyzer capture.pcap` opens the explorer
    args = parser.parse_args(argv)
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
