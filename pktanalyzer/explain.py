"""Plain-language explanations and next steps for every alert rule."""
from __future__ import annotations

from collections import defaultdict

# rule -> (title, why it matters, what to do)
RULES: dict[str, tuple[str, str, str]] = {
    "port-scan": ("Port scan",
                  "One host probed many ports in a short window. Attackers map open services this way before "
                  "trying to exploit them.",
                  "Identify the scanning host. If it isn't an authorised scanner, isolate it and review which "
                  "ports answered."),
    "host-sweep": ("Host sweep",
                   "One host tried the same port on many machines, looking for anything running that service.",
                   "Check the source host for compromise or an unapproved scanning tool."),
    "udp-scan": ("UDP scan",
                 "Many 'port unreachable' replies went to one host, which is what a UDP port scan produces.",
                 "Treat the original sender as a scanner; confirm whether the scan was authorised."),
    "syn-flood": ("SYN flood",
                  "A destination received hundreds of connection attempts per second, which can exhaust its "
                  "connection table (denial of service).",
                  "Enable SYN cookies or rate limiting upstream and look at the source distribution."),
    "null-scan": ("NULL scan",
                  "A TCP packet with no flags set has no legitimate use. Scanners send it to sneak past simple "
                  "filters and fingerprint the OS.",
                  "Block the source and check whether the target's firewall drops invalid TCP flags."),
    "xmas-scan": ("Xmas scan",
                  "FIN, PSH and URG set together ('lit up like a Christmas tree') is a stealth scanning technique.",
                  "Block the source and check firewall handling of invalid flag combinations."),
    "fin-scan": ("FIN scan",
                 "A FIN arrived for a connection that never existed, a classic way to probe ports quietly.",
                 "Treat the source as a scanner."),
    "syn-fin": ("SYN+FIN packet",
                "Opening and closing a connection in one packet is invalid and is used for OS fingerprinting "
                "and evasion.",
                "Drop such packets at the edge and investigate the sender."),
    "syn-rst": ("SYN+RST packet", "An invalid flag combination used by crafted-packet tools.",
                "Investigate the sender."),
    "land-attack": ("LAND attack",
                    "Source and destination are identical, an old trick that can make stacks loop.",
                    "Drop packets whose source equals destination at the edge."),
    "low-ttl": ("Very low TTL", "TCP traffic with TTL ≤ 1 is typical of traceroute or IDS evasion.",
                "Usually harmless; investigate if it repeats against sensitive hosts."),
    "suspicious-port": ("Suspicious port",
                        "Traffic used a port associated with backdoors, botnet C2 or remote-access services.",
                        "Find the process using the port on the internal host and confirm it is expected."),
    "ip-fragment": ("IP fragmentation abuse",
                    "Overlapping or oversized fragments are used to crash stacks (teardrop, ping of death) or "
                    "to hide payloads from inspection.",
                    "Ensure the network reassembles or drops anomalous fragments; investigate the sender."),
    "malformed": ("Malformed packet", "A packet could not be decoded cleanly.",
                  "Usually a capture artefact; investigate if it repeats from one source."),
    "bad-checksum": ("Bad checksum", "A header checksum did not verify.",
                     "Often caused by checksum offload on the capturing machine; ignore for outgoing traffic."),
    "large-icmp": ("Oversized ICMP", "Large ICMP echo payloads can carry data covertly or test fragmentation.",
                   "Check whether the size is expected (e.g. MTU probing)."),
    "dns-tunneling": ("Possible DNS tunneling",
                      "Very long or random-looking DNS names can carry encoded data out through DNS, bypassing "
                      "firewalls.",
                      "Inspect the originating host and the queried domain; block the domain if it isn't known."),
    "dns-txt": ("Long TXT query", "Tunneling tools favour TXT records because they carry the most data.",
                "Correlate with the tunneling alert and the domain's reputation."),
    "dns-unsolicited": ("Unsolicited DNS answer",
                        "A DNS response arrived with no matching query, which can indicate spoofing or cache "
                        "poisoning attempts.",
                        "Check the responder and enable DNSSEC validation where possible."),
    "nxdomain-burst": ("Burst of NXDOMAIN answers",
                       "A host looked up many names that don't exist, typical of malware using domain generation "
                       "algorithms (DGA).",
                       "Inspect the host for malware and review the queried names."),
    "scanner-ua": ("Scanning tool", "An HTTP User-Agent names an attack or vulnerability-scanning tool.",
                   "Confirm whether this was an authorised test; otherwise block the source."),
    "cleartext-credentials": ("Credentials in cleartext",
                              "A username or password crossed the network unencrypted and could be read by anyone "
                              "on the path.",
                              "Rotate the exposed credentials and move the service to TLS."),
    "path-traversal": ("Path traversal attempt",
                       "A request tried to climb out of the web root with ../ to read system files.",
                       "Check the response status and server logs to confirm the attempt failed."),
    "injection": ("Injection attempt", "A URI contained SQL injection or XSS patterns.",
                  "Check the application's response and logs; make sure input is parameterised/escaped."),
    "arp-spoof": ("ARP spoofing",
                  "An IP address suddenly claimed a different MAC address. This is how man-in-the-middle attacks "
                  "redirect LAN traffic.",
                  "Find the device with the new MAC, and consider dynamic ARP inspection on the switch."),
    "retransmissions": ("Heavy retransmission", "Many segments were resent, pointing to loss or congestion.",
                        "Check link quality and congestion along the path."),
    "tls-old-version": ("Deprecated TLS version",
                        "SSL 3.0, TLS 1.0 and 1.1 have known weaknesses and are disabled by modern browsers.",
                        "Upgrade the server to TLS 1.2 or 1.3."),
    "tls-weak-cipher": ("Weak TLS cipher", "RC4, DES/3DES, NULL and EXPORT ciphers can be broken or offer no "
                        "encryption at all.", "Disable these cipher suites on the server."),
    "tls-expired-cert": ("Expired certificate", "The server presented a certificate past its expiry date. Clients "
                         "that proceed anyway are open to interception.",
                         "Renew the certificate, or treat the site as untrusted."),
    "tls-cert-not-yet-valid": ("Certificate not yet valid", "The certificate's validity starts in the future, a "
                               "sign of a clock problem or a forged certificate.", "Check the server clock and issuer."),
    "tls-self-signed": ("Self-signed certificate", "No trusted authority vouches for this certificate; common on "
                        "test servers and in interception attacks.",
                        "Verify the fingerprint out of band before trusting it."),
    "tls-name-mismatch": ("Certificate name mismatch",
                          "The certificate doesn't cover the hostname the client asked for. Phishing and "
                          "interception proxies often look like this.",
                          "Do not trust the connection; investigate the server and the DNS answer that led to it."),
    "tls-weak-key": ("Weak certificate key", "RSA keys below 2048 bits can be factored with enough resources.",
                     "Reissue the certificate with a 2048-bit+ RSA or an EC key."),
    "tls-weak-signature": ("Weak certificate signature", "MD5 and SHA-1 signatures can be forged.",
                           "Reissue the certificate with SHA-256 or better."),
    "tls-bad-cert": ("Unparsable certificate", "The certificate could not be decoded.",
                     "Inspect the raw handshake; it may be corrupted or deliberately malformed."),
    "tls-handshake-failed": ("TLS handshake failed", "One side aborted the handshake with a fatal alert, often "
                             "because it rejected the certificate.", "Look at the alert reason and the certificate."),
    "beaconing": ("Beaconing",
                  "A host contacted the same destination on a steady timer. Malware checks in with its command-and-"
                  "control server this way to fetch instructions; people and most software don't keep such a rhythm.",
                  "Identify the process making the connections on the host, check the destination's reputation, and "
                  "block it if it's unknown. Regular jobs (updates, monitoring agents) can be allow-listed."),
    "exfiltration": ("Possible data exfiltration",
                     "Far more data left the host than came back, to a single destination. That is the shape of a "
                     "file being stolen, especially when the upload is encrypted or compressed on a plain port.",
                     "Find out what was sent: check the destination, the process and any files touched around that "
                     "time. Treat the data as exposed until shown otherwise."),
    "long-encrypted-session": ("Long-lived encrypted upload",
                               "An encrypted session stayed open for a long time and sent more than it received, "
                               "which can be a slow, quiet leak.",
                               "Confirm the destination and the application that holds the session open."),
    "dns-exfiltration": ("DNS exfiltration",
                         "Data was smuggled out inside DNS names: many unique, random-looking subdomains under one "
                         "domain. DNS is often allowed everywhere, which makes it a favourite covert channel.",
                         "Block the domain at the resolver, find the process on the host and work out what was "
                         "encoded."),
    "icmp-tunnel": ("ICMP tunnel", "Large amounts of data travelled inside ping packets, a known covert channel.",
                    "Limit ICMP payload sizes at the edge and inspect the sending host."),
}


def explain(rule: str) -> tuple[str, str, str]:
    return RULES.get(rule, (rule, "No description available.", "Investigate the hosts involved."))


def group(alerts: list) -> list[dict]:
    """Alerts grouped by rule with counts, hosts and flows, most severe first."""
    from .anomalies import SEVERITY_ORDER
    groups: dict[str, dict] = defaultdict(lambda: dict(count=0, sources=set(), targets=set(), flows=set(),
                                                       examples=[], severity="low", first=None))
    for a in alerts:
        g = groups[a.rule]
        g["count"] += 1
        g["sources"].add(a.src)
        g["targets"].add(a.dst)
        if a.flow is not None:
            g["flows"].add(a.flow)
        if len(g["examples"]) < 3:
            g["examples"].append(a.message)
        if SEVERITY_ORDER[a.severity] < SEVERITY_ORDER[g["severity"]]:
            g["severity"] = a.severity
        g["first"] = a.ts if g["first"] is None else min(g["first"], a.ts)
    out = []
    for rule, g in groups.items():
        title, why, action = explain(rule)
        out.append(dict(rule=rule, title=title, why=why, action=action, count=g["count"], severity=g["severity"],
                        sources=sorted(g["sources"]), targets=sorted(g["targets"]), flows=sorted(g["flows"]),
                        examples=g["examples"], first=g["first"]))
    return sorted(out, key=lambda g: (SEVERITY_ORDER[g["severity"]], g["first"]))
