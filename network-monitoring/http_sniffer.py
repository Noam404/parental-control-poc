#!/usr/bin/env python3
"""
HTTP request sniffer for the parental-control PoC.

Captures HTTP requests on the local machine and prints, for each one, a
compact row: an ascending index, the requested domain, the packet size and
the time the request was seen.

Cross-platform (Linux / Windows / macOS) thanks to Scapy. Verified target is
Ubuntu 22.04.5.

Usage (needs raw-socket privileges):
    sudo python3 http_sniffer.py                 # sniff default interface
    sudo python3 http_sniffer.py -i eth0         # pick an interface
    sudo python3 http_sniffer.py -f "tcp port 80 or tcp port 8080"

On Windows run from an Administrator terminal with Npcap installed.
"""

import argparse
import sys
from datetime import datetime

try:
    from scapy.all import sniff
    from scapy.layers.http import HTTPRequest  # requires scapy >= 2.4.3
    from scapy.layers.inet import IP
except ImportError:
    sys.exit(
        "Scapy is required. Install it with:\n"
        "    pip install scapy\n"
        "On Ubuntu you may also need: sudo apt install python3-scapy"
    )


# Column layout for the printed table.
HEADER = "{:>4}  {:<40}  {:>11}  {:<12}".format(
    "#", "DOMAIN", "SIZE(bytes)", "TIME"
)
ROW = "{:>4}  {:<40}  {:>11}  {:<12}"


def domain_of(packet) -> str:
    """Best-effort domain for an HTTP request packet."""
    http = packet[HTTPRequest]
    # The Host header is the reliable source of the domain for HTTP/1.1.
    if http.Host:
        host = http.Host.decode(errors="replace")
    elif packet.haslayer(IP):
        host = packet[IP].dst  # fall back to the destination IP
    else:
        host = "?"
    # Strip a trailing port such as "example.com:8080".
    return host.split(":")[0]


def make_handler():
    """Return a packet callback that keeps its own ascending counter."""
    counter = {"n": 0}

    def handle(packet):
        if not packet.haslayer(HTTPRequest):
            return
        counter["n"] += 1
        domain = domain_of(packet)
        size = len(packet)
        seen_at = datetime.now().strftime("%H:%M:%S")
        print(ROW.format(counter["n"], domain[:40], size, seen_at), flush=True)

    return handle


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Sniff HTTP requests and print domain, size and time."
    )
    parser.add_argument(
        "-i", "--iface", default=None,
        help="network interface to sniff (default: Scapy's default)",
    )
    parser.add_argument(
        "-f", "--filter", default="tcp port 80",
        help='BPF capture filter (default: "tcp port 80")',
    )
    parser.add_argument(
        "-c", "--count", type=int, default=0,
        help="stop after N HTTP requests (0 = run until Ctrl+C)",
    )
    args = parser.parse_args()

    print(HEADER)
    print("-" * len(HEADER))

    try:
        sniff(
            iface=args.iface,
            filter=args.filter,
            prn=make_handler(),
            store=False,
            count=args.count,
        )
    except PermissionError:
        sys.exit("Permission denied. Run with sudo / as Administrator.")
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
