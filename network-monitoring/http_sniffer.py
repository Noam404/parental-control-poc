#!/usr/bin/env python3
"""
HTTP/HTTPS request sniffer for the parental-control PoC.

Captures web requests on the local machine and prints, for each one, a
compact row: an ascending index, the requested domain, the packet size and
the time the request was seen.

  * HTTP  (port 80)  -> domain taken from the plaintext "Host" header.
  * HTTPS (port 443) -> domain taken from the TLS ClientHello "SNI" field,
                        which is sent unencrypted at the start of the
                        handshake.

Cross-platform (Linux / Windows / macOS) thanks to Scapy. Verified target is
Ubuntu 22.04.5.

Usage (needs raw-socket privileges):
    sudo python3 http_sniffer.py                 # sniff default interface
    sudo python3 http_sniffer.py -i eth0         # pick an interface
    sudo python3 http_sniffer.py -f "tcp port 80"          # HTTP only

On Windows run from an Administrator terminal with Npcap installed.
"""

import argparse
import sys
from datetime import datetime

try:
    from scapy.all import sniff
    from scapy.layers.http import HTTPRequest  # requires scapy >= 2.4.3
    from scapy.layers.inet import IP
    from scapy.packet import Raw
except ImportError:
    sys.exit(
        "Scapy is required. Install it with:\n"
        "    pip install scapy\n"
        "On Ubuntu you may also need: sudo apt install python3-scapy"
    )


# Column layout for the printed table.
HEADER = "{:>4}  {:<7}  {:<40}  {:>11}  {:<12}".format(
    "#", "PROTO", "DOMAIN", "SIZE(bytes)", "TIME"
)
ROW = "{:>4}  {:<7}  {:<40}  {:>11}  {:<12}"


def http_host(packet) -> str:
    """Domain of an HTTP request, from the Host header."""
    http = packet[HTTPRequest]
    if http.Host:
        host = http.Host.decode(errors="replace")
    elif packet.haslayer(IP):
        host = packet[IP].dst  # fall back to the destination IP
    else:
        host = "?"
    # Strip a trailing port such as "example.com:8080".
    return host.split(":")[0]


def tls_sni(payload: bytes) -> str | None:
    """
    Extract the SNI hostname from a TLS ClientHello.

    Parses the raw record by hand (no TLS layer needed). Returns the domain,
    or None if the payload is not a ClientHello or carries no SNI extension.
    Every access is bounds-checked so malformed packets just yield None.
    """
    try:
        # TLS record header: type(1) version(2) length(2).
        if len(payload) < 5 or payload[0] != 0x16:  # 0x16 = handshake
            return None
        pos = 5

        # Handshake header: type(1) length(3).
        if payload[pos] != 0x01:  # 0x01 = ClientHello
            return None
        pos += 4

        pos += 2 + 32  # client_version(2) + random(32)

        # session_id: len(1) + bytes.
        pos += 1 + payload[pos]

        # cipher_suites: len(2) + bytes.
        cipher_len = int.from_bytes(payload[pos:pos + 2], "big")
        pos += 2 + cipher_len

        # compression_methods: len(1) + bytes.
        pos += 1 + payload[pos]

        # extensions: len(2) + bytes.
        if pos + 2 > len(payload):
            return None
        ext_end = pos + 2 + int.from_bytes(payload[pos:pos + 2], "big")
        pos += 2

        while pos + 4 <= ext_end:
            ext_type = int.from_bytes(payload[pos:pos + 2], "big")
            ext_len = int.from_bytes(payload[pos + 2:pos + 4], "big")
            body = pos + 4
            if ext_type == 0x0000:  # server_name
                # server_name_list: len(2), then entry:
                #   name_type(1) + name_len(2) + name.
                name_len = int.from_bytes(payload[body + 3:body + 5], "big")
                start = body + 5
                name = payload[start:start + name_len]
                return name.decode(errors="replace") or None
            pos = body + ext_len
    except (IndexError, ValueError):
        return None
    return None


def make_handler():
    """Return a packet callback that keeps its own ascending counter."""
    counter = {"n": 0}

    def emit(proto: str, domain: str, size: int) -> None:
        counter["n"] += 1
        seen_at = datetime.now().strftime("%H:%M:%S")
        print(
            ROW.format(counter["n"], proto, domain[:40], size, seen_at),
            flush=True,
        )

    def handle(packet):
        if packet.haslayer(HTTPRequest):
            emit("HTTP", http_host(packet), len(packet))
        elif packet.haslayer(Raw):
            domain = tls_sni(bytes(packet[Raw].load))
            if domain:
                emit("HTTPS", domain, len(packet))

    return handle


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Sniff HTTP/HTTPS requests and print domain, size, time."
    )
    parser.add_argument(
        "-i", "--iface", default=None,
        help="network interface to sniff (default: Scapy's default)",
    )
    parser.add_argument(
        "-f", "--filter", default="tcp port 80 or tcp port 443",
        help='BPF capture filter (default: "tcp port 80 or tcp port 443")',
    )
    parser.add_argument(
        "-c", "--count", type=int, default=0,
        help="stop after N requests (0 = run until Ctrl+C)",
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
