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


def get_domain_from_http_host_header(packet) -> str:
    """
    Return the domain of a plaintext HTTP request.

    HTTP/1.1 puts the target site in the "Host" header, so we read it straight
    from there. If that header is somehow missing we fall back to the raw
    destination IP so the row is never blank.
    """
    http_layer = packet[HTTPRequest]
    if http_layer.Host:
        host = http_layer.Host.decode(errors="replace")
    elif packet.haslayer(IP):
        host = packet[IP].dst  # no Host header -> show where the packet is going
    else:
        host = "?"
    # A Host header may carry a port ("example.com:8080"); keep only the name.
    return host.split(":")[0]


def get_domain_from_tls_client_hello(tcp_payload: bytes) -> str | None:
    """
    Return the domain from a TLS ClientHello, or None if there isn't one.

    When a browser opens an HTTPS connection, the very first message it sends
    (the "ClientHello") announces which site it wants in the unencrypted
    Server Name Indication (SNI) extension. The rest of the connection is
    encrypted, but this one field is readable, so we walk the ClientHello
    byte-by-byte and pull the hostname out of it.

    We parse the raw bytes by hand instead of using Scapy's TLS layer because
    it is simpler and has no extra dependencies. Every field length is checked
    against the buffer, so a truncated or non-TLS packet just returns None
    rather than raising.
    """
    try:
        # -- TLS record header: content_type(1) + version(2) + length(2) --
        # 0x16 marks a "handshake" record; anything else is not a ClientHello.
        if len(tcp_payload) < 5 or tcp_payload[0] != 0x16:
            return None
        pos = 5

        # -- Handshake header: msg_type(1) + length(3) --
        # 0x01 is specifically the ClientHello message.
        if tcp_payload[pos] != 0x01:
            return None
        pos += 4

        pos += 2 + 32  # skip client_version(2) and the 32-byte random

        # session_id: one length byte, then that many bytes.
        pos += 1 + tcp_payload[pos]

        # cipher_suites: two-byte length, then that many bytes.
        cipher_suites_len = int.from_bytes(tcp_payload[pos:pos + 2], "big")
        pos += 2 + cipher_suites_len

        # compression_methods: one length byte, then that many bytes.
        pos += 1 + tcp_payload[pos]

        # -- extensions: two-byte total length, then the extension list --
        if pos + 2 > len(tcp_payload):
            return None
        extensions_end = pos + 2 + int.from_bytes(tcp_payload[pos:pos + 2], "big")
        pos += 2

        # Walk each extension looking for SNI (type 0x0000).
        while pos + 4 <= extensions_end:
            ext_type = int.from_bytes(tcp_payload[pos:pos + 2], "big")
            ext_len = int.from_bytes(tcp_payload[pos + 2:pos + 4], "big")
            ext_body = pos + 4
            if ext_type == 0x0000:  # server_name extension
                # Inside: server_name_list_len(2), then one entry made of
                # name_type(1) + host_name_len(2) + host_name bytes.
                host_name_len = int.from_bytes(
                    tcp_payload[ext_body + 3:ext_body + 5], "big"
                )
                host_name_start = ext_body + 5
                host_name = tcp_payload[
                    host_name_start:host_name_start + host_name_len
                ]
                return host_name.decode(errors="replace") or None
            pos = ext_body + ext_len  # skip to the next extension
    except (IndexError, ValueError):
        # Malformed / unexpected layout -> treat as "no domain found".
        return None
    return None


def build_packet_handler():
    """
    Build the per-packet callback that Scapy calls for every sniffed packet.

    The returned function keeps its own ascending request counter in a closure
    so each printed row is numbered 1, 2, 3, ... across the whole session.
    """
    request_counter = {"n": 0}

    def print_request_row(protocol: str, domain: str, packet_size: int) -> None:
        """Number and print one request as a table row."""
        request_counter["n"] += 1
        seen_at = datetime.now().strftime("%H:%M:%S")
        print(
            ROW.format(
                request_counter["n"], protocol, domain[:40], packet_size, seen_at
            ),
            flush=True,
        )

    def on_packet(packet) -> None:
        """Classify a packet as HTTP or HTTPS and print it if it's a request."""
        if packet.haslayer(HTTPRequest):
            print_request_row("HTTP", get_domain_from_http_host_header(packet),
                              len(packet))
        elif packet.haslayer(Raw):
            # Only ClientHello packets yield a domain; everything else -> None.
            domain = get_domain_from_tls_client_hello(bytes(packet[Raw].load))
            if domain:
                print_request_row("HTTPS", domain, len(packet))

    return on_packet


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
            prn=build_packet_handler(),
            store=False,
            count=args.count,
        )
    except PermissionError:
        sys.exit("Permission denied. Run with sudo / as Administrator.")
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
