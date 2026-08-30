#!/usr/bin/env python3
"""
/etc/hosts domain blocker for the parental-control PoC (Linux).

Blocks websites by pointing their domains at 0.0.0.0 in the system hosts file,
so the OS resolves them to a dead address and the connection never leaves the
machine. This is the simplest, most portable way to block a site on Linux and
needs no firewall rules.

All of our entries live inside a clearly marked block:

    # >>> PARENTAL-CONTROL BLOCK START >>>
    # Managed automatically - do not edit by hand.
    0.0.0.0    example.com
    0.0.0.0    www.example.com
    # <<< PARENTAL-CONTROL BLOCK END <<<

Every time the block list is applied we remove the previous marked block in
full and write a fresh one, so the hosts file never accumulates stale entries
and anything a user wrote outside the markers is left untouched.

Usage (needs root to write /etc/hosts):
    sudo python3 hosts_blocker.py block example.com facebook.com
    sudo python3 hosts_blocker.py list
    sudo python3 hosts_blocker.py unblock            # remove our whole block

Point --hosts-file at a scratch file to try it without touching the system:
    python3 hosts_blocker.py --hosts-file ./hosts.test block example.com
"""

import argparse
import os
import sys
from datetime import datetime

# Marker lines that fence off the section we manage. We rewrite everything
# between them each run; lines outside them are never touched.
MARKER_START = "# >>> PARENTAL-CONTROL BLOCK START >>>"
MARKER_END = "# <<< PARENTAL-CONTROL BLOCK END <<<"

# Address every blocked domain resolves to. 0.0.0.0 is the standard "black
# hole" here: it is not a reachable host, so the browser fails fast.
BLACKHOLE_IP = "0.0.0.0"

DEFAULT_HOSTS_FILE = "/etc/hosts"


def normalize_domain(domain: str) -> str:
    """Clean a user-supplied domain: strip scheme, path, whitespace and case."""
    domain = domain.strip().lower()
    # Drop a scheme like "https://" and anything from the first slash onwards.
    if "://" in domain:
        domain = domain.split("://", 1)[1]
    domain = domain.split("/", 1)[0]
    # Drop a trailing port such as "example.com:8080".
    return domain.split(":")[0]


def expand_domain(domain: str) -> list[str]:
    """
    Return the host names to block for one domain.

    We block both the bare domain and its "www." form, since users type either.
    """
    if domain.startswith("www."):
        return [domain, domain[len("www."):]]
    return [domain, "www." + domain]


def read_hosts(hosts_path: str) -> list[str]:
    """Read the hosts file as a list of lines (empty list if it doesn't exist)."""
    if not os.path.exists(hosts_path):
        return []
    with open(hosts_path, "r", encoding="utf-8") as handle:
        return handle.read().splitlines()


def strip_managed_block(lines: list[str]) -> list[str]:
    """
    Return the hosts lines with our marked block removed.

    Everything from MARKER_START to MARKER_END (inclusive) is dropped; all
    other lines are kept exactly as they were. If no block is present the
    lines come back unchanged.
    """
    result = []
    inside_block = False
    for line in lines:
        if line.strip() == MARKER_START:
            inside_block = True
            continue
        if line.strip() == MARKER_END:
            inside_block = False
            continue
        if not inside_block:
            result.append(line)
    return result


def build_managed_block(domains: list[str]) -> list[str]:
    """Build the lines of a fresh managed block for the given host names."""
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    block = [
        MARKER_START,
        f"# Managed automatically by hosts_blocker.py - do not edit by hand.",
        f"# Last updated: {stamp}",
    ]
    for domain in domains:
        block.append(f"{BLACKHOLE_IP}\t{domain}")
    block.append(MARKER_END)
    return block


def write_hosts(hosts_path: str, lines: list[str]) -> None:
    """Write lines back to the hosts file with a trailing newline."""
    try:
        with open(hosts_path, "w", encoding="utf-8") as handle:
            handle.write("\n".join(lines).rstrip("\n") + "\n")
    except PermissionError:
        sys.exit(f"Permission denied writing {hosts_path}. Run with sudo.")


def collect_blocked_domains(raw_domains: list[str]) -> list[str]:
    """Normalize, expand to www/bare, and de-duplicate while keeping order."""
    ordered: list[str] = []
    seen: set[str] = set()
    for raw in raw_domains:
        cleaned = normalize_domain(raw)
        if not cleaned:
            continue
        for host in expand_domain(cleaned):
            if host not in seen:
                seen.add(host)
                ordered.append(host)
    return ordered


def apply_block(hosts_path: str, raw_domains: list[str]) -> None:
    """
    Replace our managed block with one blocking the given domains.

    The old block (if any) is removed first, then a fresh block is appended,
    guaranteeing no stale entries survive between runs.
    """
    domains = collect_blocked_domains(raw_domains)
    if not domains:
        sys.exit("No valid domains given.")

    lines = strip_managed_block(read_hosts(hosts_path))
    lines.extend(build_managed_block(domains))
    write_hosts(hosts_path, lines)

    print(f"Blocked {len(domains)} host name(s) in {hosts_path}:")
    for domain in domains:
        print(f"  {domain}")


def remove_block(hosts_path: str) -> None:
    """Remove our managed block entirely, unblocking everything we added."""
    original = read_hosts(hosts_path)
    stripped = strip_managed_block(original)
    if len(stripped) == len(original):
        print("No parental-control block found; nothing to remove.")
        return
    write_hosts(hosts_path, stripped)
    print(f"Removed the parental-control block from {hosts_path}.")


def list_block(hosts_path: str) -> None:
    """Print the host names currently inside our managed block."""
    inside_block = False
    found = False
    for line in read_hosts(hosts_path):
        stripped = line.strip()
        if stripped == MARKER_START:
            inside_block = True
            continue
        if stripped == MARKER_END:
            inside_block = False
            continue
        # Skip our own comment lines; print only the "0.0.0.0 domain" rows.
        if inside_block and stripped and not stripped.startswith("#"):
            print(stripped.split()[-1])
            found = True
    if not found:
        print("No domains are currently blocked.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Block or unblock websites via the Linux hosts file."
    )
    parser.add_argument(
        "--hosts-file", default=DEFAULT_HOSTS_FILE,
        help=f"hosts file to edit (default: {DEFAULT_HOSTS_FILE})",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    block_cmd = sub.add_parser("block", help="block one or more domains")
    block_cmd.add_argument("domains", nargs="+", help="domains to block")

    sub.add_parser("unblock", help="remove our entire managed block")
    sub.add_parser("list", help="show currently blocked domains")

    args = parser.parse_args()

    if args.command == "block":
        apply_block(args.hosts_file, args.domains)
    elif args.command == "unblock":
        remove_block(args.hosts_file)
    elif args.command == "list":
        list_block(args.hosts_file)


if __name__ == "__main__":
    main()
