#!/usr/bin/env python3
"""Block websites by pointing their domains at 0.0.0.0 in the hosts file.

Our entries live between two marker lines. Each run removes the old block and
writes a fresh one, so nothing outside the markers is ever touched.

Usage:
    sudo python3 hosts_blocker.py block example.com facebook.com
    sudo python3 hosts_blocker.py unblock
    sudo python3 hosts_blocker.py list
    python3 hosts_blocker.py --hosts-file ./hosts.test block example.com
"""

import argparse
import os

MARKER_START = "# >>> PARENTAL-CONTROL BLOCK START >>>"
MARKER_END = "# <<< PARENTAL-CONTROL BLOCK END <<<"
BLACKHOLE_IP = "0.0.0.0"
DEFAULT_HOSTS_FILE = "/etc/hosts"


def extract_domain(domain: str) -> str:
    """Strip scheme, path, port, whitespace and case from a domain."""
    domain = domain.strip().lower()
    if "://" in domain:
        domain = domain.split("://", 1)[1]
    domain = domain.split("/", 1)[0]
    return domain.split(":")[0]


def add_www_variant(domain: str) -> list[str]:
    """Return both the bare domain and its www. form."""
    if domain.startswith("www."):
        return [domain, domain[len("www."):]]
    return [domain, "www." + domain]


def read_hosts_lines(hosts_path: str) -> list[str]:
    if not os.path.exists(hosts_path):
        return []
    with open(hosts_path, "r", encoding="utf-8") as handle:
        return handle.read().splitlines()


def lines_without_our_block(lines: list[str]) -> list[str]:
    """Return the hosts lines with our marked block removed."""
    result = []
    inside_block = False
    for line in lines:
        if line.strip() == MARKER_START:
            inside_block = True
        elif line.strip() == MARKER_END:
            inside_block = False
        elif not inside_block:
            result.append(line)
    return result


def build_block_lines(domains: list[str]) -> list[str]:
    block = [MARKER_START]
    for domain in domains:
        block.append(f"{BLACKHOLE_IP}\t{domain}")
    block.append(MARKER_END)
    return block


def write_hosts_lines(hosts_path: str, lines: list[str]) -> None:
    with open(hosts_path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines).rstrip("\n") + "\n")


def domains_to_block(raw_domains: list[str]) -> list[str]:
    """Normalize, expand to www/bare, and de-duplicate while keeping order."""
    ordered: list[str] = []
    for raw in raw_domains:
        for host in add_www_variant(extract_domain(raw)):
            if host not in ordered:
                ordered.append(host)
    return ordered


def block_domains(hosts_path: str, raw_domains: list[str]) -> None:
    domains = domains_to_block(raw_domains)
    lines = lines_without_our_block(read_hosts_lines(hosts_path))
    lines.extend(build_block_lines(domains))
    write_hosts_lines(hosts_path, lines)


def unblock_all(hosts_path: str) -> None:
    write_hosts_lines(hosts_path, lines_without_our_block(read_hosts_lines(hosts_path)))


def print_blocked_domains(hosts_path: str) -> None:
    inside_block = False
    for line in read_hosts_lines(hosts_path):
        stripped = line.strip()
        if stripped == MARKER_START:
            inside_block = True
        elif stripped == MARKER_END:
            inside_block = False
        elif inside_block and stripped and not stripped.startswith("#"):
            print(stripped.split()[-1])


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--hosts-file", default=DEFAULT_HOSTS_FILE)
    sub = parser.add_subparsers(dest="command", required=True)
    block_cmd = sub.add_parser("block")
    block_cmd.add_argument("domains", nargs="+")
    sub.add_parser("unblock")
    sub.add_parser("list")

    args = parser.parse_args()
    if args.command == "block":
        block_domains(args.hosts_file, args.domains)
    elif args.command == "unblock":
        unblock_all(args.hosts_file)
    elif args.command == "list":
        print_blocked_domains(args.hosts_file)


if __name__ == "__main__":
    main()
