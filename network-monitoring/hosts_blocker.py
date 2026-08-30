#!/usr/bin/env python3
"""
Block websites on Linux by editing /etc/hosts (parental-control PoC).

Each domain in BLOCKED_DOMAINS is pointed at 0.0.0.0, so the OS resolves it
to a dead address and the connection never leaves the machine. Our entries
live between two markers; every run removes the old marked block and writes a
fresh one, leaving everything outside the markers untouched.

Run as root:  sudo python3 hosts_blocker.py
"""

HOSTS_FILE = "/etc/hosts"
MARKER_START = "# >>> PARENTAL-CONTROL BLOCK START >>>"
MARKER_END = "# <<< PARENTAL-CONTROL BLOCK END <<<"

# Edit this list to choose what gets blocked.
BLOCKED_DOMAINS = [
    "example.com",
    "www.example.com",
]


def apply_block():
    with open(HOSTS_FILE) as f:
        lines = f.read().splitlines()

    # Keep every line that is not inside our old block.
    kept, inside = [], False
    for line in lines:
        if line.strip() == MARKER_START:
            inside = True
        elif line.strip() == MARKER_END:
            inside = False
        elif not inside:
            kept.append(line)

    # Append a fresh block with the current domain list.
    kept.append(MARKER_START)
    for domain in BLOCKED_DOMAINS:
        kept.append(f"0.0.0.0\t{domain}")
    kept.append(MARKER_END)

    with open(HOSTS_FILE, "w") as f:
        f.write("\n".join(kept) + "\n")

    print(f"Blocked {len(BLOCKED_DOMAINS)} domain(s) in {HOSTS_FILE}.")


if __name__ == "__main__":
    apply_block()
