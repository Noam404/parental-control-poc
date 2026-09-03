# Network Monitoring — HTTP/HTTPS Sniffer (PoC)

Captures web requests seen on the machine and prints a compact row per
request: an ascending index, the protocol, the domain, the packet size and
the time.

  * **HTTP**  (port 80)  — domain from the plaintext `Host` header.
  * **HTTPS** (port 443) — domain from the TLS **ClientHello SNI** field,
    which is sent unencrypted at the start of the handshake. The packet
    payload stays encrypted; only the destination hostname is revealed.

Built with **Scapy**, which runs the same way on Linux, Windows and macOS.
Primary target: **Ubuntu 22.04.5**.

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

On Ubuntu, Scapy uses libpcap (available out of the box; install explicitly
with `sudo apt install libpcap0.8` if needed).
On Windows, install [Npcap](https://npcap.com/) first.

## Run

Sniffing raw traffic needs elevated privileges.

```bash
sudo python3 http_sniffer.py                     # HTTP + HTTPS, default iface
sudo python3 http_sniffer.py -i eth0             # choose an interface
sudo python3 http_sniffer.py -f "tcp port 80"    # HTTP only
sudo python3 http_sniffer.py -c 20               # stop after 20 requests
```

On Windows, run from an **Administrator** terminal (no `sudo`).

Example output:

```
   #  PROTO    DOMAIN                                    SIZE(bytes)  TIME
------------------------------------------------------------------------------
   1  HTTP     example.com                                       412  18:02:07
   2  HTTPS    www.github.com                                    583  18:02:09
```

## Notes

- For HTTPS only the **domain** (SNI) is visible — never the path or content.
  A modern extension called Encrypted Client Hello (ECH) can hide even the
  SNI; those requests simply won't be resolved by this PoC.
- The sniffer only prints. Sending rows to the server over a socket is a
  separate task in the project roadmap.

---

# Domain Blocking — `hosts_blocker.py` (Linux)

Blocks websites by pointing their domains at `0.0.0.0` in the Linux hosts
file (`/etc/hosts`), so the OS resolves them to a dead address and the
connection never leaves the machine. No firewall rules needed.

All entries live between two markers, and the whole block is rewritten on
every run — so nothing outside the markers is touched and no stale entries
pile up:

```text
# >>> PARENTAL-CONTROL BLOCK START >>>
# Managed automatically by hosts_blocker.py - do not edit by hand.
0.0.0.0	example.com
0.0.0.0	www.example.com
# <<< PARENTAL-CONTROL BLOCK END <<<
```

Each blocked domain is expanded to both its bare and `www.` form.

## Run

Editing `/etc/hosts` needs root.

```bash
sudo python3 hosts_blocker.py block example.com facebook.com   # block sites
sudo python3 hosts_blocker.py list                             # show blocked
sudo python3 hosts_blocker.py unblock                          # remove block
```

Try it safely against a scratch file, no root required:

```bash
python3 hosts_blocker.py --hosts-file ./hosts.test block example.com
```
