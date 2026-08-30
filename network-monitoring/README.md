# Network Monitoring — HTTP Sniffer (PoC)

Captures HTTP requests seen on the machine and prints a compact row per
request: an ascending index, the domain, the packet size and the time.

Built with **Scapy**, which runs the same way on Linux, Windows and macOS.
Primary target: **Ubuntu 22.04.5**.

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

On Ubuntu, Scapy uses libpcap; it is available out of the box but you can
install it explicitly with `sudo apt install libpcap0.8`.
On Windows, install [Npcap](https://npcap.com/) first.

## Run

Sniffing raw traffic needs elevated privileges.

```bash
sudo python3 http_sniffer.py                 # default interface, tcp/80
sudo python3 http_sniffer.py -i eth0         # choose an interface
sudo python3 http_sniffer.py -f "tcp port 80 or tcp port 8080"
sudo python3 http_sniffer.py -c 20           # stop after 20 requests
```

On Windows, run from an **Administrator** terminal (no `sudo`).

## Notes

- Only unencrypted **HTTP** requests expose the `Host` header used for the
  domain. HTTPS traffic is encrypted; a later step will extract the domain
  from the TLS SNI field instead.
- This PoC only prints. Sending rows to the server over a socket and the
  firewall/blocking logic are separate tasks in the project roadmap.
