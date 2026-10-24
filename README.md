# LanSled

Find devices on a network you specify. A small local web UI over a Python
backend: ARP scan, a ping-sweep fallback, a TCP port scan on whatever answers,
hostname lookups, and a vendor name for each MAC from a local copy of the IEEE
OUI registry — no accounts, no cloud, nothing about your network leaves your
machine.

**Only scan networks you own or have explicit permission to scan.**

## Windows: just the .exe, nothing to install

Grab **`LanSled.exe`** from the [latest release](https://github.com/vox4vulpes/LanSled/releases/latest)
and double-click it — no Python, no `pip`, nothing. Windows will ask to run
it as administrator (needed for the ARP scan's raw socket); say yes and a
browser tab opens on its own. Say no, or skip the release and just run it
normally, and it still works — it falls back to a ping sweep instead.

## Install and run from source

```sh
pip install -r requirements.txt
sudo python3 run.py        # root/admin: needed for the ARP scan's raw socket
```

Then open **http://127.0.0.1:5151**, type a network (`192.168.1.0/24`), hit
**Scan**. Results fill in live as they're found — MAC, vendor, hostname, then
whichever of the common ports (or a port list/range you set) are open on each.

Without root/admin, LanSled still runs: it falls back to a ping sweep and
reads your OS's own ARP cache for MACs, it just finds fewer devices (some
don't answer pings) and can't do the raw ARP broadcast. `--host 0.0.0.0` binds
it to every interface instead of just this machine; `--port` picks a different
port.

## How it works

- **ARP scan** (`scapy`): broadcasts a who-has for every address in the
  subnet, reads back the replies. Only works for a subnet this machine is
  actually on (ARP doesn't route), and needs a raw socket.
- **Ping sweep**: a plain ICMP ping to every address, threaded, no special
  privileges — the fallback when ARP isn't available, and a supplement when it
  is (catches anything ARP missed).
- **ARP cache read**: after the ping sweep, LanSled reads the OS's own
  neighbour table (`ip neigh` / `arp -a`) to pick up MACs for hosts it only
  found by pinging.
- **Vendor lookup**: the first three bytes of a MAC (the OUI) looked up
  against a local copy of the [IEEE's public OUI
  registry](https://standards-oui.ieee.org/oui/oui.csv) — over 40,000 entries,
  bundled in this repo, no network call at scan time.
- **Port scan**: a plain TCP `connect()` to each port, threaded — no raw
  sockets, no privileges needed, works for everyone regardless of the ARP
  scan's permissions.

A scan is capped at 1024 addresses (a `/22`) and 1024 ports at a time, so a
typo like `/8` fails instantly instead of trying to sweep 16 million
addresses.

## Project layout

- `lansled/scan.py` — the actual discovery: ARP, ping, ports, hostnames.
- `lansled/vendor.py` — the OUI lookup.
- `lansled/app.py` — the Flask app: serves the page, streams scan results
  over Server-Sent Events as they're found.
- `lansled/static/` — the single-page UI (`index.html`/`app.js`/`style.css`)
  and the bundled `oui.json`.
- `tests/` — unit tests for the parsing/validation/lookup logic (no real
  network access needed, so these run anywhere).
- `.github/workflows/build-windows.yml` — builds `LanSled.exe` on a Windows
  runner and attaches it to a release when you push a tag like `v0.1.0` (or
  run it by hand for just a build artifact).

## Building the portable .exe yourself

On Windows, with Python installed:

```sh
pip install -r requirements-build.txt
pyinstaller --onefile --name LanSled --add-data "lansled/static;lansled/static" --icon assets/icon.ico --uac-admin run.py
```

`dist\LanSled.exe` is the result. `--uac-admin` is what makes Windows prompt
for elevation on launch; drop it if you'd rather it just run unprivileged
(ping-sweep fallback) every time.

## License

[GNU AGPLv3](LICENSE). Copyright (c) 2026 vox4vulpes
