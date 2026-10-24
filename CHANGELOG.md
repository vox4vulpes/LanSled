# Changelog

## [0.1.2]

### Added
- A TCP presence probe for whatever a ping sweep still misses (ICMP blocked,
  but the device answers -- or even just refuses -- a connection on one of a
  handful of common ports). No raw sockets needed, so it works on a machine
  with no Npcap/WinPcap and no root/admin, same as the ping sweep.

## [0.1.1]

### Fixed
- A crash on Windows without Npcap/WinPcap installed: scapy raises a plain
  `RuntimeError` there (not the `OSError`/`PermissionError` this expected),
  which went uncaught and broke the scan mid-stream instead of falling back
  to a ping sweep like it's supposed to. Any failure from the ARP attempt is
  now treated the same way, and the SSE stream itself has a safety net so an
  unanticipated error still ends the scan cleanly instead of crashing it.

### Added
- An app icon for `LanSled.exe`.

## [0.1.0]

### Added
- ARP scan of a given subnet (`scapy`), with a no-privilege ping-sweep +
  OS-ARP-cache fallback when a raw socket isn't available.
- A threaded TCP connect-scan of each host found, against a default common-port
  list or a custom list/range.
- Hostname resolution (reverse DNS) and MAC vendor lookup against a bundled,
  40,000+ entry copy of the IEEE OUI registry — fully offline.
- A single-page local web UI: enter a network, results stream in live via
  Server-Sent Events as each device, hostname and port set is found.
- Input validation that rejects an oversized network or port range instantly,
  rather than trying to sweep millions of addresses.
- A portable `LanSled.exe` for Windows (built with PyInstaller, no Python
  install needed), with a CI workflow that builds and attaches it to a
  release on a version tag. It opens a browser tab on its own, and asks for
  admin so ARP scanning works out of the box.
