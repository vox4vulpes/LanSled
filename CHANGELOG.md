# Changelog

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
