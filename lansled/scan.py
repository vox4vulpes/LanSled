"""The actual network discovery: ARP scan, a ping sweep as a fallback/supplement,
a TCP port scan on whatever answers, and hostname/vendor lookups. Everything here
is a generator that yields small dicts as it goes, so the web UI can fill in
results live instead of waiting for the whole subnet to finish.
"""
import ipaddress
import re
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from . import vendor

MAX_HOSTS = 1024          # a /22 -- past this a scan just takes too long to be useful
MAX_PORTS = 1024
PING_WORKERS = 64
PORT_WORKERS = 128
PING_TIMEOUT_S = 1.0
PORT_TIMEOUT_S = 0.6

DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 554, 631,
                  993, 995, 1723, 3306, 3389, 5000, 5432, 5900, 8000, 8080, 8443, 8888, 9100]

COMMON_PORT_NAMES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    554: "RTSP", 631: "IPP", 993: "IMAPS", 995: "POP3S", 1723: "PPTP",
    3306: "MySQL", 3389: "RDP", 5000: "UPnP/HTTP", 5432: "PostgreSQL",
    5900: "VNC", 8000: "HTTP-alt", 8080: "HTTP-alt", 8443: "HTTPS-alt",
    8888: "HTTP-alt", 9100: "Printer",
}


class ScanError(Exception):
    """A problem with the scan itself (bad input, too large a range)."""


class PermissionNeeded(Exception):
    """Raw ARP needs a privilege this process doesn't have."""


def parse_subnet(text):
    try:
        net = ipaddress.ip_network(text.strip(), strict=False)
    except ValueError as e:
        raise ScanError(f"“{text}” isn’t a valid network (try something like 192.168.1.0/24)") from e
    if net.version != 4:
        raise ScanError("only IPv4 for now")
    # check the size before materializing anything -- net.hosts() over a /8 is 16
    # million IPv4Address objects, and building that list just to reject it is slow
    if net.num_addresses > MAX_HOSTS:
        raise ScanError(f"{text} is {net.num_addresses} addresses — keep it to {MAX_HOSTS} or fewer (a /22 or smaller)")
    hosts = list(net.hosts()) if net.num_addresses > 1 else [net.network_address]
    return net, hosts


def parse_ports(text):
    if not text or not text.strip():
        return list(DEFAULT_PORTS)
    ports = set()
    for part in text.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            a, b = int(a), int(b)
            if a > b or a < 1 or b > 65535:
                raise ScanError(f"bad port range “{part}”")
            ports.update(range(a, b + 1))
        else:
            p = int(part)
            if not (1 <= p <= 65535):
                raise ScanError(f"bad port “{part}”")
            ports.add(p)
    if len(ports) > MAX_PORTS:
        raise ScanError(f"that’s {len(ports)} ports — keep it to {MAX_PORTS} or fewer")
    return sorted(ports)


# ---------- ARP (needs a raw socket -- root on Linux/macOS, admin + Npcap on Windows) ----------

def arp_scan(net, timeout=2.0):
    """{ip: mac} for everything that answers an ARP who-has on this subnet.
    Raises PermissionNeeded if this process can't do a raw layer-2 send --
    no root/admin on Linux/macOS, or no Npcap/WinPcap on Windows. Scapy's own
    failure for that varies by platform and even by Scapy version (OSError,
    PermissionError, RuntimeError, one of its own Scapy_Exception subclasses),
    so anything going wrong here is treated the same way: fall back to a ping
    sweep instead of crashing the whole scan."""
    try:
        from scapy.all import ARP, Ether, srp
    except ImportError as e:
        raise PermissionNeeded("scapy isn’t installed") from e
    try:
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(net))
        answered, _ = srp(pkt, timeout=timeout, verbose=False, retry=1)
    except Exception as e:  # noqa: BLE001 -- see the docstring: anything here means "no raw socket"
        raise PermissionNeeded(str(e)) from e
    return {r.psrc: r.hwsrc.upper() for _, r in answered}


# ---------- ping sweep: no special privileges needed, works everywhere ----------

def _ping_once(ip):
    if sys.platform.startswith("win"):
        cmd = ["ping", "-n", "1", "-w", str(int(PING_TIMEOUT_S * 1000)), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, int(PING_TIMEOUT_S))), ip]
    try:
        r = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            timeout=PING_TIMEOUT_S + 1.5)
        return ip if r.returncode == 0 else None
    except (subprocess.TimeoutExpired, OSError):
        return None


def ping_sweep(hosts):
    found = set()
    with ThreadPoolExecutor(max_workers=PING_WORKERS) as ex:
        futs = {ex.submit(_ping_once, str(h)): h for h in hosts}
        for fut in as_completed(futs):
            ip = fut.result()
            if ip:
                found.add(ip)
    return found


# ---------- read the OS's own ARP cache, to pick up MACs a ping sweep warmed up ----------

_ARP_LINE_RE = re.compile(
    r"\(?(\d{1,3}(?:\.\d{1,3}){3})\)?\s+.*?\b([0-9A-Fa-f]{1,2}(?::[0-9A-Fa-f]{1,2}){5}|[0-9A-Fa-f]{1,2}(?:-[0-9A-Fa-f]{1,2}){5})\b"
)


def read_arp_cache():
    """{ip: mac} from the OS's neighbour table -- a best-effort parse that doesn't
    need any special privileges, used to fill in MACs the ping sweep found."""
    out = {}
    cmds = [["ip", "neigh"]] if not sys.platform.startswith(("win", "darwin")) else []
    cmds.append(["arp", "-a"])
    for cmd in cmds:
        try:
            r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                timeout=5, text=True)
        except OSError:
            continue
        for line in r.stdout.splitlines():
            m = _ARP_LINE_RE.search(line)
            if m:
                ip, mac = m.group(1), m.group(2).upper().replace("-", ":")
                out[ip] = mac
        if out:
            break
    return out


# ---------- a TCP presence probe: for hosts that don't answer a ping (a
# closed-off device, or ICMP just blocked) but do answer *something* on one of
# a few very common ports -- even a closed-port refusal still means a live
# device, and either way the OS does its own ARP resolution to reach it, so
# read_arp_cache() can pick up a MAC afterward exactly like it does post-ping.
# No raw sockets, no admin/Npcap -- this works everywhere ping does. ----------

TCP_PROBE_PORTS = [80, 443, 22, 445, 139, 8080]
TCP_PROBE_TIMEOUT_S = 0.4


def _tcp_alive(ip):
    for port in TCP_PROBE_PORTS:
        try:
            with socket.create_connection((ip, port), timeout=TCP_PROBE_TIMEOUT_S):
                return True
        except ConnectionRefusedError:
            return True   # a RST still means someone's home, just not listening there
        except OSError:
            continue      # timeout / unreachable -- try the next port
    return False


def tcp_presence_sweep(hosts):
    found = set()
    hosts = list(hosts)
    if not hosts:
        return found
    with ThreadPoolExecutor(max_workers=PING_WORKERS) as ex:
        futs = {ex.submit(_tcp_alive, str(h)): h for h in hosts}
        for fut in as_completed(futs):
            if fut.result():
                found.add(str(futs[fut]))
    return found


# ---------- port scan: a plain TCP connect, no privileges needed ----------

def _probe_port(ip, port):
    try:
        with socket.create_connection((ip, port), timeout=PORT_TIMEOUT_S):
            return port
    except OSError:
        return None


def port_scan(ip, ports):
    open_ports = []
    with ThreadPoolExecutor(max_workers=min(PORT_WORKERS, max(1, len(ports)))) as ex:
        futs = {ex.submit(_probe_port, ip, p): p for p in ports}
        for fut in as_completed(futs):
            p = fut.result()
            if p:
                open_ports.append(p)
    return sorted(open_ports)


def resolve_hostname(ip):
    try:
        socket.setdefaulttimeout(1.0)
        name, _, _ = socket.gethostbyaddr(ip)
        return name
    except (socket.herror, socket.gaierror, OSError):
        return None
    finally:
        socket.setdefaulttimeout(None)


# ---------- orchestration ----------

def scan_network(subnet_text, ports_text, want_ports=True, want_hostnames=True):
    """Yields dicts: {'type': 'status'|'warning'|'host'|'ports'|'error'|'done', ...}."""
    t0 = time.time()
    try:
        net, hosts = parse_subnet(subnet_text)
        ports = parse_ports(ports_text) if want_ports else []
    except ScanError as e:
        yield {"type": "error", "message": str(e)}
        return

    yield {"type": "status", "message": f"Scanning {net} ({len(hosts)} addresses)…"}

    mac_by_ip = {}
    try:
        mac_by_ip = arp_scan(net)
        yield {"type": "status", "message": f"ARP found {len(mac_by_ip)} host(s), pinging the rest…"}
    except PermissionNeeded as e:
        yield {"type": "warning", "message": f"ARP scan needs admin/root privileges ({e}) — falling back to a ping sweep only."}

    pinged = ping_sweep(h for h in hosts if str(h) not in mac_by_ip)

    still_quiet = [h for h in hosts if str(h) not in mac_by_ip and str(h) not in pinged]
    tcp_found = tcp_presence_sweep(still_quiet)
    if tcp_found:
        yield {"type": "status", "message": f"{len(tcp_found)} more answered a TCP probe (no ping reply)…"}

    newly_found = pinged | tcp_found
    if newly_found:
        cache = read_arp_cache()
        for ip in newly_found:
            if ip not in mac_by_ip:
                mac = cache.get(ip)
                if mac:
                    mac_by_ip[ip] = mac

    all_ips = sorted(set(mac_by_ip) | newly_found, key=lambda s: tuple(int(p) for p in s.split(".")))
    yield {"type": "status", "message": f"{len(all_ips)} device(s) up."}

    hosts_out = []
    for ip in all_ips:
        mac = mac_by_ip.get(ip)
        host = {"ip": ip, "mac": mac, "vendor": vendor.lookup(mac) if mac else None, "hostname": None}
        hosts_out.append(host)
        yield {"type": "host", "ip": ip, "mac": mac, "vendor": host["vendor"]}

    if want_hostnames:
        with ThreadPoolExecutor(max_workers=PING_WORKERS) as ex:
            futs = {ex.submit(resolve_hostname, h["ip"]): h for h in hosts_out}
            for fut in as_completed(futs):
                h = futs[fut]
                name = fut.result()
                if name:
                    yield {"type": "hostname", "ip": h["ip"], "hostname": name}

    if want_ports and hosts_out:
        for h in hosts_out:
            open_ports = port_scan(h["ip"], ports)
            yield {"type": "ports", "ip": h["ip"],
                   "ports": [{"port": p, "name": COMMON_PORT_NAMES.get(p, "")} for p in open_ports]}

    yield {"type": "done", "count": len(all_ips), "elapsed": round(time.time() - t0, 1)}
