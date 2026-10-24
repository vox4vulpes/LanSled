"""Unit tests for the pure logic in lansled.scan and lansled.vendor -- no real
network access, so these run anywhere (including CI)."""
import socket
import time
import unittest
from unittest import mock

from lansled import scan, vendor


class ParseSubnetTests(unittest.TestCase):
    def test_valid_cidr(self):
        net, hosts = scan.parse_subnet("192.168.0.0/30")
        self.assertEqual(str(net), "192.168.0.0/30")
        self.assertEqual([str(h) for h in hosts], ["192.168.0.1", "192.168.0.2"])

    def test_single_host(self):
        net, hosts = scan.parse_subnet("192.168.0.5/32")
        self.assertEqual([str(h) for h in hosts], ["192.168.0.5"])

    def test_garbage_input_rejected(self):
        with self.assertRaises(scan.ScanError):
            scan.parse_subnet("not-a-network")

    def test_ipv6_rejected(self):
        with self.assertRaises(scan.ScanError):
            scan.parse_subnet("::1/128")

    def test_oversized_subnet_rejected_without_hanging(self):
        # this used to materialize 16 million IPv4Address objects before checking
        # the size -- it must reject instantly, not after doing all that work
        t0 = time.time()
        with self.assertRaises(scan.ScanError):
            scan.parse_subnet("10.0.0.0/8")
        self.assertLess(time.time() - t0, 0.5)

    def test_boundary_is_exactly_max_hosts(self):
        # a /22 is exactly MAX_HOSTS (1024) addresses, counting the network and
        # broadcast address -- should be accepted right at the limit
        net, hosts = scan.parse_subnet("10.0.0.0/22")
        self.assertLessEqual(len(hosts), scan.MAX_HOSTS)


class ParsePortsTests(unittest.TestCase):
    def test_blank_gives_defaults(self):
        self.assertEqual(scan.parse_ports(""), scan.DEFAULT_PORTS)
        self.assertEqual(scan.parse_ports("   "), scan.DEFAULT_PORTS)

    def test_comma_list(self):
        self.assertEqual(scan.parse_ports("80, 22,443"), [22, 80, 443])

    def test_range(self):
        self.assertEqual(scan.parse_ports("1000-1003"), [1000, 1001, 1002, 1003])

    def test_mixed(self):
        self.assertEqual(scan.parse_ports("22,100-102"), [22, 100, 101, 102])

    def test_duplicates_collapse(self):
        self.assertEqual(scan.parse_ports("80,80,1-3"), [1, 2, 3, 80])

    def test_out_of_range_port_rejected(self):
        with self.assertRaises(scan.ScanError):
            scan.parse_ports("70000")
        with self.assertRaises(scan.ScanError):
            scan.parse_ports("0")

    def test_backwards_range_rejected(self):
        with self.assertRaises(scan.ScanError):
            scan.parse_ports("100-50")

    def test_too_many_ports_rejected(self):
        with self.assertRaises(scan.ScanError):
            scan.parse_ports("1-{}".format(scan.MAX_PORTS + 1))


class ArpScanFallbackTests(unittest.TestCase):
    """Scapy's raw-socket failure shows up as a different exception type on
    every platform (and even different Scapy versions) -- a Windows machine
    with no Npcap/WinPcap raises a plain RuntimeError, not an OSError or
    PermissionError, and this was missed once already (it crashed the whole
    SSE stream instead of falling back to a ping sweep). Whatever scapy
    throws here must become PermissionNeeded, never propagate raw."""

    def _net(self):
        net, _ = scan.parse_subnet("192.168.0.0/30")
        return net

    def test_runtime_error_from_missing_npcap_is_caught(self):
        with mock.patch("scapy.all.srp", side_effect=RuntimeError(
                "Sniffing and sending packets is not available at layer 2: winpcap is not installed.")):
            with self.assertRaises(scan.PermissionNeeded):
                scan.arp_scan(self._net())

    def test_permission_error_is_caught(self):
        with mock.patch("scapy.all.srp", side_effect=PermissionError("Operation not permitted")):
            with self.assertRaises(scan.PermissionNeeded):
                scan.arp_scan(self._net())

    def test_os_error_is_caught(self):
        with mock.patch("scapy.all.srp", side_effect=OSError("Socket type not supported")):
            with self.assertRaises(scan.PermissionNeeded):
                scan.arp_scan(self._net())

    def test_some_other_unexpected_exception_is_still_caught(self):
        # the point of the broad catch: whatever it is, the scan must not crash
        with mock.patch("scapy.all.srp", side_effect=ValueError("something scapy-internal")):
            with self.assertRaises(scan.PermissionNeeded):
                scan.arp_scan(self._net())


class TcpPresenceSweepTests(unittest.TestCase):
    """A host that doesn't answer a ping (ICMP blocked, or just a device that
    doesn't reply to it) should still turn up if it answers -- or even just
    refuses -- a connection on one of a few common ports. No ping, no ARP, no
    admin: this is what's left to find such a host on a machine with no
    Npcap/WinPcap at all."""

    def test_open_port_counts_as_alive(self):
        with mock.patch("socket.create_connection", return_value=mock.MagicMock(__enter__=mock.MagicMock(), __exit__=mock.MagicMock())):
            self.assertTrue(scan._tcp_alive("10.0.0.5"))

    def test_connection_refused_still_counts_as_alive(self):
        # a RST means a live device, even though nothing's listening on that port
        with mock.patch("socket.create_connection", side_effect=ConnectionRefusedError()):
            self.assertTrue(scan._tcp_alive("10.0.0.5"))

    def test_every_port_timing_out_means_not_alive(self):
        with mock.patch("socket.create_connection", side_effect=socket.timeout()):
            self.assertFalse(scan._tcp_alive("10.0.0.5"))

    def test_tries_the_next_port_after_a_timeout(self):
        # times out on the first probe port, then succeeds on a later one
        calls = []

        def fake_connect(addr, timeout):
            calls.append(addr[1])
            if addr[1] == scan.TCP_PROBE_PORTS[0]:
                raise socket.timeout()
            return mock.MagicMock(__enter__=mock.MagicMock(), __exit__=mock.MagicMock())

        with mock.patch("socket.create_connection", side_effect=fake_connect):
            self.assertTrue(scan._tcp_alive("10.0.0.5"))
        self.assertGreaterEqual(len(calls), 2)

    def test_sweep_returns_only_the_hosts_that_answered(self):
        def fake_alive(ip):
            return ip == "10.0.0.2"

        with mock.patch("lansled.scan._tcp_alive", side_effect=fake_alive):
            found = scan.tcp_presence_sweep(["10.0.0.1", "10.0.0.2", "10.0.0.3"])
        self.assertEqual(found, {"10.0.0.2"})

    def test_empty_host_list_short_circuits(self):
        self.assertEqual(scan.tcp_presence_sweep([]), set())


class VendorLookupTests(unittest.TestCase):
    def test_known_oui_with_colons(self):
        self.assertIsNotNone(vendor.lookup("B8:27:EB:00:00:00"))

    def test_known_oui_with_dashes_and_lowercase(self):
        self.assertEqual(vendor.lookup("b8-27-eb-11-22-33"), vendor.lookup("B8:27:EB:44:55:66"))

    def test_unassigned_oui_returns_none(self):
        self.assertIsNone(vendor.lookup("02:00:00:00:00:00"))

    def test_garbage_mac_returns_none(self):
        self.assertIsNone(vendor.lookup("not-a-mac"))
        self.assertIsNone(vendor.lookup(None))

    def test_normalize_mac(self):
        self.assertEqual(vendor.normalize_mac("aa:bb:cc:dd:ee:ff"), "AABBCCDDEEFF")
        self.assertEqual(vendor.normalize_mac("AA-BB-CC-DD-EE-FF"), "AABBCCDDEEFF")
        self.assertIsNone(vendor.normalize_mac("short"))


if __name__ == "__main__":
    unittest.main()
