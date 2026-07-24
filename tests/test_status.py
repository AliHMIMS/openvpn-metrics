import unittest

from ovpn_metrics.status import parse_status

STATUS_V1 = """\
OpenVPN CLIENT LIST
Updated,Thu Jul 24 04:23:14 2026
Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since
alice,203.0.113.10:52345,3871,3924,Thu Jul 24 04:23:05 2026
bob,198.51.100.7:41000,120000,98000,Thu Jul 24 03:00:00 2026
ROUTING TABLE
Virtual Address,Common Name,Real Address,Last Ref
10.8.0.6,alice,203.0.113.10:52345,Thu Jul 24 04:23:14 2026
10.8.0.10,bob,198.51.100.7:41000,Thu Jul 24 04:23:10 2026
192.168.100.0/24,bob,198.51.100.7:41000,Thu Jul 24 04:23:10 2026
GLOBAL STATS
Max bcast/mcast queue length,0
END
"""

STATUS_V2 = """\
TITLE,OpenVPN 2.5.5 x86_64-pc-linux-gnu
TIME,Thu Jul 24 04:23:14 2026,1784866994
HEADER,CLIENT_LIST,Common Name,Real Address,Virtual Address,Virtual IPv6 Address,Bytes Received,Bytes Sent,Connected Since,Connected Since (time_t),Username,Client ID,Peer ID
CLIENT_LIST,alice,203.0.113.10:52345,10.8.0.6,,3871,3924,Thu Jul 24 04:23:05 2026,1784866985,UNDEF,0,0
CLIENT_LIST,bob,198.51.100.7:41000,10.8.0.10,fd00::10,120000,98000,Thu Jul 24 03:00:00 2026,1784862000,UNDEF,1,1
HEADER,ROUTING_TABLE,Virtual Address,Common Name,Real Address,Last Ref,Last Ref (time_t)
ROUTING_TABLE,10.8.0.6,alice,203.0.113.10:52345,Thu Jul 24 04:23:14 2026,1784866994
ROUTING_TABLE,10.8.0.10,bob,198.51.100.7:41000,Thu Jul 24 04:23:10 2026,1784866990
GLOBAL_STATS,Max bcast/mcast queue length,0
END
"""

STATUS_V3 = STATUS_V2.replace(",", "\t")


class StatusV1Tests(unittest.TestCase):
    def test_routes(self):
        snap = parse_status(STATUS_V1)
        self.assertEqual(snap.routes["10.8.0.6"], "alice")
        self.assertEqual(snap.routes["10.8.0.10"], "bob")
        self.assertEqual(snap.routes["192.168.100.0/24"], "bob")

    def test_clients(self):
        snap = parse_status(STATUS_V1)
        self.assertEqual(len(snap.clients), 2)
        alice = next(c for c in snap.clients if c.common_name == "alice")
        self.assertEqual(alice.real_address, "203.0.113.10:52345")
        self.assertEqual(alice.bytes_received, 3871)
        self.assertEqual(alice.bytes_sent, 3924)
        # virtual address backfilled from routing table
        self.assertEqual(alice.virtual_address, "10.8.0.6")


class StatusV2Tests(unittest.TestCase):
    def test_routes_and_v6(self):
        snap = parse_status(STATUS_V2)
        self.assertEqual(snap.routes["10.8.0.6"], "alice")
        self.assertEqual(snap.routes["10.8.0.10"], "bob")
        self.assertEqual(snap.routes["fd00::10"], "bob")

    def test_clients(self):
        snap = parse_status(STATUS_V2)
        bob = next(c for c in snap.clients if c.common_name == "bob")
        self.assertEqual(bob.virtual_address, "10.8.0.10")
        self.assertEqual(bob.bytes_received, 120000)
        self.assertEqual(bob.connected_since, "Thu Jul 24 03:00:00 2026")


class StatusV3Tests(unittest.TestCase):
    def test_tab_separated(self):
        snap = parse_status(STATUS_V3)
        self.assertEqual(snap.routes["10.8.0.6"], "alice")
        self.assertEqual(len(snap.clients), 2)


class EdgeCaseTests(unittest.TestCase):
    def test_empty_input(self):
        snap = parse_status("")
        self.assertEqual(snap.routes, {})
        self.assertEqual(snap.clients, [])

    def test_garbage_input(self):
        snap = parse_status("not a status file\nat all\n")
        self.assertEqual(snap.routes, {})


if __name__ == "__main__":
    unittest.main()
