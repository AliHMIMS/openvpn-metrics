import os
import tempfile
import unittest

from ovpn_metrics.db import Database
from ovpn_metrics.status import ClientSession


class DatabaseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Database(os.path.join(self.tmp.name, "test.db"))

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def _seed(self):
        # alice hits 9.9.9.9:443 in two buckets, bob hits it in one
        self.db.flush_aggregates({
            ("alice", "9.9.9.9", 443, "tcp", "out", 1000060): [5, 500, 1000063.0, 1000110.0],
            ("alice", "9.9.9.9", 443, "tcp", "in", 1000060): [4, 4000, 1000064.0, 1000111.0],
            ("alice", "9.9.9.9", 443, "tcp", "out", 1000120): [2, 200, 1000121.0, 1000130.0],
            ("alice", "8.8.8.8", 53, "udp", "out", 1000060): [1, 60, 1000070.0, 1000070.0],
            ("bob", "9.9.9.9", 443, "tcp", "out", 1000180): [3, 300, 1000185.0, 1000190.0],
        })

    def test_flush_and_upsert_merges(self):
        key = ("alice", "9.9.9.9", 443, "tcp", "out", 1000060)
        self.db.flush_aggregates({key: [5, 500, 1000063.0, 1000110.0]})
        self.db.flush_aggregates({key: [2, 100, 1000061.0, 1000115.0]})
        rows = self.db.client_timeline("alice")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["packets"], 7)
        self.assertEqual(rows[0]["bytes"], 600)
        self.assertEqual(rows[0]["first_ts"], 1000061.0)
        self.assertEqual(rows[0]["last_ts"], 1000115.0)

    def test_client_overview(self):
        self._seed()
        rows = self.db.client_overview("alice")
        by_ip = {r["remote_ip"]: r for r in rows}
        self.assertEqual(set(by_ip), {"9.9.9.9", "8.8.8.8"})
        nine = by_ip["9.9.9.9"]
        self.assertEqual(nine["packets_out"], 7)
        self.assertEqual(nine["packets_in"], 4)
        self.assertEqual(nine["bytes"], 4700)
        self.assertEqual(nine["first_seen"], 1000063.0)
        self.assertEqual(nine["last_seen"], 1000130.0)

    def test_client_overview_time_filter(self):
        self._seed()
        rows = self.db.client_overview("alice", since=1000120)
        self.assertEqual([r["remote_ip"] for r in rows], ["9.9.9.9"])
        rows = self.db.client_overview("alice", until=1000065)
        self.assertEqual([r["remote_ip"] for r in rows], ["9.9.9.9"])
        rows = self.db.client_overview("alice", until=1000075)
        self.assertEqual({r["remote_ip"] for r in rows}, {"9.9.9.9", "8.8.8.8"})

    def test_ip_overview_maps_back_to_clients(self):
        self._seed()
        rows = self.db.ip_overview("9.9.9.9")
        names = {r["common_name"]: r for r in rows}
        self.assertEqual(set(names), {"alice", "bob"})
        self.assertEqual(names["bob"]["packets_out"], 3)
        self.assertEqual(names["alice"]["packets_out"], 7)

    def test_ip_timeline_filters_by_client(self):
        self._seed()
        rows = self.db.ip_timeline("9.9.9.9", client="bob")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["common_name"], "bob")
        self.assertEqual(rows[0]["bucket"], 1000180)

    def test_list_clients(self):
        self._seed()
        rows = self.db.list_clients()
        by_name = {r["common_name"]: r for r in rows}
        self.assertEqual(by_name["alice"]["remote_ips"], 2)
        self.assertEqual(by_name["alice"]["packets"], 12)
        self.assertEqual(by_name["bob"]["remote_ips"], 1)

    def test_sessions_upsert(self):
        s = ClientSession(
            common_name="alice", real_address="203.0.113.10:52345",
            virtual_address="10.8.0.6", bytes_received=100, bytes_sent=200,
            connected_since="Thu Jul 24 04:23:05 2026",
        )
        self.db.record_sessions([s], now=1000.0)
        s.bytes_received = 999
        self.db.record_sessions([s], now=2000.0)
        rows = self.db.list_sessions()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["bytes_received"], 999)
        self.assertEqual(rows[0]["last_seen"], 2000.0)

    def test_summary(self):
        self._seed()
        row = self.db.summary()
        self.assertEqual(row["clients"], 2)
        self.assertEqual(row["remote_ips"], 2)
        self.assertEqual(row["packets"], 15)


if __name__ == "__main__":
    unittest.main()
