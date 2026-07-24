import os
import tempfile
import time
import unittest

from ovpn_metrics.db import Database
from ovpn_metrics.status import ClientSession
from ovpn_metrics.util import parse_duration


class ParseDurationTests(unittest.TestCase):
    def test_units(self):
        self.assertEqual(parse_duration("24h"), 24 * 3600)
        self.assertEqual(parse_duration("30m"), 1800)
        self.assertEqual(parse_duration("7d"), 7 * 86400)
        self.assertEqual(parse_duration("2w"), 2 * 604800)
        self.assertEqual(parse_duration("90"), 90.0)

    def test_invalid(self):
        for bad in ("day", "1 hour", "", "-5h"):
            with self.assertRaises(ValueError):
                parse_duration(bad)


class DbPruneTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = Database(os.path.join(self.tmp.name, "m.db"))
        self.addCleanup(self.db.close)

    def test_prune_removes_only_old_data(self):
        old, new = 1000, 5000
        self.db.flush_aggregates({
            ("alice", "9.9.9.9", 443, "tcp", "out", old): [5, 500, float(old), float(old)],
            ("alice", "9.9.9.9", 443, "tcp", "out", new): [2, 200, float(new), float(new)],
            ("bob", "8.8.8.8", 53, "udp", "out", old): [1, 60, float(old), float(old)],
        })
        counts = self.db.prune(cutoff_ts=3000)
        self.assertEqual(counts["traffic"], 2)
        rows = self.db.client_timeline("alice")
        self.assertEqual([r["bucket"] for r in rows], [new])
        # bob had only old data -> all traffic gone and client row dropped
        names = {r["common_name"] for r in self.db.list_clients()}
        self.assertEqual(names, {"alice"})
        self.assertEqual(counts["clients"], 1)

    def test_prune_sessions_and_rdns(self):
        s = ClientSession(common_name="carol", real_address="1.2.3.4:1",
                          connected_since="x")
        self.db.record_sessions([s], now=1000.0)
        self.db.rdns_put({"9.9.9.9": "old.example"}, now=1000.0)
        self.db.rdns_put({"8.8.8.8": "new.example"}, now=5000.0)
        counts = self.db.prune(cutoff_ts=3000)
        self.assertEqual(counts["sessions"], 1)
        self.assertEqual(counts["rdns"], 1)
        self.assertEqual(list(self.db.rdns_get(["8.8.8.8", "9.9.9.9"])),
                         ["8.8.8.8"])

    def test_prune_keeps_current_sessions(self):
        s = ClientSession(common_name="dave", real_address="1.2.3.4:1",
                          connected_since="x")
        self.db.record_sessions([s], now=5000.0)
        counts = self.db.prune(cutoff_ts=3000)
        self.assertEqual(counts["sessions"], 0)
        self.assertEqual(len(self.db.list_sessions()), 1)

    def test_client_ids_usable_after_prune(self):
        key = ("erin", "9.9.9.9", 443, "tcp", "out", 1000)
        self.db.flush_aggregates({key: [1, 10, 1000.0, 1000.0]})
        self.db.prune(cutoff_ts=3000)
        # re-inserting the same client after its row was pruned must work
        self.db.flush_aggregates({
            ("erin", "9.9.9.9", 443, "tcp", "out", 5000): [1, 10, 5000.0, 5000.0]
        })
        rows = self.db.client_overview("erin")
        self.assertEqual(len(rows), 1)


class CollectorRetentionTests(unittest.TestCase):
    def test_collector_prunes_old_buckets(self):
        import io
        from ovpn_metrics.capture import StdinCapture
        from ovpn_metrics.collector import run_collect

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        status_path = os.path.join(tmp.name, "status.log")
        with open(status_path, "w") as fh:
            fh.write(
                "OpenVPN CLIENT LIST\n"
                "Updated,now\n"
                "Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since\n"
                "alice,1.2.3.4:1,1,1,now\n"
                "ROUTING TABLE\n"
                "Virtual Address,Common Name,Real Address,Last Ref\n"
                "10.8.0.6,alice,1.2.3.4:1,now\n"
                "GLOBAL STATS\nEND\n"
            )
        now = time.time()
        db_path = os.path.join(tmp.name, "m.db")

        # seed data from "a previous run", 2h old — outside a 1h retention
        old_bucket = int(now - 7200)
        seed = Database(db_path)
        seed.flush_aggregates({
            ("alice", "9.9.9.9", 443, "tcp", "out", old_bucket):
                [5, 500, now - 7200, now - 7200],
        })
        seed.close()

        new_ts = now - 60
        dump = f"{new_ts:.2f} IP 10.8.0.6.1000 > 8.8.8.8.443: tcp 20\n"
        run_collect(
            db_path=db_path,
            status_path=status_path,
            capture=StdinCapture(io.StringIO(dump)),
            status_interval=3600,
            retention_seconds=3600,  # keep 1h; prune fires on first packet
        )
        db = Database(db_path)
        self.addCleanup(db.close)
        ips = {r["remote_ip"] for r in db.client_overview("alice")}
        self.assertEqual(ips, {"8.8.8.8"})  # old bucket pruned, new kept


if __name__ == "__main__":
    unittest.main()
