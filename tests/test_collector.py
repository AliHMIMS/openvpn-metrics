import io
import os
import tempfile
import unittest

from ovpn_metrics.capture import StdinCapture
from ovpn_metrics.collector import Collector, StatusWatcher, run_collect
from ovpn_metrics.db import Database

STATUS = """\
OpenVPN CLIENT LIST
Updated,Thu Jul 24 04:23:14 2026
Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since
alice,203.0.113.10:52345,3871,3924,Thu Jul 24 04:23:05 2026
bob,198.51.100.7:41000,120000,98000,Thu Jul 24 03:00:00 2026
ROUTING TABLE
Virtual Address,Common Name,Real Address,Last Ref
10.8.0.6,alice,203.0.113.10:52345,Thu Jul 24 04:23:14 2026
10.8.0.10,bob,198.51.100.7:41000,Thu Jul 24 04:23:10 2026
GLOBAL STATS
END
"""

DUMP = """\
listening on tun0, link-type RAW (Raw IP), snapshot length 96 bytes
1721822400.10 IP 10.8.0.6.51234 > 142.250.185.78.443: tcp 517
1721822400.20 IP 142.250.185.78.443 > 10.8.0.6.51234: tcp 1400
1721822405.30 IP 10.8.0.6.51234 > 142.250.185.78.443: tcp 100
1721822460.40 IP 10.8.0.10.40000 > 142.250.185.78.443: tcp 200
1721822460.50 IP 10.8.0.10.5353 > 8.8.8.8.53: UDP, length 48
1721822460.60 IP 10.8.0.99.1000 > 4.4.4.4.80: tcp 10
1721822460.70 IP 172.16.0.1.1000 > 4.4.4.4.80: tcp 10
"""


class CollectorEndToEndTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmp.name, "m.db")
        self.status_path = os.path.join(self.tmp.name, "status.log")
        with open(self.status_path, "w") as fh:
            fh.write(STATUS)

    def tearDown(self):
        self.tmp.cleanup()

    def _run(self, **kwargs):
        capture = StdinCapture(io.StringIO(DUMP))
        run_collect(
            db_path=self.db_path,
            status_path=self.status_path,
            capture=capture,
            bucket_seconds=60,
            status_interval=3600,
            **kwargs,
        )
        return Database(self.db_path)

    def test_client_traffic_attributed(self):
        db = self._run()
        rows = db.client_overview("alice")
        self.assertEqual(len(rows), 1)
        r = rows[0]
        self.assertEqual(r["remote_ip"], "142.250.185.78")
        self.assertEqual(r["packets_out"], 2)
        self.assertEqual(r["packets_in"], 1)
        self.assertEqual(r["bytes"], 517 + 1400 + 100)

    def test_ip_view_shows_both_clients(self):
        db = self._run()
        rows = db.ip_overview("142.250.185.78")
        self.assertEqual({r["common_name"] for r in rows}, {"alice", "bob"})

    def test_unmapped_dropped_by_default(self):
        db = self._run()
        rows = db.ip_overview("4.4.4.4")
        self.assertEqual(rows, [])

    def test_keep_unmapped_with_subnet(self):
        db = self._run(vpn_subnets=["10.8.0.0/24"], keep_unmapped=True)
        rows = db.ip_overview("4.4.4.4")
        self.assertEqual([r["common_name"] for r in rows], ["unmapped:10.8.0.99"])
        # 172.16.0.1 is outside the VPN subnet and stays dropped
        names = {r["common_name"] for r in db.list_clients()}
        self.assertNotIn("unmapped:172.16.0.1", names)

    def test_sessions_recorded_from_status(self):
        db = self._run()
        rows = db.list_sessions()
        self.assertEqual({r["common_name"] for r in rows}, {"alice", "bob"})

    def test_bucketing(self):
        db = self._run()
        rows = db.client_timeline("alice", remote_ip="142.250.185.78")
        buckets = {r["bucket"] for r in rows}
        self.assertEqual(buckets, {1721822400})
        out = [r for r in rows if r["direction"] == "out"][0]
        self.assertEqual(out["packets"], 2)
        self.assertEqual(out["first_ts"], 1721822400.10)
        self.assertEqual(out["last_ts"], 1721822405.30)


class ClassifyTests(unittest.TestCase):
    def test_classify_prefers_source(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        db = Database(os.path.join(tmp.name, "m.db"))
        self.addCleanup(db.close)
        status_path = os.path.join(tmp.name, "status.log")
        with open(status_path, "w") as fh:
            fh.write(STATUS)
        watcher = StatusWatcher(status_path, db)
        watcher.refresh()
        collector = Collector(db, watcher)

        from ovpn_metrics.capture import parse_line
        pkt = parse_line("1.0 IP 10.8.0.6.1000 > 9.9.9.9.443: tcp 10")
        self.assertEqual(collector.classify(pkt),
                         ("alice", "9.9.9.9", 443, "out"))
        pkt = parse_line("1.0 IP 9.9.9.9.443 > 10.8.0.6.1000: tcp 10")
        self.assertEqual(collector.classify(pkt),
                         ("alice", "9.9.9.9", 443, "in"))
        pkt = parse_line("1.0 IP 1.1.1.1.1 > 2.2.2.2.2: tcp 10")
        self.assertIsNone(collector.classify(pkt))


if __name__ == "__main__":
    unittest.main()
