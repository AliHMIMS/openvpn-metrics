import io
import os
import tempfile
import unittest

from ovpn_metrics.capture import StdinCapture
from ovpn_metrics.collector import run_collect
from ovpn_metrics.db import Database
from ovpn_metrics.dns import parse_dns_line, queries_from_lines

STATUS = """\
OpenVPN CLIENT LIST
Updated,Thu Jul 24 04:23:14 2026
Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since
alice,203.0.113.10:52345,1,1,Thu Jul 24 04:23:05 2026
bob,198.51.100.7:41000,1,1,Thu Jul 24 03:00:00 2026
ROUTING TABLE
Virtual Address,Common Name,Real Address,Last Ref
10.8.0.6,alice,203.0.113.10:52345,Thu Jul 24 04:23:14 2026
10.8.0.10,bob,198.51.100.7:41000,Thu Jul 24 04:23:10 2026
GLOBAL STATS
END
"""

DNS_DUMP = """\
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
1753300000.10 IP 10.8.0.6.34567 > 8.8.8.8.53: 45678+ A? www.google.com. (32)
1753300000.20 IP 10.8.0.6.34568 > 8.8.8.8.53: 12+ AAAA? www.google.com. (32)
1753300000.30 IP 8.8.8.8.53 > 10.8.0.6.34567: 45678 1/0/0 A 142.250.185.68 (48)
1753300005.40 IP 10.8.0.10.40001 > 1.1.1.1.53: 9+ [1au] HTTPS? api.x.com. (40)
1753300006.50 IP 10.8.0.6.34569 > 8.8.8.8.53: 77+ A? www.google.com. (32)
1753300007.60 IP 10.8.0.99.5000 > 8.8.8.8.53: 5+ A? unmapped.example. (30)
"""


class ParseDnsLineTests(unittest.TestCase):
    def test_a_query(self):
        q = parse_dns_line(
            "1753300000.10 IP 10.8.0.6.34567 > 8.8.8.8.53: 45678+ A? www.google.com. (32)")
        self.assertEqual(q.client_ip, "10.8.0.6")
        self.assertEqual(q.server_ip, "8.8.8.8")
        self.assertEqual(q.qname, "www.google.com")
        self.assertEqual(q.qtype, "A")

    def test_edns_and_https_type(self):
        q = parse_dns_line(
            "1753300005.40 IP 10.8.0.10.40001 > 1.1.1.1.53: 9+ [1au] HTTPS? api.x.com. (40)")
        self.assertEqual(q.qname, "api.x.com")
        self.assertEqual(q.qtype, "HTTPS")

    def test_response_ignored(self):
        self.assertIsNone(parse_dns_line(
            "1753300000.30 IP 8.8.8.8.53 > 10.8.0.6.34567: 45678 1/0/0 A 142.250.185.68 (48)"))

    def test_non_dns_ignored(self):
        self.assertIsNone(parse_dns_line(
            "1753300000.10 IP 10.8.0.6.51234 > 1.2.3.4.443: tcp 517"))
        self.assertIsNone(parse_dns_line("listening on tun0"))

    def test_ipv6_query(self):
        q = parse_dns_line(
            "1.0 IP6 fd00::6.34567 > 2001:4860:4860::8888.53: 5+ A? x.com. (23)")
        self.assertEqual(q.client_ip, "fd00::6")
        self.assertEqual(q.qname, "x.com")

    def test_case_normalized(self):
        q = parse_dns_line(
            "1.0 IP 10.8.0.6.1 > 8.8.8.8.53: 1+ A? WWW.Example.COM. (20)")
        self.assertEqual(q.qname, "www.example.com")

    def test_queries_from_lines_filters(self):
        qs = list(queries_from_lines(io.StringIO(DNS_DUMP)))
        # 5 queries (2 google, 1 https, 1 more google, 1 unmapped); response skipped
        self.assertEqual(len(qs), 5)


class DnsCollectorEndToEndTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db_path = os.path.join(self.tmp.name, "m.db")
        self.status_path = os.path.join(self.tmp.name, "status.log")
        with open(self.status_path, "w") as fh:
            fh.write(STATUS)

    def _run(self):
        run_collect(
            db_path=self.db_path,
            status_path=self.status_path,
            capture=StdinCapture(io.StringIO("")),  # no traffic
            status_interval=3600,
            dns_capture=StdinCapture(io.StringIO(DNS_DUMP)),
        )
        db = Database(self.db_path)
        self.addCleanup(db.close)
        return db

    def test_domains_aggregated_per_client(self):
        db = self._run()
        rows = db.dns_domains(client="alice")
        by = {r["qname"]: r for r in rows}
        # alice queried google 3x (A, AAAA, A) across one bucket
        self.assertEqual(by["www.google.com"]["queries"], 3)

    def test_domain_clients(self):
        db = self._run()
        rows = db.dns_domain_clients("www.google.com")
        self.assertEqual([r["common_name"] for r in rows], ["alice"])
        rows = db.dns_domain_clients("api.x.com")
        self.assertEqual([r["common_name"] for r in rows], ["bob"])

    def test_top_domains_across_clients(self):
        db = self._run()
        rows = db.dns_domains()
        names = {r["qname"] for r in rows}
        self.assertIn("www.google.com", names)
        self.assertIn("api.x.com", names)
        # unmapped client's query is dropped (not in status routes)
        self.assertNotIn("unmapped.example", names)

    def test_contains_filter(self):
        db = self._run()
        rows = db.dns_domains(contains="google")
        self.assertEqual([r["qname"] for r in rows], ["www.google.com"])

    def test_prune_covers_dns(self):
        db = self._run()
        counts = db.prune(cutoff_ts=9_999_999_999)  # far future: delete all
        self.assertGreater(counts["dns"], 0)
        self.assertEqual(db.dns_domains(), [])


if __name__ == "__main__":
    unittest.main()
