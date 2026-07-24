import os
import tempfile
import unittest

from ovpn_metrics.db import Database
from ovpn_metrics.resolve import Resolver


class CountingLookup:
    def __init__(self, table):
        self.table = table
        self.calls = []

    def __call__(self, ip):
        self.calls.append(ip)
        return self.table.get(ip, "")


class ResolverTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Database(os.path.join(self.tmp.name, "test.db"))
        self.lookup = CountingLookup({
            "8.8.8.8": "dns.google",
            "142.250.185.78": "fra16s24-in-f14.1e100.net",
        })
        self.resolver = Resolver(self.db, lookup=self.lookup)

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def test_resolves_and_reports_failures(self):
        names = self.resolver.resolve(["8.8.8.8", "203.0.113.99"])
        self.assertEqual(names["8.8.8.8"], "dns.google")
        self.assertEqual(names["203.0.113.99"], "")

    def test_cache_prevents_repeat_lookups(self):
        self.resolver.resolve(["8.8.8.8"])
        self.resolver.resolve(["8.8.8.8"])
        self.assertEqual(self.lookup.calls, ["8.8.8.8"])
        # failures are cached too (negative cache)
        self.resolver.resolve(["203.0.113.99"])
        self.resolver.resolve(["203.0.113.99"])
        self.assertEqual(self.lookup.calls.count("203.0.113.99"), 1)

    def test_cache_shared_across_resolver_instances(self):
        self.resolver.resolve(["8.8.8.8"])
        second = Resolver(self.db, lookup=self.lookup)
        names = second.resolve(["8.8.8.8"])
        self.assertEqual(names["8.8.8.8"], "dns.google")
        self.assertEqual(self.lookup.calls, ["8.8.8.8"])

    def test_expired_entries_are_refreshed(self):
        self.resolver.resolve(["8.8.8.8"])
        # backdate the cache entry beyond the TTL
        self.db.conn.execute("UPDATE rdns SET resolved_at = resolved_at - ?",
                             (self.resolver.ttl + 10,))
        self.db.conn.commit()
        self.resolver.resolve(["8.8.8.8"])
        self.assertEqual(self.lookup.calls, ["8.8.8.8", "8.8.8.8"])

    def test_failure_ttl_shorter_than_success_ttl(self):
        self.resolver.resolve(["203.0.113.99"])
        # backdate past the failure TTL but not the success TTL
        self.db.conn.execute("UPDATE rdns SET resolved_at = resolved_at - ?",
                             (self.resolver.failure_ttl + 10,))
        self.db.conn.commit()
        self.resolver.resolve(["203.0.113.99"])
        self.assertEqual(self.lookup.calls.count("203.0.113.99"), 2)

    def test_deduplicates_and_skips_empty(self):
        names = self.resolver.resolve(["8.8.8.8", "8.8.8.8", ""])
        self.assertEqual(self.lookup.calls, ["8.8.8.8"])
        self.assertEqual(names, {"8.8.8.8": "dns.google"})

    def test_budget_exhaustion_returns_partial(self):
        import time as _time

        def slow_lookup(ip):
            _time.sleep(5)
            return "never.example"

        resolver = Resolver(self.db, lookup=slow_lookup, budget=0.1,
                            max_workers=1)
        names = resolver.resolve(["198.51.100.1"])
        # not resolved within budget: reported unknown, not cached
        self.assertEqual(names["198.51.100.1"], "")
        self.assertEqual(self.db.rdns_get(["198.51.100.1"]), {})


if __name__ == "__main__":
    unittest.main()
