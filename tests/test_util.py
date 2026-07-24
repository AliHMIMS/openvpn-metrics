import unittest

from ovpn_metrics.util import format_bytes, parse_when


class ParseWhenTests(unittest.TestCase):
    def test_relative(self):
        now = 1_000_000.0
        self.assertEqual(parse_when("30m", now=now), now - 1800)
        self.assertEqual(parse_when("4h", now=now), now - 4 * 3600)
        self.assertEqual(parse_when("7d", now=now), now - 7 * 86400)
        self.assertEqual(parse_when("2w", now=now), now - 2 * 604800)
        self.assertEqual(parse_when("90s", now=now), now - 90)

    def test_absolute_date(self):
        import datetime
        ts = parse_when("2026-07-24")
        dt = datetime.datetime.fromtimestamp(ts)
        self.assertEqual((dt.year, dt.month, dt.day, dt.hour), (2026, 7, 24, 0))

    def test_absolute_datetime(self):
        import datetime
        ts = parse_when("2026-07-24 13:45")
        dt = datetime.datetime.fromtimestamp(ts)
        self.assertEqual((dt.hour, dt.minute), (13, 45))

    def test_invalid(self):
        with self.assertRaises(ValueError):
            parse_when("yesterday-ish")


class FormatBytesTests(unittest.TestCase):
    def test_units(self):
        self.assertEqual(format_bytes(0), "0 B")
        self.assertEqual(format_bytes(1023), "1023 B")
        self.assertEqual(format_bytes(1536), "1.5 KiB")
        self.assertEqual(format_bytes(5 * 1024 * 1024), "5.0 MiB")


if __name__ == "__main__":
    unittest.main()
