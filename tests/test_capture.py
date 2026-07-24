import unittest

from ovpn_metrics.capture import TcpdumpCapture, parse_line, packets_from_lines


class ParseLineTests(unittest.TestCase):
    def test_tcp_line(self):
        pkt = parse_line(
            "1721822400.123456 IP 10.8.0.6.51234 > 142.250.185.78.443: tcp 517"
        )
        self.assertIsNotNone(pkt)
        self.assertAlmostEqual(pkt.ts, 1721822400.123456)
        self.assertEqual(pkt.src_ip, "10.8.0.6")
        self.assertEqual(pkt.src_port, 51234)
        self.assertEqual(pkt.dst_ip, "142.250.185.78")
        self.assertEqual(pkt.dst_port, 443)
        self.assertEqual(pkt.proto, "tcp")
        self.assertEqual(pkt.length, 517)

    def test_tcp_zero_length(self):
        pkt = parse_line("1721822400.0 IP 10.8.0.6.51234 > 1.2.3.4.80: tcp 0")
        self.assertEqual(pkt.proto, "tcp")
        self.assertEqual(pkt.length, 0)

    def test_udp_line(self):
        pkt = parse_line(
            "1721822400.223456 IP 10.8.0.6.5353 > 8.8.8.8.53: UDP, length 48"
        )
        self.assertEqual(pkt.proto, "udp")
        self.assertEqual(pkt.src_port, 5353)
        self.assertEqual(pkt.dst_port, 53)
        self.assertEqual(pkt.length, 48)

    def test_icmp_line_no_ports(self):
        pkt = parse_line(
            "1721822401.323456 IP 10.8.0.6 > 1.1.1.1: "
            "ICMP echo request, id 1, seq 9, length 64"
        )
        self.assertEqual(pkt.proto, "icmp")
        self.assertEqual(pkt.src_ip, "10.8.0.6")
        self.assertEqual(pkt.src_port, 0)
        self.assertEqual(pkt.dst_ip, "1.1.1.1")
        self.assertEqual(pkt.dst_port, 0)
        self.assertEqual(pkt.length, 64)

    def test_ipv6_line(self):
        pkt = parse_line(
            "1721822402.423456 IP6 fd00::6.51234 > 2607:f8b0::200e.443: tcp 100"
        )
        self.assertEqual(pkt.src_ip, "fd00::6")
        self.assertEqual(pkt.src_port, 51234)
        self.assertEqual(pkt.dst_ip, "2607:f8b0::200e")
        self.assertEqual(pkt.dst_port, 443)

    def test_non_packet_lines_ignored(self):
        for line in (
            "tcpdump: verbose output suppressed, use -v[v]... for full protocol decode",
            "listening on tun0, link-type RAW (Raw IP), snapshot length 96 bytes",
            "",
            "12 packets captured",
        ):
            self.assertIsNone(parse_line(line))

    def test_packets_from_lines_filters_garbage(self):
        lines = [
            "listening on tun0, link-type RAW (Raw IP)",
            "1721822400.1 IP 10.8.0.6.1000 > 9.9.9.9.443: tcp 10",
            "garbage",
            "1721822400.2 IP 9.9.9.9.443 > 10.8.0.6.1000: tcp 20",
        ]
        pkts = list(packets_from_lines(lines))
        self.assertEqual(len(pkts), 2)
        self.assertEqual(pkts[1].src_ip, "9.9.9.9")


class TcpdumpCommandTests(unittest.TestCase):
    def test_command_includes_flags_and_filter(self):
        cap = TcpdumpCapture("tun1", bpf_filter=["not", "port", "53"])
        cmd = cap.command()
        self.assertEqual(cmd[0], "tcpdump")
        self.assertIn("tun1", cmd)
        for flag in ("-tt", "-l", "-n", "-q"):
            self.assertIn(flag, cmd)
        self.assertEqual(cmd[-3:], ["not", "port", "53"])


if __name__ == "__main__":
    unittest.main()
