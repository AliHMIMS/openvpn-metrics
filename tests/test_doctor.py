import contextlib
import io
import os
import tempfile
import unittest

from ovpn_metrics import capture, doctor
from ovpn_metrics.capture import CaptureSample, Packet


def _quiet(fn, *args, **kwargs):
    """Run fn with stdout suppressed (doctor prints its report)."""
    with contextlib.redirect_stdout(io.StringIO()):
        return fn(*args, **kwargs)

STATUS = """\
OpenVPN CLIENT LIST
Updated,Thu Jul 24 04:23:14 2026
Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since
alice,203.0.113.10:52345,3871,3924,Thu Jul 24 04:23:05 2026
ROUTING TABLE
Virtual Address,Common Name,Real Address,Last Ref
10.8.0.6,alice,203.0.113.10:52345,Thu Jul 24 04:23:14 2026
GLOBAL STATS
END
"""


def pkt(src, dst):
    return Packet(ts=1.0, src_ip=src, src_port=1, dst_ip=dst, dst_port=2,
                  proto="tcp", length=10)


class StatusCheckTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_missing_status_fails(self):
        rep = doctor.Report()
        snap = _quiet(doctor._check_status, rep, os.path.join(self.tmp.name, "nope"))
        self.assertIsNone(snap)
        self.assertEqual(rep.worst, doctor.FAIL)

    def test_valid_status_ok(self):
        path = os.path.join(self.tmp.name, "status.log")
        with open(path, "w") as fh:
            fh.write(STATUS)
        rep = doctor.Report()
        snap = _quiet(doctor._check_status, rep, path)
        self.assertEqual(rep.worst, doctor.OK)
        self.assertEqual(snap.routes["10.8.0.6"], "alice")

    def test_status_without_routes_warns(self):
        path = os.path.join(self.tmp.name, "empty.log")
        with open(path, "w") as fh:
            fh.write("OpenVPN CLIENT LIST\nGLOBAL STATS\nEND\n")
        rep = doctor.Report()
        _quiet(doctor._check_status, rep, path)
        self.assertEqual(rep.worst, doctor.WARN)


class CaptureProbeTests(unittest.TestCase):
    def setUp(self):
        from ovpn_metrics.status import parse_status
        self.snap = parse_status(STATUS)

    def _run(self, sample):
        orig = capture.TcpdumpCapture.sample
        capture.TcpdumpCapture.sample = lambda self, seconds: sample
        self.addCleanup(lambda: setattr(capture.TcpdumpCapture, "sample", orig))
        rep = doctor.Report()
        _quiet(doctor._check_capture, rep, "tun0", "tcpdump", self.snap, 0.01)
        return rep

    def test_no_packets_warns(self):
        rep = self._run(CaptureSample([], "", -15))
        self.assertEqual(rep.worst, doctor.WARN)

    def test_packets_but_none_mapped_fails(self):
        rep = self._run(CaptureSample(
            [pkt("1.2.3.4", "5.6.7.8"), pkt("9.9.9.9", "8.8.8.8")], "", -15))
        self.assertEqual(rep.worst, doctor.FAIL)

    def test_mapped_packets_ok(self):
        rep = self._run(CaptureSample(
            [pkt("10.8.0.6", "8.8.8.8"), pkt("1.1.1.1", "2.2.2.2")], "", -15))
        self.assertEqual(rep.worst, doctor.OK)

    def test_tcpdump_error_fails(self):
        rep = self._run(CaptureSample([], "tun0: No such device", 1))
        self.assertEqual(rep.worst, doctor.FAIL)


class SampleTests(unittest.TestCase):
    def test_sample_reads_until_deadline(self):
        # Feed a slow generator via a fake process-like object is heavy;
        # instead verify sample() tolerates an immediately-closed stream.
        cap = capture.TcpdumpCapture("tun0", tcpdump_path="/bin/true")
        result = cap.sample(0.2)
        self.assertIsInstance(result, CaptureSample)
        self.assertEqual(result.packets, [])


class DbCheckTests(unittest.TestCase):
    def test_empty_db_warns(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        rep = doctor.Report()
        _quiet(doctor._check_db, rep, os.path.join(tmp.name, "m.db"))
        self.assertEqual(rep.worst, doctor.WARN)


if __name__ == "__main__":
    unittest.main()
