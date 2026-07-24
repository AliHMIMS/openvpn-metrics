"""Attach to tcpdump and parse its output into packet records.

The collector does not link against libpcap. Instead it spawns tcpdump on
the OpenVPN tunnel interface (tun0 by default) with flags that produce a
stable, line-oriented output:

    tcpdump -i tun0 -tt -l -n -q

  -tt  epoch timestamps
  -l   line-buffered stdout
  -n   no name resolution
  -q   quiet/terse per-packet lines

Example lines this module understands:

    1721822400.123456 IP 10.8.0.6.51234 > 142.250.185.78.443: tcp 517
    1721822400.223456 IP 10.8.0.6.5353 > 8.8.8.8.53: UDP, length 48
    1721822401.323456 IP 10.8.0.6 > 1.1.1.1: ICMP echo request, id 1, seq 9, length 64
    1721822402.423456 IP6 fd00::6.51234 > 2607:f8b0::200e.443: tcp 100
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from typing import IO, Iterator, List, Optional

_LINE_RE = re.compile(
    r"^(?P<ts>\d+(?:\.\d+)?)\s+(?P<fam>IP6|IP)\s+"
    r"(?P<src>\S+)\s+>\s+(?P<dst>\S+):\s*(?P<rest>.*)$"
)
_LENGTH_RE = re.compile(r"length[ :]+(\d+)")


@dataclass
class Packet:
    ts: float
    src_ip: str
    src_port: int  # 0 when the protocol has no port (e.g. ICMP)
    dst_ip: str
    dst_port: int
    proto: str  # "tcp", "udp", "icmp", ...
    length: int  # payload length when tcpdump reports one, else 0


def _split_host_port(token: str, is_ipv6: bool) -> tuple:
    """Split tcpdump's 'addr.port' notation into (addr, port).

    tcpdump appends the port with a dot: '10.8.0.6.51234' or 'fd00::6.51234'.
    A bare IPv4 address has exactly 3 dots, so a 4th dotted field that is all
    digits is a port. For IPv6 any trailing '.digits' is a port.
    """
    head, sep, tail = token.rpartition(".")
    if sep and tail.isdigit():
        if is_ipv6 or head.count(".") == 3:
            try:
                return head, int(tail)
            except ValueError:
                pass
    return token, 0


def parse_line(line: str) -> Optional[Packet]:
    """Parse one tcpdump output line; return None for non-packet lines."""
    m = _LINE_RE.match(line.strip())
    if not m:
        return None
    is_ipv6 = m.group("fam") == "IP6"
    src_ip, src_port = _split_host_port(m.group("src"), is_ipv6)
    dst_ip, dst_port = _split_host_port(m.group("dst"), is_ipv6)

    rest = m.group("rest")
    first = rest.split(None, 1)[0].rstrip(",").lower() if rest else ""
    if first.startswith("icmp"):
        proto = "icmp"
    elif first in ("tcp", "udp"):
        proto = first
    elif first:
        proto = first
    else:
        proto = "other"

    length = 0
    if proto == "tcp":
        # "-q" prints: "tcp 517"
        parts = rest.split()
        if len(parts) >= 2 and parts[1].isdigit():
            length = int(parts[1])
    else:
        lm = _LENGTH_RE.search(rest)
        if lm:
            length = int(lm.group(1))

    return Packet(
        ts=float(m.group("ts")),
        src_ip=src_ip,
        src_port=src_port,
        dst_ip=dst_ip,
        dst_port=dst_port,
        proto=proto,
        length=length,
    )


def packets_from_lines(lines) -> Iterator[Packet]:
    for line in lines:
        pkt = parse_line(line)
        if pkt is not None:
            yield pkt


class TcpdumpCapture:
    """Spawns tcpdump on an interface and yields parsed packets."""

    def __init__(
        self,
        interface: str,
        tcpdump_path: str = "tcpdump",
        bpf_filter: Optional[List[str]] = None,
        snaplen: int = 96,
    ):
        self.interface = interface
        self.tcpdump_path = tcpdump_path
        self.bpf_filter = bpf_filter or []
        self.snaplen = snaplen
        self.proc: Optional[subprocess.Popen] = None

    def command(self) -> List[str]:
        cmd = [
            self.tcpdump_path,
            "-i", self.interface,
            "-tt", "-l", "-n", "-q",
            "-s", str(self.snaplen),
        ]
        cmd.extend(self.bpf_filter)
        return cmd

    def start(self) -> None:
        if shutil.which(self.tcpdump_path) is None:
            raise RuntimeError(
                f"tcpdump binary not found: {self.tcpdump_path!r}. "
                "Install tcpdump or pass --tcpdump-path."
            )
        self.proc = subprocess.Popen(
            self.command(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )

    def packets(self) -> Iterator[Packet]:
        if self.proc is None:
            self.start()
        assert self.proc is not None and self.proc.stdout is not None
        try:
            yield from packets_from_lines(self.proc.stdout)
        finally:
            self.stop()
        rc = self.proc.returncode
        if rc not in (0, None, -2, -15):  # allow SIGINT/SIGTERM
            err = ""
            if self.proc.stderr is not None:
                err = self.proc.stderr.read().strip()
            raise RuntimeError(f"tcpdump exited with status {rc}: {err}")

    def stop(self) -> None:
        if self.proc is not None and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()


class StdinCapture:
    """Reads tcpdump-formatted lines from a stream (testing / replay)."""

    def __init__(self, stream: Optional[IO[str]] = None):
        self.stream = stream if stream is not None else sys.stdin

    def packets(self) -> Iterator[Packet]:
        yield from packets_from_lines(self.stream)

    def stop(self) -> None:
        pass
