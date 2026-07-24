"""Parse DNS query lines from tcpdump and collect them per client.

A second tcpdump runs alongside the traffic capture, filtered to port 53 and
*without* ``-q`` so tcpdump decodes the DNS payload. Query lines look like:

    1721822400.12 IP 10.8.0.6.34567 > 8.8.8.8.53: 45678+ A? www.google.com. (32)
    1721822400.20 IP 10.8.0.6.40001 > 8.8.8.8.53: 12+ AAAA? example.org. (29)
    1721822400.30 IP 10.8.0.6.5300 > 1.1.1.1.53: 9+ [1au] HTTPS? api.x.com. (40)

We record the query name (the hostname the client is about to visit),
attributed to the client that sent it. Responses (no ``?``) are ignored.

Only queries that traverse the tunnel are visible: this catches clients that
use a DNS resolver reachable over the VPN. It does not see DNS-over-HTTPS/TLS
(that looks like ordinary HTTPS) or answers served from the client's cache.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterator, Optional

# Reuse the address prefix: "<ts> IP[6] <src> > <dst>: <rest>"
_PREFIX_RE = re.compile(
    r"^(?P<ts>\d+(?:\.\d+)?)\s+(?P<fam>IP6|IP)\s+"
    r"(?P<src>\S+)\s+>\s+(?P<dst>\S+):\s*(?P<rest>.*)$"
)
# A DNS question: "<TYPE>? <name>." somewhere in the decoded body.
_QUESTION_RE = re.compile(r"\b(?P<qtype>[A-Z][A-Z0-9]*)\?\s+(?P<qname>[^\s()]+)")


@dataclass
class DnsQuery:
    ts: float
    client_ip: str
    server_ip: str
    qname: str
    qtype: str


def _split_host_port(token: str, is_ipv6: bool):
    head, sep, tail = token.rpartition(".")
    if sep and tail.isdigit() and (is_ipv6 or head.count(".") == 3):
        return head, int(tail)
    return token, 0


def parse_dns_line(line: str) -> Optional[DnsQuery]:
    """Parse one tcpdump line; return a DnsQuery only for outbound queries."""
    m = _PREFIX_RE.match(line.strip())
    if not m:
        return None
    is_ipv6 = m.group("fam") == "IP6"
    dst_ip, dst_port = _split_host_port(m.group("dst"), is_ipv6)
    if dst_port != 53:  # only queries (client -> resolver); skip responses
        return None
    q = _QUESTION_RE.search(m.group("rest"))
    if not q:
        return None
    qname = q.group("qname").rstrip(".").lower()
    if not qname:
        return None
    src_ip, _ = _split_host_port(m.group("src"), is_ipv6)
    return DnsQuery(
        ts=float(m.group("ts")),
        client_ip=src_ip,
        server_ip=dst_ip,
        qname=qname,
        qtype=q.group("qtype"),
    )


def queries_from_lines(lines) -> Iterator[DnsQuery]:
    for line in lines:
        q = parse_dns_line(line)
        if q is not None:
            yield q
