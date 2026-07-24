"""Parse the OpenVPN status file (versions 1, 2 and 3).

The status file is what lets us translate a VPN-internal ("virtual") IP seen
on the tun interface into the client's certificate common name. Enable it in
the server config, e.g.:

    status /var/log/openvpn/status.log 10
    # optionally: status-version 2

Version 1 (default) is sectioned CSV:

    OpenVPN CLIENT LIST
    Updated,Thu Jun 18 04:23:14 2015
    Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since
    alice,203.0.113.10:52345,3871,3924,Thu Jun 18 04:23:05 2015
    ROUTING TABLE
    Virtual Address,Common Name,Real Address,Last Ref
    10.8.0.6,alice,203.0.113.10:52345,Thu Jun 18 04:23:14 2015
    GLOBAL STATS
    ...

Versions 2/3 use prefixed rows (comma vs tab separated):

    HEADER,CLIENT_LIST,Common Name,Real Address,Virtual Address,...
    CLIENT_LIST,alice,203.0.113.10:52345,10.8.0.6,,3871,3924,...
    HEADER,ROUTING_TABLE,Virtual Address,Common Name,...
    ROUTING_TABLE,10.8.0.6,alice,203.0.113.10:52345,...
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class ClientSession:
    common_name: str
    real_address: str = ""
    virtual_address: str = ""
    bytes_received: int = 0
    bytes_sent: int = 0
    connected_since: str = ""


@dataclass
class StatusSnapshot:
    # virtual address -> common name
    routes: Dict[str, str] = field(default_factory=dict)
    clients: List[ClientSession] = field(default_factory=list)


def _to_int(value: str) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _strip_route_suffix(virtual_address: str) -> str:
    # iroute entries can look like "192.168.100.0/24"; client-to-client
    # MAC routes look like "aa:bb:..." — keep them as-is, but strip
    # nothing from plain IPs.
    return virtual_address.strip()


def _parse_v23(lines: List[str]) -> StatusSnapshot:
    snap = StatusSnapshot()
    headers: Dict[str, List[str]] = {}
    for raw in lines:
        line = raw.rstrip("\n")
        if not line:
            continue
        sep = "\t" if "\t" in line else ","
        parts = line.split(sep)
        tag = parts[0]
        if tag == "HEADER" and len(parts) >= 2:
            headers[parts[1]] = parts[2:]
        elif tag == "CLIENT_LIST":
            cols = headers.get(
                "CLIENT_LIST",
                [
                    "Common Name", "Real Address", "Virtual Address",
                    "Virtual IPv6 Address", "Bytes Received", "Bytes Sent",
                    "Connected Since", "Connected Since (time_t)",
                    "Username", "Client ID", "Peer ID",
                ],
            )
            row = dict(zip(cols, parts[1:]))
            session = ClientSession(
                common_name=row.get("Common Name", ""),
                real_address=row.get("Real Address", ""),
                virtual_address=row.get("Virtual Address", ""),
                bytes_received=_to_int(row.get("Bytes Received", "0")),
                bytes_sent=_to_int(row.get("Bytes Sent", "0")),
                connected_since=row.get("Connected Since", ""),
            )
            if session.common_name:
                snap.clients.append(session)
                if session.virtual_address:
                    snap.routes[session.virtual_address] = session.common_name
                v6 = row.get("Virtual IPv6 Address", "")
                if v6:
                    snap.routes[v6] = session.common_name
        elif tag == "ROUTING_TABLE" and len(parts) >= 3:
            cols = headers.get(
                "ROUTING_TABLE",
                ["Virtual Address", "Common Name", "Real Address",
                 "Last Ref", "Last Ref (time_t)"],
            )
            row = dict(zip(cols, parts[1:]))
            vaddr = _strip_route_suffix(row.get("Virtual Address", ""))
            cname = row.get("Common Name", "")
            if vaddr and cname:
                snap.routes[vaddr] = cname
    return snap


def _parse_v1(lines: List[str]) -> StatusSnapshot:
    snap = StatusSnapshot()
    section = ""
    expect_header = False
    for raw in lines:
        line = raw.rstrip("\n").strip()
        if not line:
            continue
        if line == "OpenVPN CLIENT LIST":
            section = "clients"
            expect_header = False
            continue
        if line == "ROUTING TABLE":
            section = "routes"
            expect_header = True
            continue
        if line == "GLOBAL STATS":
            section = ""
            continue
        if line.startswith("Updated,"):
            # after the Updated line comes the client list column header
            expect_header = True
            continue
        if expect_header:
            expect_header = False
            continue  # skip the CSV column header row
        if section == "clients":
            parts = line.split(",")
            if len(parts) >= 5:
                snap.clients.append(
                    ClientSession(
                        common_name=parts[0],
                        real_address=parts[1],
                        bytes_received=_to_int(parts[2]),
                        bytes_sent=_to_int(parts[3]),
                        connected_since=parts[4],
                    )
                )
        elif section == "routes":
            parts = line.split(",")
            if len(parts) >= 4:
                vaddr = _strip_route_suffix(parts[0])
                cname = parts[1]
                if vaddr and cname:
                    snap.routes[vaddr] = cname
    # backfill virtual addresses onto sessions where the routing table has them
    by_name = {c.common_name: c for c in snap.clients}
    for vaddr, cname in snap.routes.items():
        client = by_name.get(cname)
        if client is not None and not client.virtual_address and "/" not in vaddr:
            client.virtual_address = vaddr
    return snap


def parse_status(text: str) -> StatusSnapshot:
    """Parse status file content, auto-detecting version 1/2/3."""
    lines = text.splitlines()
    for line in lines:
        first = line.split(",", 1)[0].split("\t", 1)[0]
        if first in ("TITLE", "HEADER", "CLIENT_LIST", "ROUTING_TABLE"):
            return _parse_v23(lines)
    return _parse_v1(lines)


def read_status_file(path: str) -> Optional[StatusSnapshot]:
    """Read and parse a status file; returns None if unreadable."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return parse_status(fh.read())
    except OSError:
        return None
