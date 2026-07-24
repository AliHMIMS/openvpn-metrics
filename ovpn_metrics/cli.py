"""openvpn-metrics command line interface."""

from __future__ import annotations

import argparse
import logging
import sys
from typing import Optional

from . import __version__
from .capture import StdinCapture, TcpdumpCapture
from .collector import run_collect
from .db import Database
from .resolve import Resolver
from .util import (format_bytes, format_ts, parse_duration, parse_when,
                   print_json, print_table)

DEFAULT_DB = "/var/lib/openvpn-metrics/metrics.db"
DEFAULT_STATUS = "/var/log/openvpn/status.log"
DEFAULT_INTERFACE = "tun0"


def _add_db_arg(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--db", default=DEFAULT_DB,
        help=f"path to the metrics SQLite database (default: {DEFAULT_DB})",
    )


def _add_query_args(p: argparse.ArgumentParser) -> None:
    _add_db_arg(p)
    p.add_argument(
        "--since", metavar="WHEN",
        help="only include traffic after WHEN ('30m', '4h', '7d', "
             "'2026-07-24', '2026-07-24 13:00')",
    )
    p.add_argument("--until", metavar="WHEN",
                   help="only include traffic before WHEN (same formats)")
    p.add_argument("--json", action="store_true",
                   help="output JSON instead of a table")
    p.add_argument("--limit", type=int, default=0,
                   help="limit number of rows (0 = no limit)")
    p.add_argument("--no-resolve", action="store_true",
                   help="skip reverse-DNS lookups on remote IPs")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="openvpn-metrics",
        description="Collect and query per-client OpenVPN traffic metrics "
                    "by attaching to tcpdump on the tunnel interface.",
    )
    parser.add_argument("--version", action="version",
                        version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    # collect
    p = sub.add_parser(
        "collect",
        help="attach to tcpdump on the tun interface and record traffic",
        description="Runs the collector daemon: spawns tcpdump on the OpenVPN "
                    "tunnel interface, maps VPN-internal IPs to client common "
                    "names via the status file, and aggregates traffic into "
                    "the metrics database. Run as root (or grant tcpdump "
                    "CAP_NET_RAW).",
    )
    _add_db_arg(p)
    p.add_argument("-i", "--interface", default=DEFAULT_INTERFACE,
                   help=f"tunnel interface to capture on (default: {DEFAULT_INTERFACE})")
    p.add_argument("-s", "--status-file", default=DEFAULT_STATUS,
                   help=f"OpenVPN status file path (default: {DEFAULT_STATUS})")
    p.add_argument("--status-interval", type=float, default=10.0,
                   help="seconds between status file polls (default: 10)")
    p.add_argument("--bucket-seconds", type=int, default=60,
                   help="aggregation bucket size in seconds (default: 60)")
    p.add_argument("--flush-interval", type=float, default=5.0,
                   help="seconds between database flushes (default: 5)")
    p.add_argument("--tcpdump-path", default="tcpdump",
                   help="tcpdump binary to use (default: tcpdump from PATH)")
    p.add_argument("--filter", dest="bpf", default="",
                   help="extra BPF filter passed to tcpdump, e.g. 'not port 53'")
    p.add_argument("--vpn-subnet", action="append", default=[],
                   metavar="CIDR",
                   help="VPN client subnet(s), e.g. 10.8.0.0/24; used with "
                        "--keep-unmapped to attribute traffic from IPs not "
                        "in the status file (may be given multiple times)")
    p.add_argument("--keep-unmapped", action="store_true",
                   help="record traffic from VPN-subnet IPs with no status "
                        "entry as 'unmapped:<ip>' instead of dropping it")
    p.add_argument("--retention", metavar="DURATION", default="",
                   help="delete data older than this while collecting, e.g. "
                        "'24h', '7d' (default: keep everything)")
    p.add_argument("--stdin", action="store_true",
                   help="read tcpdump-formatted lines from stdin instead of "
                        "spawning tcpdump (for testing/replay)")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="verbose logging")

    # clients
    p = sub.add_parser("clients", help="list clients and their totals")
    _add_query_args(p)

    # client <name>
    p = sub.add_parser(
        "client",
        help="overview for one client: which IPs it hit and when",
        description="Shows every remote IP a client exchanged traffic with, "
                    "with packet/byte counts and first/last seen timestamps. "
                    "Use --timeline for per-time-bucket detail.",
    )
    p.add_argument("name", help="client common name")
    _add_query_args(p)
    p.add_argument("--ip", help="restrict to a single remote IP")
    p.add_argument("--by-port", action="store_true",
                   help="break rows down by remote port and protocol")
    p.add_argument("--timeline", action="store_true",
                   help="show individual time buckets (when each IP was hit)")

    # ip <addr>
    p = sub.add_parser(
        "ip",
        help="overview for one remote IP: which clients hit it and when",
        description="Shows every client that exchanged traffic with the "
                    "given remote IP. Use --timeline for per-time-bucket "
                    "detail.",
    )
    p.add_argument("address", help="remote IP address")
    _add_query_args(p)
    p.add_argument("--client", help="restrict timeline to a single client")
    p.add_argument("--timeline", action="store_true",
                   help="show individual time buckets (when the IP was hit)")

    # sessions
    p = sub.add_parser("sessions",
                       help="show client VPN sessions seen in the status file")
    _add_db_arg(p)
    p.add_argument("--client", help="restrict to one client")
    p.add_argument("--json", action="store_true")
    p.add_argument("--limit", type=int, default=0)

    # summary
    p = sub.add_parser("summary", help="database-wide totals")
    _add_db_arg(p)
    p.add_argument("--json", action="store_true")

    # prune
    p = sub.add_parser(
        "prune",
        help="delete data older than a retention window",
        description="Deletes traffic, session and reverse-DNS data older "
                    "than the given window. Safe to run while the collector "
                    "is running. Freed space is reused by new data; pass "
                    "--vacuum to also shrink the file on disk after a large "
                    "one-off prune.",
    )
    _add_db_arg(p)
    p.add_argument("--keep", required=True, metavar="DURATION",
                   help="how much history to keep, e.g. '24h', '7d', '4w'")
    p.add_argument("--vacuum", action="store_true",
                   help="rewrite the database file to release freed disk "
                        "space to the OS")

    # doctor
    p = sub.add_parser(
        "doctor",
        help="diagnose why collection isn't producing data",
        description="Runs checks (tcpdump, interface, status file, a short "
                    "live capture probe, database) and reports what's wrong. "
                    "Run as root with the same -i/-s/--db you pass to collect.",
    )
    _add_db_arg(p)
    p.add_argument("-i", "--interface", default=DEFAULT_INTERFACE,
                   help=f"tunnel interface to probe (default: {DEFAULT_INTERFACE})")
    p.add_argument("-s", "--status-file", default=DEFAULT_STATUS,
                   help=f"OpenVPN status file path (default: {DEFAULT_STATUS})")
    p.add_argument("--tcpdump-path", default="tcpdump",
                   help="tcpdump binary to use (default: tcpdump from PATH)")
    p.add_argument("--capture-seconds", type=float, default=6.0,
                   help="how long the live capture probe samples (default: 6)")

    return parser


def _times(args) -> tuple:
    since = parse_when(args.since) if getattr(args, "since", None) else None
    until = parse_when(args.until) if getattr(args, "until", None) else None
    return since, until


def _hostnames(args, db: Database, rows, key: str = "remote_ip") -> dict:
    """Reverse-resolve the IPs appearing in `rows`; {} when disabled."""
    if getattr(args, "no_resolve", False):
        return {}
    return Resolver(db).resolve(r[key] for r in rows)


def _host(names: dict, ip: str) -> str:
    return names.get(ip) or "-"


def cmd_collect(args) -> int:
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    if args.stdin:
        capture = StdinCapture()
    else:
        bpf = args.bpf.split() if args.bpf else None
        capture = TcpdumpCapture(
            args.interface, tcpdump_path=args.tcpdump_path, bpf_filter=bpf
        )
    retention = parse_duration(args.retention) if args.retention else 0.0
    try:
        run_collect(
            db_path=args.db,
            status_path=args.status_file,
            capture=capture,
            bucket_seconds=args.bucket_seconds,
            flush_interval=args.flush_interval,
            status_interval=args.status_interval,
            vpn_subnets=args.vpn_subnet,
            keep_unmapped=args.keep_unmapped,
            retention_seconds=retention,
        )
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


def cmd_clients(args) -> int:
    db = Database(args.db)
    since, until = _times(args)
    rows = db.list_clients(since=since, until=until)
    if args.limit:
        rows = rows[: args.limit]
    if args.json:
        print_json(rows)
    else:
        print_table(
            ["CLIENT", "REMOTE IPS", "PACKETS", "TRAFFIC", "FIRST SEEN", "LAST SEEN"],
            [
                (r["common_name"], r["remote_ips"], r["packets"],
                 format_bytes(r["bytes"]),
                 format_ts(r["first_seen"]), format_ts(r["last_seen"]))
                for r in rows
            ],
        )
    return 0


def cmd_client(args) -> int:
    db = Database(args.db)
    since, until = _times(args)
    if args.timeline:
        rows = db.client_timeline(args.name, remote_ip=args.ip,
                                  since=since, until=until, limit=args.limit)
        names = _hostnames(args, db, rows)
        if args.json:
            print_json(dict(r, hostname=names.get(r["remote_ip"], ""))
                       for r in rows)
        else:
            print_table(
                ["TIME", "REMOTE IP", "HOST", "PORT", "PROTO", "DIR",
                 "PACKETS", "TRAFFIC"],
                [
                    (format_ts(r["bucket"]), r["remote_ip"],
                     _host(names, r["remote_ip"]),
                     r["remote_port"] or "-", r["proto"], r["direction"],
                     r["packets"], format_bytes(r["bytes"]))
                    for r in rows
                ],
            )
        return 0

    rows = db.client_overview(args.name, since=since, until=until,
                              by_port=args.by_port, limit=args.limit)
    if args.ip:
        rows = [r for r in rows if r["remote_ip"] == args.ip]
    if not rows and not args.json:
        print(f"no traffic recorded for client {args.name!r}", file=sys.stderr)
        return 1
    names = _hostnames(args, db, rows)
    if args.json:
        print_json(dict(r, hostname=names.get(r["remote_ip"], ""))
                   for r in rows)
    elif args.by_port:
        print_table(
            ["REMOTE IP", "HOST", "PORT", "PROTO", "PKTS OUT", "PKTS IN",
             "TRAFFIC", "FIRST SEEN", "LAST SEEN"],
            [
                (r["remote_ip"], _host(names, r["remote_ip"]),
                 r["remote_port"] or "-", r["proto"],
                 r["packets_out"], r["packets_in"], format_bytes(r["bytes"]),
                 format_ts(r["first_seen"]), format_ts(r["last_seen"]))
                for r in rows
            ],
        )
    else:
        print_table(
            ["REMOTE IP", "HOST", "PKTS OUT", "PKTS IN", "TRAFFIC",
             "FIRST SEEN", "LAST SEEN"],
            [
                (r["remote_ip"], _host(names, r["remote_ip"]),
                 r["packets_out"], r["packets_in"],
                 format_bytes(r["bytes"]),
                 format_ts(r["first_seen"]), format_ts(r["last_seen"]))
                for r in rows
            ],
        )
    return 0


def cmd_ip(args) -> int:
    db = Database(args.db)
    since, until = _times(args)
    hostname = ""
    if not args.no_resolve:
        hostname = Resolver(db).resolve([args.address]).get(args.address, "")
    if args.timeline:
        rows = db.ip_timeline(args.address, client=args.client,
                              since=since, until=until, limit=args.limit)
        if args.json:
            print_json(dict(r, remote_hostname=hostname) for r in rows)
        else:
            if hostname:
                print(f"{args.address} = {hostname}\n")
            print_table(
                ["TIME", "CLIENT", "PORT", "PROTO", "DIR", "PACKETS", "TRAFFIC"],
                [
                    (format_ts(r["bucket"]), r["common_name"],
                     r["remote_port"] or "-", r["proto"], r["direction"],
                     r["packets"], format_bytes(r["bytes"]))
                    for r in rows
                ],
            )
        return 0

    rows = db.ip_overview(args.address, since=since, until=until)
    if args.limit:
        rows = rows[: args.limit]
    if not rows and not args.json:
        print(f"no traffic recorded for IP {args.address}", file=sys.stderr)
        return 1
    if args.json:
        print_json(dict(r, remote_hostname=hostname) for r in rows)
    else:
        if hostname:
            print(f"{args.address} = {hostname}\n")
        print_table(
            ["CLIENT", "PKTS OUT", "PKTS IN", "TRAFFIC", "FIRST SEEN", "LAST SEEN"],
            [
                (r["common_name"], r["packets_out"], r["packets_in"],
                 format_bytes(r["bytes"]),
                 format_ts(r["first_seen"]), format_ts(r["last_seen"]))
                for r in rows
            ],
        )
    return 0


def cmd_sessions(args) -> int:
    db = Database(args.db)
    rows = db.list_sessions(client=args.client, limit=args.limit)
    if args.json:
        print_json(rows)
    else:
        print_table(
            ["CLIENT", "REAL ADDRESS", "VPN IP", "CONNECTED SINCE",
             "RECEIVED", "SENT", "LAST SEEN"],
            [
                (r["common_name"], r["real_address"] or "-",
                 r["virtual_address"] or "-", r["connected_since"] or "-",
                 format_bytes(r["bytes_received"]),
                 format_bytes(r["bytes_sent"]), format_ts(r["last_seen"]))
                for r in rows
            ],
        )
    return 0


def cmd_summary(args) -> int:
    db = Database(args.db)
    row = db.summary()
    if args.json:
        print_json([row])
    else:
        print(f"clients:      {row['clients']}")
        print(f"remote IPs:   {row['remote_ips']}")
        print(f"packets:      {row['packets']}")
        print(f"traffic:      {format_bytes(row['bytes'])}")
        print(f"first seen:   {format_ts(row['first_seen'])}")
        print(f"last seen:    {format_ts(row['last_seen'])}")
    return 0


def cmd_prune(args) -> int:
    import os
    import time

    keep = parse_duration(args.keep)
    db = Database(args.db)

    def _size() -> int:
        total = 0
        for suffix in ("", "-wal", "-shm"):
            try:
                total += os.path.getsize(args.db + suffix)
            except OSError:
                pass
        return total

    before = _size()
    counts = db.prune(time.time() - keep)
    print(f"kept last {args.keep}; deleted "
          f"{counts['traffic']} traffic rows, {counts['sessions']} sessions, "
          f"{counts['rdns']} cached DNS entries, "
          f"{counts['clients']} idle clients")
    if args.vacuum:
        db.vacuum()
        after = _size()
        print(f"vacuumed: {format_bytes(before)} -> {format_bytes(after)}")
    else:
        print(f"database file: {format_bytes(before)} (freed pages will be "
              "reused; run with --vacuum to shrink the file now)")
    db.close()
    return 0


def cmd_doctor(args) -> int:
    from .doctor import run_doctor
    return run_doctor(
        interface=args.interface,
        status_path=args.status_file,
        db_path=args.db,
        tcpdump_path=args.tcpdump_path,
        capture_seconds=args.capture_seconds,
    )


_COMMANDS = {
    "collect": cmd_collect,
    "clients": cmd_clients,
    "client": cmd_client,
    "ip": cmd_ip,
    "sessions": cmd_sessions,
    "summary": cmd_summary,
    "prune": cmd_prune,
    "doctor": cmd_doctor,
}


def main(argv: Optional[list] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return _COMMANDS[args.command](args)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130
    except BrokenPipeError:
        # output piped into head/less which exited early; not an error
        try:
            sys.stdout.close()
        except OSError:
            pass
        return 141


if __name__ == "__main__":
    sys.exit(main())
