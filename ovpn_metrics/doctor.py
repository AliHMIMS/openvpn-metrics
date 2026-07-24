"""`openvpn-metrics doctor`: diagnose why collection isn't producing data.

Runs a series of checks and prints OK / WARN / FAIL for each, with a short
explanation and a suggested fix. The most useful one is the live capture
probe: it spawns tcpdump on the interface for a few seconds and reports how
many packets were seen and how many could be mapped to a client using the
current status file — which distinguishes "tcpdump sees nothing" (wrong
interface / DCO) from "packets seen but none map" (wrong status file).
"""

from __future__ import annotations

import os
import shutil
import subprocess
from typing import List, Optional

from .capture import TcpdumpCapture
from .status import parse_status

OK = "OK"
WARN = "WARN"
FAIL = "FAIL"

_MARK = {OK: "[ OK ]", WARN: "[WARN]", FAIL: "[FAIL]"}


class Report:
    def __init__(self) -> None:
        self.worst = OK
        self._order = {OK: 0, WARN: 1, FAIL: 2}

    def line(self, level: str, title: str, detail: str = "") -> None:
        print(f"{_MARK[level]} {title}")
        if detail:
            for ln in detail.splitlines():
                print(f"       {ln}")
        if self._order[level] > self._order[self.worst]:
            self.worst = level


def _list_interfaces() -> List[str]:
    try:
        return sorted(os.listdir("/sys/class/net"))
    except OSError:
        return []


def _check_privileges(rep: Report) -> None:
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        rep.line(OK, "Privileges: running as root")
        return
    rep.line(
        WARN,
        "Privileges: not running as root",
        "Packet capture needs root or a tcpdump binary with CAP_NET_RAW. "
        "If the capture probe below fails, this is likely why.",
    )


def _check_tcpdump(rep: Report, tcpdump_path: str) -> bool:
    path = shutil.which(tcpdump_path)
    if path is None:
        rep.line(FAIL, f"tcpdump: {tcpdump_path!r} not found on PATH",
                 "Install it, e.g. `apt install tcpdump`.")
        return False
    version = ""
    try:
        out = subprocess.run([path, "--version"], capture_output=True,
                             text=True, timeout=5)
        version = (out.stdout or out.stderr).splitlines()[0].strip()
    except (OSError, subprocess.SubprocessError, IndexError):
        pass
    rep.line(OK, f"tcpdump: {path}", version)
    return True


def _check_interface(rep: Report, interface: str) -> bool:
    interfaces = _list_interfaces()
    if not interfaces:
        rep.line(WARN, "Interface: could not enumerate /sys/class/net")
        return True
    candidates = [i for i in interfaces
                  if i.startswith(("tun", "tap", "ovpn")) or "dco" in i]
    hint = ("VPN-like interfaces present: " + ", ".join(candidates)) \
        if candidates else \
        ("no tun/tap/ovpn interfaces found — is OpenVPN running, and is a "
         "client connected? Interfaces: " + ", ".join(interfaces))
    if interface in interfaces:
        rep.line(OK, f"Interface: {interface} exists", hint)
        return True
    rep.line(
        FAIL,
        f"Interface: {interface} does not exist",
        hint + f"\nPass the right one with -i, e.g. -i {candidates[0]}"
        if candidates else hint,
    )
    return False


def _check_status(rep: Report, status_path: str):
    if not os.path.exists(status_path):
        rep.line(
            FAIL,
            f"Status file: {status_path} does not exist",
            "Set `status <path>` in the OpenVPN server config, and point "
            "--status-file / the service's ExecStart at that same path.",
        )
        return None
    try:
        with open(status_path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError as exc:
        rep.line(FAIL, f"Status file: cannot read {status_path}",
                 f"{exc}\nCheck file permissions (the collector runs as root).")
        return None
    snap = parse_status(text)
    if not snap.routes:
        rep.line(
            WARN,
            f"Status file: {status_path} readable but has no routes",
            "No client is currently connected, or the routing table is "
            "empty. Connect a client and re-run. Without routes, captured "
            "packets cannot be mapped to a client and are dropped.",
        )
        return snap
    sample = list(snap.routes.items())[:3]
    detail = f"{len(snap.routes)} route(s), {len(snap.clients)} client(s). " \
             "Sample: " + ", ".join(f"{ip}->{cn}" for ip, cn in sample)
    rep.line(OK, f"Status file: {status_path} parsed", detail)
    return snap


def _check_capture(rep: Report, interface: str, tcpdump_path: str,
                   snap, seconds: float) -> None:
    rep.line(OK, f"Capture probe: sampling {interface} for "
                 f"{seconds:.0f}s ...")
    cap = TcpdumpCapture(interface, tcpdump_path=tcpdump_path)
    try:
        result = cap.sample(seconds)
    except Exception as exc:  # pragma: no cover - defensive
        rep.line(FAIL, "Capture probe: tcpdump failed to run", str(exc))
        return

    if result.returncode not in (0, None, -2, -15) and not result.packets:
        rep.line(FAIL, "Capture probe: tcpdump exited with an error",
                 result.stderr or f"exit status {result.returncode}")
        return

    seen = len(result.packets)
    if seen == 0:
        rep.line(
            WARN,
            "Capture probe: 0 packets seen",
            "tcpdump saw no traffic on this interface during the sample. "
            "Either no client sent traffic just now, the interface is wrong, "
            "or (OpenVPN 2.6+ DCO) the data channel bypasses the tun device. "
            "Generate traffic from a connected client and re-run; if it "
            "stays 0, try another interface from the list above.\n"
            + (result.stderr if result.stderr else ""),
        )
        return

    routes = snap.routes if snap is not None else {}
    mapped = 0
    unmapped_ips = set()
    for pkt in result.packets:
        if pkt.src_ip in routes or pkt.dst_ip in routes:
            mapped += 1
        else:
            unmapped_ips.add(pkt.src_ip)
    if mapped == 0:
        sample_ips = ", ".join(list(unmapped_ips)[:4])
        rep.line(
            FAIL,
            f"Capture probe: {seen} packets seen, but NONE mapped to a client",
            "tcpdump works, but no packet's address matched a virtual IP in "
            "the status file. This is the classic 'wrong status file' or "
            "'stale routes' case — the collector is capturing but dropping "
            "everything.\n"
            f"Unmapped sample IPs: {sample_ips}\n"
            "Confirm --status-file points at the file this server actually "
            "writes, and that its routing table lists the VPN IPs above.",
        )
        return
    rep.line(
        OK,
        f"Capture probe: {seen} packets seen, {mapped} mapped to a client",
        "Capture and client mapping are both working.",
    )


def _check_db(rep: Report, db_path: str) -> None:
    from .db import Database
    try:
        db = Database(db_path)
    except Exception as exc:
        rep.line(FAIL, f"Database: cannot open {db_path}",
                 f"{exc}\nEnsure the directory exists and is writable.")
        return
    try:
        row = db.summary()
        detail = (f"{row['clients']} client(s), {row['remote_ips']} remote "
                  f"IP(s), {row['packets']} packet(s) recorded so far")
        if row["packets"]:
            rep.line(OK, f"Database: {db_path}", detail)
        else:
            rep.line(WARN, f"Database: {db_path} is empty",
                     "No traffic recorded yet. If the capture probe above "
                     "passed, start (or restart) the collector and give it "
                     "a moment.")
    finally:
        db.close()


def run_doctor(interface: str, status_path: str, db_path: str,
               tcpdump_path: str = "tcpdump", capture_seconds: float = 6.0) -> int:
    """Run all checks; return a process exit code (0 unless something FAILed)."""
    rep = Report()
    print("openvpn-metrics doctor\n")
    _check_privileges(rep)
    have_tcpdump = _check_tcpdump(rep, tcpdump_path)
    iface_ok = _check_interface(rep, interface)
    snap = _check_status(rep, status_path)
    if have_tcpdump and iface_ok:
        _check_capture(rep, interface, tcpdump_path, snap, capture_seconds)
    else:
        rep.line(WARN, "Capture probe: skipped",
                 "Fix the tcpdump/interface issues above first.")
    _check_db(rep, db_path)

    print()
    if rep.worst == FAIL:
        print("Result: FAIL — see the [FAIL] lines above for what to fix.")
        return 1
    if rep.worst == WARN:
        print("Result: WARN — collection may work, but review the warnings.")
        return 0
    print("Result: OK — everything checks out.")
    return 0
