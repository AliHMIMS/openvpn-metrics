"""The collect loop: consume packets, map VPN IPs to clients, aggregate to DB."""

from __future__ import annotations

import ipaddress
import logging
import threading
import time
from typing import Dict, Optional

from .capture import Packet
from .db import AggKey, AggVal, Database
from .status import read_status_file

log = logging.getLogger("ovpn-metrics")


class StatusWatcher(threading.Thread):
    """Polls the OpenVPN status file, maintaining the vip->client map."""

    def __init__(self, path: str, db: Database, interval: float = 10.0):
        super().__init__(daemon=True, name="status-watcher")
        self.path = path
        self.db = db
        self.interval = interval
        self._routes: Dict[str, str] = {}
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._warned = False

    def refresh(self) -> None:
        snap = read_status_file(self.path)
        if snap is None:
            if not self._warned:
                log.warning(
                    "cannot read status file %s (will keep retrying); "
                    "is `status` enabled in the OpenVPN server config?",
                    self.path,
                )
                self._warned = True
            return
        self._warned = False
        with self._lock:
            self._routes = dict(snap.routes)
        if snap.clients:
            self.db.record_sessions(snap.clients, time.time())

    def lookup(self, ip: str) -> Optional[str]:
        with self._lock:
            return self._routes.get(ip)

    def run(self) -> None:
        while not self._stop_event.is_set():
            try:
                self.refresh()
            except Exception:
                log.exception("status refresh failed")
            self._stop_event.wait(self.interval)

    def stop(self) -> None:
        self._stop_event.set()
        if self.is_alive():
            self.join(timeout=5)


class Collector:
    """Aggregates packets into time buckets and flushes them to SQLite."""

    def __init__(
        self,
        db: Database,
        watcher: StatusWatcher,
        bucket_seconds: int = 60,
        flush_interval: float = 5.0,
        vpn_subnets: Optional[list] = None,
        keep_unmapped: bool = False,
        retention_seconds: float = 0.0,
        prune_interval: float = 900.0,
    ):
        self.db = db
        self.watcher = watcher
        self.bucket_seconds = max(1, bucket_seconds)
        self.flush_interval = flush_interval
        self.keep_unmapped = keep_unmapped
        self.retention_seconds = retention_seconds
        self.prune_interval = prune_interval
        self._last_prune: Optional[float] = None  # None -> prune on first packet
        self.vpn_networks = [
            ipaddress.ip_network(s, strict=False) for s in (vpn_subnets or [])
        ]
        self._agg: Dict[AggKey, AggVal] = {}
        self._agg_lock = threading.Lock()
        self._last_flush = time.monotonic()
        self.packets_seen = 0
        self.packets_recorded = 0

    # -- classification ----------------------------------------------------

    def _in_vpn_subnet(self, ip: str) -> bool:
        if not self.vpn_networks:
            return False
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in self.vpn_networks)

    def _client_for(self, ip: str) -> Optional[str]:
        """Resolve a VPN-side IP to a client label, or None."""
        name = self.watcher.lookup(ip)
        if name:
            return name
        if self.keep_unmapped and self._in_vpn_subnet(ip):
            return f"unmapped:{ip}"
        return None

    def classify(self, pkt: Packet):
        """Return (client, remote_ip, remote_port, direction) or None.

        'out' means the VPN client originated the packet (client -> remote);
        'in' is the reverse. On a tun interface every packet has exactly one
        VPN-side address, so we try the source first, then the destination.
        """
        client = self._client_for(pkt.src_ip)
        if client is not None:
            return client, pkt.dst_ip, pkt.dst_port, "out"
        client = self._client_for(pkt.dst_ip)
        if client is not None:
            return client, pkt.src_ip, pkt.src_port, "in"
        return None

    # -- aggregation -------------------------------------------------------

    def add_packet(self, pkt: Packet) -> None:
        self.packets_seen += 1
        info = self.classify(pkt)
        if info is None:
            return
        client, remote_ip, remote_port, direction = info
        self.packets_recorded += 1
        bucket = int(pkt.ts) - int(pkt.ts) % self.bucket_seconds
        key: AggKey = (client, remote_ip, remote_port, pkt.proto, direction, bucket)
        with self._agg_lock:
            val = self._agg.get(key)
            if val is None:
                self._agg[key] = [1, pkt.length, pkt.ts, pkt.ts]
            else:
                val[0] += 1
                val[1] += pkt.length
                val[2] = min(val[2], pkt.ts)
                val[3] = max(val[3], pkt.ts)

    def flush(self) -> int:
        with self._agg_lock:
            pending, self._agg = self._agg, {}
        n = self.db.flush_aggregates(pending)
        self._last_flush = time.monotonic()
        return n

    def maybe_flush(self) -> None:
        if time.monotonic() - self._last_flush >= self.flush_interval:
            self.flush()

    def prune(self) -> None:
        cutoff = time.time() - self.retention_seconds
        counts = self.db.prune(cutoff)
        self._last_prune = time.monotonic()
        if any(counts.values()):
            log.info(
                "retention prune (older than %.0fh): "
                "%d traffic rows, %d sessions, %d rdns, %d idle clients",
                self.retention_seconds / 3600, counts["traffic"],
                counts["sessions"], counts["rdns"], counts["clients"],
            )

    def maybe_prune(self) -> None:
        if not self.retention_seconds:
            return
        if (self._last_prune is not None
                and time.monotonic() - self._last_prune < self.prune_interval):
            return
        self.prune()

    # -- main loop ---------------------------------------------------------

    def run(self, capture) -> None:
        """Consume packets from a capture object until EOF or interrupt."""
        try:
            for pkt in capture.packets():
                self.add_packet(pkt)
                self.maybe_flush()
                self.maybe_prune()
        except KeyboardInterrupt:
            pass
        finally:
            capture.stop()
            self.flush()
            log.info(
                "collector stopped: %d packets seen, %d attributed to clients",
                self.packets_seen, self.packets_recorded,
            )


def run_collect(
    db_path: str,
    status_path: str,
    capture,
    bucket_seconds: int = 60,
    flush_interval: float = 5.0,
    status_interval: float = 10.0,
    vpn_subnets: Optional[list] = None,
    keep_unmapped: bool = False,
    retention_seconds: float = 0.0,
) -> Collector:
    """Wire up watcher + collector and run until the capture ends."""
    db = Database(db_path)
    watcher = StatusWatcher(status_path, db, interval=status_interval)
    watcher.refresh()  # synchronous first read so early packets can be mapped
    watcher.start()
    collector = Collector(
        db,
        watcher,
        bucket_seconds=bucket_seconds,
        flush_interval=flush_interval,
        vpn_subnets=vpn_subnets,
        keep_unmapped=keep_unmapped,
        retention_seconds=retention_seconds,
    )
    log.info("collecting: db=%s status=%s", db_path, status_path)
    try:
        collector.run(capture)
    finally:
        watcher.stop()
        db.close()
    return collector
