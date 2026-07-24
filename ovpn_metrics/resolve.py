"""Reverse-DNS resolution with a database-backed cache.

Lookups happen at query time, not capture time, so the collector never
stalls on DNS. Results (including failures) are cached in the metrics
database; successful lookups are re-checked after `ttl`, failures after
`failure_ttl`. A batch of misses is resolved concurrently by daemon
threads under an overall time budget — PTR lookups for unrouted or
firewalled IPs can take several seconds each, and a query command should
never hang on them. IPs that don't resolve within the budget are simply
shown bare this time and retried on the next query.
"""

from __future__ import annotations

import socket
import threading
import time
from typing import Dict, Iterable, List

DEFAULT_TTL = 24 * 3600
DEFAULT_FAILURE_TTL = 3600
DEFAULT_BUDGET = 8.0
DEFAULT_WORKERS = 16


def reverse_lookup(ip: str) -> str:
    """Return the PTR hostname for an IP, or '' if there is none."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return ""


class Resolver:
    def __init__(
        self,
        db,
        ttl: float = DEFAULT_TTL,
        failure_ttl: float = DEFAULT_FAILURE_TTL,
        budget: float = DEFAULT_BUDGET,
        max_workers: int = DEFAULT_WORKERS,
        lookup=reverse_lookup,
    ):
        self.db = db
        self.ttl = ttl
        self.failure_ttl = failure_ttl
        self.budget = budget
        self.max_workers = max_workers
        self.lookup = lookup

    def resolve(self, ips: Iterable[str]) -> Dict[str, str]:
        """Resolve IPs to hostnames. Missing/unknown IPs map to ''."""
        unique = list(dict.fromkeys(ip for ip in ips if ip))
        if not unique:
            return {}
        now = time.time()
        cached = self.db.rdns_get(unique)
        result: Dict[str, str] = {}
        misses: List[str] = []
        for ip in unique:
            row = cached.get(ip)
            if row is not None:
                hostname, resolved_at = row
                max_age = self.ttl if hostname else self.failure_ttl
                if now - resolved_at < max_age:
                    result[ip] = hostname
                    continue
            misses.append(ip)
        if misses:
            resolved = self._resolve_batch(misses)
            if resolved:
                self.db.rdns_put(resolved, now)
            result.update(resolved)
        for ip in unique:
            result.setdefault(ip, "")
        return result

    def _resolve_batch(self, ips: List[str]) -> Dict[str, str]:
        results: Dict[str, str] = {}
        pending = list(ips)
        lock = threading.Lock()

        def worker() -> None:
            while True:
                with lock:
                    if not pending:
                        return
                    ip = pending.pop()
                hostname = self.lookup(ip)
                with lock:
                    results[ip] = hostname

        threads = [
            threading.Thread(target=worker, daemon=True, name=f"rdns-{i}")
            for i in range(min(self.max_workers, len(ips)))
        ]
        for t in threads:
            t.start()
        deadline = time.monotonic() + self.budget
        for t in threads:
            t.join(max(0.0, deadline - time.monotonic()))
        with lock:
            return dict(results)
