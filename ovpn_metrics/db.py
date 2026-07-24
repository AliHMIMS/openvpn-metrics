"""SQLite storage for aggregated traffic metrics.

Traffic is aggregated into time buckets (default 60s) per
(client, remote ip, remote port, protocol, direction) so the database stays
small while still answering "which IPs did this client hit, and when".
"""

from __future__ import annotations

import os
import sqlite3
import threading
from typing import Dict, Iterable, List, Optional, Tuple

SCHEMA = """
CREATE TABLE IF NOT EXISTS clients (
    id          INTEGER PRIMARY KEY,
    common_name TEXT UNIQUE NOT NULL
);

CREATE TABLE IF NOT EXISTS traffic (
    client_id   INTEGER NOT NULL REFERENCES clients(id),
    remote_ip   TEXT    NOT NULL,
    remote_port INTEGER NOT NULL DEFAULT 0,
    proto       TEXT    NOT NULL,
    direction   TEXT    NOT NULL,             -- 'out' (client -> ip) or 'in'
    bucket      INTEGER NOT NULL,             -- epoch secs, floored to bucket
    packets     INTEGER NOT NULL DEFAULT 0,
    bytes       INTEGER NOT NULL DEFAULT 0,
    first_ts    REAL    NOT NULL,
    last_ts     REAL    NOT NULL,
    PRIMARY KEY (client_id, remote_ip, remote_port, proto, direction, bucket)
);

CREATE INDEX IF NOT EXISTS idx_traffic_remote ON traffic (remote_ip, bucket);
CREATE INDEX IF NOT EXISTS idx_traffic_bucket ON traffic (bucket);

CREATE TABLE IF NOT EXISTS rdns (
    ip          TEXT PRIMARY KEY,
    hostname    TEXT NOT NULL DEFAULT '',   -- '' = lookup failed (negative cache)
    resolved_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    client_id       INTEGER NOT NULL REFERENCES clients(id),
    real_address    TEXT NOT NULL DEFAULT '',
    virtual_address TEXT NOT NULL DEFAULT '',
    connected_since TEXT NOT NULL DEFAULT '',
    bytes_received  INTEGER NOT NULL DEFAULT 0,
    bytes_sent      INTEGER NOT NULL DEFAULT 0,
    last_seen       REAL NOT NULL DEFAULT 0,
    PRIMARY KEY (client_id, real_address, connected_since)
);
"""

# key: (client_name, remote_ip, remote_port, proto, direction, bucket)
AggKey = Tuple[str, str, int, str, str, int]
# value: [packets, bytes, first_ts, last_ts]
AggVal = List[float]


class Database:
    def __init__(self, path: str):
        self.path = path
        directory = os.path.dirname(os.path.abspath(path))
        os.makedirs(directory, exist_ok=True)
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.executescript(SCHEMA)
        self._lock = threading.Lock()
        self._client_ids: Dict[str, int] = {}

    def close(self) -> None:
        self.conn.close()

    # -- writes ------------------------------------------------------------

    def client_id(self, common_name: str) -> int:
        cid = self._client_ids.get(common_name)
        if cid is not None:
            return cid
        self.conn.execute(
            "INSERT OR IGNORE INTO clients(common_name) VALUES(?)",
            (common_name,),
        )
        cid = self.conn.execute(
            "SELECT id FROM clients WHERE common_name = ?", (common_name,)
        ).fetchone()[0]
        self._client_ids[common_name] = cid
        return cid

    def flush_aggregates(self, aggregates: Dict[AggKey, AggVal]) -> int:
        """Upsert in-memory aggregates into the traffic table."""
        if not aggregates:
            return 0
        with self._lock:
            for (name, rip, rport, proto, direction, bucket), val in aggregates.items():
                cid = self.client_id(name)
                self.conn.execute(
                    """
                    INSERT INTO traffic
                        (client_id, remote_ip, remote_port, proto, direction,
                         bucket, packets, bytes, first_ts, last_ts)
                    VALUES (?,?,?,?,?,?,?,?,?,?)
                    ON CONFLICT(client_id, remote_ip, remote_port, proto,
                                direction, bucket)
                    DO UPDATE SET
                        packets  = packets + excluded.packets,
                        bytes    = bytes + excluded.bytes,
                        first_ts = MIN(first_ts, excluded.first_ts),
                        last_ts  = MAX(last_ts, excluded.last_ts)
                    """,
                    (cid, rip, rport, proto, direction, bucket,
                     int(val[0]), int(val[1]), val[2], val[3]),
                )
            self.conn.commit()
        return len(aggregates)

    def record_sessions(self, sessions: Iterable, now: float) -> None:
        with self._lock:
            for s in sessions:
                cid = self.client_id(s.common_name)
                self.conn.execute(
                    """
                    INSERT INTO sessions
                        (client_id, real_address, virtual_address,
                         connected_since, bytes_received, bytes_sent, last_seen)
                    VALUES (?,?,?,?,?,?,?)
                    ON CONFLICT(client_id, real_address, connected_since)
                    DO UPDATE SET
                        virtual_address = excluded.virtual_address,
                        bytes_received  = excluded.bytes_received,
                        bytes_sent      = excluded.bytes_sent,
                        last_seen       = excluded.last_seen
                    """,
                    (cid, s.real_address, s.virtual_address,
                     s.connected_since, s.bytes_received, s.bytes_sent, now),
                )
            self.conn.commit()

    def rdns_get(self, ips) -> Dict[str, Tuple[str, float]]:
        """Return {ip: (hostname, resolved_at)} for cached entries."""
        out: Dict[str, Tuple[str, float]] = {}
        ips = list(ips)
        for i in range(0, len(ips), 500):  # stay under SQLite's param limit
            chunk = ips[i:i + 500]
            marks = ",".join("?" * len(chunk))
            for row in self.conn.execute(
                f"SELECT ip, hostname, resolved_at FROM rdns WHERE ip IN ({marks})",
                chunk,
            ):
                out[row["ip"]] = (row["hostname"], row["resolved_at"])
        return out

    def rdns_put(self, mapping: Dict[str, str], now: float) -> None:
        with self._lock:
            self.conn.executemany(
                """
                INSERT INTO rdns (ip, hostname, resolved_at) VALUES (?,?,?)
                ON CONFLICT(ip) DO UPDATE SET
                    hostname = excluded.hostname,
                    resolved_at = excluded.resolved_at
                """,
                [(ip, hostname, now) for ip, hostname in mapping.items()],
            )
            self.conn.commit()

    # -- queries -----------------------------------------------------------

    @staticmethod
    def _time_clause(since: Optional[float], until: Optional[float]):
        clauses, params = [], []
        if since is not None:
            clauses.append("t.last_ts >= ?")
            params.append(since)
        if until is not None:
            clauses.append("t.first_ts <= ?")
            params.append(until)
        return clauses, params

    def list_clients(self, since=None, until=None) -> List[sqlite3.Row]:
        clauses, params = self._time_clause(since, until)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        return self.conn.execute(
            f"""
            SELECT c.common_name,
                   COUNT(DISTINCT t.remote_ip)              AS remote_ips,
                   COALESCE(SUM(t.packets), 0)              AS packets,
                   COALESCE(SUM(t.bytes), 0)                AS bytes,
                   MIN(t.first_ts)                          AS first_seen,
                   MAX(t.last_ts)                           AS last_seen
            FROM clients c
            LEFT JOIN traffic t ON t.client_id = c.id
            {where}
            GROUP BY c.id
            ORDER BY c.common_name
            """,
            params,
        ).fetchall()

    def client_overview(self, common_name, since=None, until=None,
                        by_port=False, limit=0) -> List[sqlite3.Row]:
        """IPs a client hit: one row per remote IP (or IP:port with by_port)."""
        clauses, params = self._time_clause(since, until)
        clauses.insert(0, "c.common_name = ?")
        params.insert(0, common_name)
        group = "t.remote_ip, t.remote_port, t.proto" if by_port else "t.remote_ip"
        select_port = "t.remote_port AS remote_port, t.proto AS proto," if by_port else ""
        limit_sql = f"LIMIT {int(limit)}" if limit else ""
        return self.conn.execute(
            f"""
            SELECT t.remote_ip AS remote_ip, {select_port}
                   SUM(CASE WHEN t.direction='out' THEN t.packets ELSE 0 END) AS packets_out,
                   SUM(CASE WHEN t.direction='in'  THEN t.packets ELSE 0 END) AS packets_in,
                   SUM(t.bytes)    AS bytes,
                   MIN(t.first_ts) AS first_seen,
                   MAX(t.last_ts)  AS last_seen
            FROM traffic t JOIN clients c ON c.id = t.client_id
            WHERE {' AND '.join(clauses)}
            GROUP BY {group}
            ORDER BY last_seen DESC
            {limit_sql}
            """,
            params,
        ).fetchall()

    def client_timeline(self, common_name, remote_ip=None,
                        since=None, until=None, limit=0) -> List[sqlite3.Row]:
        """Bucketed hits for a client: exactly when each IP was hit."""
        clauses, params = self._time_clause(since, until)
        clauses.insert(0, "c.common_name = ?")
        params.insert(0, common_name)
        if remote_ip:
            clauses.append("t.remote_ip = ?")
            params.append(remote_ip)
        limit_sql = f"LIMIT {int(limit)}" if limit else ""
        return self.conn.execute(
            f"""
            SELECT t.bucket, t.remote_ip, t.remote_port, t.proto, t.direction,
                   t.packets, t.bytes, t.first_ts, t.last_ts
            FROM traffic t JOIN clients c ON c.id = t.client_id
            WHERE {' AND '.join(clauses)}
            ORDER BY t.bucket DESC, t.remote_ip
            {limit_sql}
            """,
            params,
        ).fetchall()

    def ip_overview(self, remote_ip, since=None, until=None) -> List[sqlite3.Row]:
        """Which clients hit a given IP."""
        clauses, params = self._time_clause(since, until)
        clauses.insert(0, "t.remote_ip = ?")
        params.insert(0, remote_ip)
        return self.conn.execute(
            f"""
            SELECT c.common_name,
                   SUM(CASE WHEN t.direction='out' THEN t.packets ELSE 0 END) AS packets_out,
                   SUM(CASE WHEN t.direction='in'  THEN t.packets ELSE 0 END) AS packets_in,
                   SUM(t.bytes)    AS bytes,
                   MIN(t.first_ts) AS first_seen,
                   MAX(t.last_ts)  AS last_seen
            FROM traffic t JOIN clients c ON c.id = t.client_id
            WHERE {' AND '.join(clauses)}
            GROUP BY c.id
            ORDER BY last_seen DESC
            """,
            params,
        ).fetchall()

    def ip_timeline(self, remote_ip, client=None,
                    since=None, until=None, limit=0) -> List[sqlite3.Row]:
        clauses, params = self._time_clause(since, until)
        clauses.insert(0, "t.remote_ip = ?")
        params.insert(0, remote_ip)
        if client:
            clauses.append("c.common_name = ?")
            params.append(client)
        limit_sql = f"LIMIT {int(limit)}" if limit else ""
        return self.conn.execute(
            f"""
            SELECT t.bucket, c.common_name, t.remote_port, t.proto, t.direction,
                   t.packets, t.bytes
            FROM traffic t JOIN clients c ON c.id = t.client_id
            WHERE {' AND '.join(clauses)}
            ORDER BY t.bucket DESC, c.common_name
            {limit_sql}
            """,
            params,
        ).fetchall()

    def list_sessions(self, client=None, limit=0) -> List[sqlite3.Row]:
        clauses, params = [], []
        if client:
            clauses.append("c.common_name = ?")
            params.append(client)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        limit_sql = f"LIMIT {int(limit)}" if limit else ""
        return self.conn.execute(
            f"""
            SELECT c.common_name, s.real_address, s.virtual_address,
                   s.connected_since, s.bytes_received, s.bytes_sent, s.last_seen
            FROM sessions s JOIN clients c ON c.id = s.client_id
            {where}
            ORDER BY s.last_seen DESC
            {limit_sql}
            """,
            params,
        ).fetchall()

    def summary(self) -> sqlite3.Row:
        return self.conn.execute(
            """
            SELECT (SELECT COUNT(*) FROM clients)            AS clients,
                   (SELECT COUNT(DISTINCT remote_ip) FROM traffic) AS remote_ips,
                   COALESCE(SUM(packets), 0)                 AS packets,
                   COALESCE(SUM(bytes), 0)                   AS bytes,
                   MIN(first_ts)                             AS first_seen,
                   MAX(last_ts)                              AS last_seen
            FROM traffic
            """
        ).fetchone()
