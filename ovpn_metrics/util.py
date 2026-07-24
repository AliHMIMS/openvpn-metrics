"""Small formatting/parsing helpers for the CLI."""

from __future__ import annotations

import datetime as _dt
import json
import re
import sys
from typing import Iterable, List, Optional, Sequence

_RELATIVE_RE = re.compile(r"^(\d+)([smhdw])$")
_UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}


def parse_when(value: str, now: Optional[float] = None) -> float:
    """Parse '--since/--until' values.

    Accepts relative durations ('30m', '4h', '7d', '2w') meaning "that long
    ago", or absolute 'YYYY-MM-DD' / 'YYYY-MM-DD HH:MM[:SS]' local times.
    """
    value = value.strip()
    m = _RELATIVE_RE.match(value)
    if m:
        base = now if now is not None else _dt.datetime.now().timestamp()
        return base - int(m.group(1)) * _UNIT_SECONDS[m.group(2)]
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%dT%H:%M", "%Y-%m-%d"):
        try:
            return _dt.datetime.strptime(value, fmt).timestamp()
        except ValueError:
            continue
    raise ValueError(
        f"unrecognized time {value!r}; use e.g. '30m', '4h', '7d', "
        "'2026-07-24' or '2026-07-24 13:00'"
    )


def format_ts(ts: Optional[float]) -> str:
    if ts is None or ts == 0:
        return "-"
    return _dt.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def format_bytes(n: Optional[float]) -> str:
    if n is None:
        return "-"
    n = float(n)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if n < 1024 or unit == "TiB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TiB"


def print_table(headers: Sequence[str], rows: Iterable[Sequence],
                file=None) -> None:
    file = file or sys.stdout
    str_rows: List[List[str]] = [[str(c) for c in row] for row in rows]
    widths = [len(h) for h in headers]
    for row in str_rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))
    fmt = "  ".join(f"{{:<{w}}}" for w in widths)
    print(fmt.format(*headers), file=file)
    print(fmt.format(*("-" * w for w in widths)), file=file)
    for row in str_rows:
        print(fmt.format(*row), file=file)


def print_json(rows: Iterable, file=None) -> None:
    file = file or sys.stdout
    json.dump([dict(r) for r in rows], file, indent=2, default=str)
    file.write("\n")
