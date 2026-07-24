# openvpn-metrics

A zero-dependency CLI that collects per-client traffic metrics from an
OpenVPN server and lets you query them:

- **Per client**: select a client and see every IP it hit, and when.
- **Per IP**: filter by a remote IP and see which clients hit it, and when.
- Sessions, totals, timelines, time-range filters, JSON output.

It works by **attaching to `tcpdump` on the OpenVPN tunnel interface**
(`tun0`) and mapping each packet's VPN-internal IP to a client certificate
common name using the OpenVPN **status file**. Traffic is aggregated into
time buckets (60s by default) and stored in a local SQLite database, so the
database stays small even under sustained traffic.

Pure Python 3 standard library — no pip packages, no libpcap bindings.
Requirements on the server: `python3` (≥ 3.8) and `tcpdump`.

## Setup

### 1. Enable the OpenVPN status file

In your server config (e.g. `/etc/openvpn/server.conf`):

```
status /var/log/openvpn/status.log 10
```

Status versions 1 (default), 2, and 3 are all supported. Restart OpenVPN
after changing the config.

### 2. Install

```sh
git clone <this repo> && cd openvpn-metrics
pip install .            # installs the `openvpn-metrics` command
# — or run it in place without installing:
python3 -m ovpn_metrics --help
```

### 3. Start the collector

Capturing packets requires root (or a tcpdump binary with `CAP_NET_RAW`):

```sh
sudo openvpn-metrics collect \
    --interface tun0 \
    --status-file /var/log/openvpn/status.log \
    --db /var/lib/openvpn-metrics/metrics.db
```

Leave it running — a systemd unit is provided in
[`contrib/openvpn-metrics.service`](contrib/openvpn-metrics.service):

```sh
sudo cp contrib/openvpn-metrics.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now openvpn-metrics
```

## Querying

All query commands accept `--db`, `--since`/`--until` (`30m`, `4h`, `7d`,
`2026-07-24`, `2026-07-24 13:00`), `--limit`, and `--json`.

**List clients and totals:**

```
$ openvpn-metrics clients
CLIENT  REMOTE IPS  PACKETS  TRAFFIC  FIRST SEEN           LAST SEEN
------  ----------  -------  -------  -------------------  -------------------
alice   2           4        2.0 KiB  2026-07-23 19:46:40  2026-07-23 19:47:50
bob     2           2        550 B    2026-07-23 19:48:40  2026-07-23 19:48:41
```

**Select a client → IPs they hit + when:**

```
$ openvpn-metrics client alice --since 7d
REMOTE IP       HOST                       PKTS OUT  PKTS IN  TRAFFIC  FIRST SEEN           LAST SEEN
--------------  -------------------------  --------  -------  -------  -------------------  -------------------
8.8.8.8         dns.google                 1         0        48 B     2026-07-23 19:47:50  2026-07-23 19:47:50
142.250.185.78  fra16s48-in-f14.1e100.net  2         1        2.0 KiB  2026-07-23 19:46:40  2026-07-23 19:47:45

$ openvpn-metrics client alice --timeline          # per-time-bucket detail
$ openvpn-metrics client alice --ip 8.8.8.8 --timeline
$ openvpn-metrics client alice --by-port           # break down by port/proto
```

**Filter by IP → which clients hit it + when:**

```
$ openvpn-metrics ip 142.250.185.78
CLIENT  PKTS OUT  PKTS IN  TRAFFIC  FIRST SEEN           LAST SEEN
------  --------  -------  -------  -------------------  -------------------
bob     1         0        200 B    2026-07-23 19:48:40  2026-07-23 19:48:40
alice   2         1        2.0 KiB  2026-07-23 19:46:40  2026-07-23 19:47:45

$ openvpn-metrics ip 142.250.185.78 --timeline
```

**Reverse DNS.** The HOST column (and the `<ip> = <hostname>` line on the
`ip` command) comes from a reverse-DNS (PTR) lookup done at query time.
Results are cached in the database — 24 h for successes, 1 h for failures —
and lookups run concurrently under an overall time budget, so slow PTR
zones can't hang a query: unresolved IPs show `-` and are retried on the
next query. Pass `--no-resolve` to skip lookups entirely (this also avoids
sending PTR queries for every displayed IP to your resolver). JSON output
gains a `hostname` field.

**Sessions and overall stats:**

```
$ openvpn-metrics sessions        # connections seen in the status file
$ openvpn-metrics summary         # database-wide totals
$ openvpn-metrics doctor          # diagnose collection problems (see below)
```

## How it works

```
tun0 ──▶ tcpdump -tt -l -n -q ──▶ line parser ──▶ classify ──▶ aggregate ──▶ SQLite
                                                     ▲
                     status file (poll every 10s) ───┘
                     virtual IP ──▶ client common name
```

- The collector spawns `tcpdump` as a subprocess and parses its
  line-oriented output; there is nothing to compile and no libpcap binding.
- The status file's routing table maps each VPN virtual IP to the client
  common name. It's polled every `--status-interval` seconds (10 by
  default), so reconnects and re-assigned IPs are picked up quickly.
- Each packet is attributed to the client on its VPN side; the other side
  is the "remote IP". Direction is `out` (client → remote) or `in`.
- Packets are aggregated in memory per
  `(client, remote IP, remote port, protocol, direction, time bucket)` and
  flushed to SQLite every `--flush-interval` seconds (5 by default).

### Useful collector options

| Option | Purpose |
| --- | --- |
| `-i/--interface` | Tunnel interface to capture on (default `tun0`) |
| `-s/--status-file` | OpenVPN status file path |
| `--bucket-seconds` | Aggregation granularity; lower = more detail, bigger DB |
| `--filter 'not port 53'` | Extra BPF filter passed to tcpdump |
| `--vpn-subnet 10.8.0.0/24 --keep-unmapped` | Record traffic from VPN IPs missing from the status file as `unmapped:<ip>` instead of dropping it |
| `--stdin` | Read tcpdump-formatted lines from stdin (testing/replay) |

Replay a capture without touching an interface:

```sh
tcpdump -r capture.pcap -tt -n -q | openvpn-metrics collect --stdin --db test.db -s status.log
```

## Troubleshooting: no data being collected

Run the built-in diagnostic with the **same** `-i`/`-s`/`--db` you use for
`collect` (as root):

```sh
openvpn-metrics doctor -i tun0 -s /run/openvpn-server/status-server.log \
    --db /var/lib/openvpn-metrics/metrics.db
```

It checks tcpdump, the interface, the status file, runs a short live capture
probe, and inspects the database — then tells you which layer is broken. The
capture probe is the key one: it distinguishes **"tcpdump sees nothing"**
(wrong interface, or OpenVPN 2.6+ DCO bypassing the tun device) from
**"packets seen but none map to a client"** (wrong or stale status file).

The most common causes:

- **The service's `ExecStart` still has the default paths.** The shipped
  `contrib/openvpn-metrics.service` defaults to `tun0` and
  `/var/log/openvpn/status.log`. If your server writes elsewhere (e.g.
  `/run/openvpn-server/status-server.log`), edit `ExecStart` to match, then
  `systemctl daemon-reload && systemctl restart openvpn-metrics`. Check what
  the running service actually uses with `systemctl cat openvpn-metrics`, and
  what it logged at startup with `journalctl -u openvpn-metrics -n 20` — the
  first log line prints the exact db and status paths in use.
- **Wrong interface.** `ip -brief link show | grep -iE 'tun|ovpn|dco'` lists
  the real ones. `doctor` also prints the candidates it finds.
- **Status file unreadable / not enabled.** The collector logs
  `cannot read status file ...` and drops all traffic. Confirm `status
  <path>` is in the server config and the path matches.
- **Service fails only under systemd** (works when you run it by hand).
  `journalctl -u openvpn-metrics` shows one of:
  - `tcpdump: Couldn't change to 'tcpdump' uid=... Operation not permitted`
    — tcpdump drops privileges on startup and needs `CAP_SETUID`/`CAP_SETGID`.
  - `cannot read status file ...` while the file is readable as root — the
    status file is owned by the OpenVPN user (often in a `0750` dir under
    `/run`), so reading it as the sandboxed service needs
    `CAP_DAC_READ_SEARCH`.

  Both come from restricting the service's capabilities (`User=`,
  `CapabilityBoundingSet=`, `AmbientCapabilities=`). tcpdump's startup
  privilege-drop and the status-file read need a specific capability set
  that is easy to get wrong. The provided unit therefore runs as plain root
  with **no** capability restrictions — that's the reliable configuration.
  If you want to re-harden with an explicit capability list, you need at
  least `CAP_NET_RAW CAP_NET_ADMIN CAP_SETUID CAP_SETGID CAP_DAC_READ_SEARCH`.
  `doctor` runs as unrestricted root and so won't reproduce a sandbox-only
  failure — check `journalctl -u openvpn-metrics` for the running service.

## Notes & limitations

- Byte counts are the payload lengths tcpdump reports (IP header overhead
  is not included); treat them as good relative indicators.
- If two clients exchange traffic with each other over the VPN, the packet
  is attributed to the *originating* client.
- The database only knows about clients that generated traffic or appeared
  in the status file while the collector was running. Issued-but-never-seen
  certificates won't appear.
- Privacy: this records every remote IP each VPN user contacts. Make sure
  that's acceptable (and lawful) for your users before deploying.

## Development

```sh
python3 -m unittest discover -s tests -v
```

## License

MIT
