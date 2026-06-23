# Windows netscan — TCP listeners, UDP endpoints, IPv6 (4 audit HIGHs)

> **For Claude:** strict TDD (RED+GREEN separate commits). Synthetic unit tests are
> **tier-3** here (I author both fixture and layout); the load-bearing validation is
> the **tier-2 citadel oracle**, which needs issen's `build_reader` bootstrap and is
> therefore **owed to issen** (see bottom). Do NOT declare these correct on synthetic
> tests alone.

Fixes four `docs/correctness-audit-2026-06-23.md` HIGHs, all in
`crates/memf-windows/src/network.rs` (+ `dns_cache.rs` for the 4th):
1. netscan misses `TcpL`/`_TCP_LISTENER` + `UdpA`/`_UDP_ENDPOINT` (only `TcpE`).
2. both TCP paths are IPv4-only — every IPv6 connection dropped.
3. wired `netstat` hard-requires tcpip.sys `TcpBTable*` symbols; the symbol-free
   `scan_tcp_endpoints` exists but is never called (CLI wiring).
4. DNS cache walker reads a user-mode `dnsrslvr.dll` symbol from kernel space with
   no svchost context switch / fallback — empty on every real dump.

## Oracle ground truth (vol3 `windows.netscan` on citadeldc01.mem)

Counts saved at `/tmp/net-oracle/citadel-proto-counts.txt`:

| proto | rows |
|---|---|
| UDPv4 | 13095 |
| UDPv6 | 6416 |
| TCPv6 | 93 |
| TCPv4 | 81 |
| **TCP LISTENING** | 123 |

memf today (TcpE/IPv4 only) recovers ~81 of ~19,600 rows — it misses **every** UDP
endpoint, **every** IPv6 row, and **every** listener. The single most legible row:
`dns.exe (pid 1368)` listening `TCPv4 127.0.0.1:53` and `TCPv6 ::1:53`, plus
thousands of UDP `0.0.0.0:<port>` / `:::<port>` endpoints.

## Authoritative struct offsets (vol3 netscan ISFs, x64)

Parsing model (vol3 `extensions/network.py`, `_TCP_LISTENER` is the base of both
`_UDP_ENDPOINT` and `_TCP_ENDPOINT`):
- `InetAF` (ptr) → `_INETAF.AddressFamily` @ **0x18** (u16): `AF_INET=2`, `AF_INET6=0x17`.
- `Owner` (ptr) → `_EPROCESS` (UniqueProcessId / ImageFileName) — may be 0 (ownerless).
- `CreateTime` — FILETIME (`0` ⇒ field absent for that build).
- `LocalAddr` (ptr) → `_LOCAL_ADDRESS.pData` @ **0x10** (ptr) → `_IN_ADDR` (`addr4`/`addr6` both @0; read 4 or 16 bytes by family).
- `Port` — u16 **big-endian**.
- Listener: remote = INADDR_(6)_ANY, state `LISTENING`. Dual-stack `AF_INET6` yields BOTH a v4 (`0.0.0.0`) and v6 row (vol3 `dual_stack_sockets`).
- UDP: state blank; same address handling (dual-stack).

| build (ISF) | `_TCP_LISTENER` InetAF/Owner/CreateTime/LocalAddr/Port | `_UDP_ENDPOINT` InetAF/Owner/CreateTime/LocalAddr/Port |
|---|---|---|
| win81-x64 (9600, citadel) | 0x60 / 0x28 / 0x40 / 0x58 / 0x6a | 0x20 / 0x28 / 0x58 / 0x60 / 0x78 |
| win10-17763 (Svr2019) | 0x28 / 0x30 / 0x40 / 0x60 / 0x72 | 0x20 / 0x28 / 0x58 / 0x80 / 0x78 |
| win10-19041 (workstation) | 0x28 / 0x30 / 0x40 / 0x60 / 0x72 | 0x20 / 0x28 / 0x58 / 0xa8 / 0xa0 |
| win10-20348 (+TTcb→TcpE) | 0x28 / 0x30 / 0x40 / 0x60 / 0x72 | 0x20 / 0x28 / 0x58 / 0xa8 / 0xa0 |

Shared: `_INETAF.AddressFamily`@0x18, `_LOCAL_ADDRESS.pData`@0x10, `_IN_ADDR.addr4/addr6`@0.
Pool tags: `TcpL`→listener, `UdpA`→udp, `TTcb`→`_TCP_ENDPOINT` (build 20348 only).

**Real-data caveat (must resolve against the oracle):** memf's validated `TcpE`
local-address chain double-derefs `pData` (`la.pData`→ptr→`_IN_ADDR`), while vol3's
listener model single-derefs (`pData`→`_IN_ADDR`). Confirm the correct indirection
for `_TCP_LISTENER`/`_UDP_ENDPOINT.LocalAddr` against citadel before locking it —
this is the shimcache-`Parent@0x0` failure mode (passes synthetic, wrong on real).

## TDD increments (order)

1. **`UdpEndpointLayout` + `scan_udp_endpoints`** (`UdpA`). Family-aware address read
   from the start (so step 2 is just "stop rejecting AF_INET6"). Emit `UDPv4`/`UDPv6`,
   remote blank, no state. RED: synthetic `UdpA` pool object (AF_INET) → one endpoint.
2. **IPv6** across TcpE + UDP + listener: read 16 bytes on `AF_INET6`, format v6,
   emit `*v6`; dual-stack listener/UDP yields both rows. RED: AF_INET6 fixture.
3. **`TcpListenerLayout` + `scan_tcp_listeners`** (`TcpL`), state `LISTENING`,
   remote `0.0.0.0`/`::`, port 0. RED: synthetic `TcpL` object.
4. **Wire the symbol-free scanner**: `cmd_net` / timeline call `scan_tcp_endpoints`
   (+ the new udp/listener scans) instead of hard-failing on `TcpBTable*`; keep the
   symbol path as a fast path when present. (audit HIGH #3)
5. **DNS** (`dns_cache.rs`): locate the svchost running `-s Dnscache`, switch process
   context, resolve `dnsrslvr!g_HashTable` from the dnsrslvr.dll module, fall back to
   a heap pointer scan. Largest item; reference Rekall `dns.py` + MemProcFS
   `m_sys_netdns.c`. (audit HIGH #4) — likely its own session.

A unified `scan_network_objects` that scans all three tags in one physical pass is
the eventual shape (one scan, dispatch by tag); build it incrementally per above.

## OWED: issen tier-2 validation (`crates/issen-mem/tests/szechuan_netscan.rs`)

memf-windows can't open a `.mem` (needs `issen_mem::dispatch::build_reader`). Mirror
`szechuan_lsadump.rs`: build reader on citadeldc01.mem, run the new scanners, and
reconcile against the oracle counts above (≥ the listed UDP/listener/IPv6 counts, the
`dns.exe:53` listeners present, pid attribution non-empty). Release-coupling caveat as
shimcache/lsadump: needs published memf-windows or a local `[patch.crates-io]`.
Oracle command: `PYTHONPATH=~/src/_refs/volatility3 python3 ~/src/_refs/volatility3/vol.py -f /tmp/szechuan-extracted/citadeldc01.mem windows.netscan`.
