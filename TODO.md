# Hyperion VPN — TODO

Legend: `[ ]` open · `[~]` in progress · `[x]` done.
Read `ARCHITECTURE.md` first — it fixes the design decisions these tasks implement.

Top priorities, in order: **security → reliability → speed.**

## Confirmed design

- **Closed-port model:** Single Packet Authorization (SPA / port-knock). Firewall
  default-DROPs all; an authenticated knock transiently opens the tunnel port to the
  admin's *current* IP. **Direct** admin→server data path, no broker, no relay, no P2P.
- **Tunnel crypto:** Noise `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s` via **`noise-rust`**
  (`noise-protocol` =0.2.1 + `noise-rust-crypto` =0.6.2). Not WireGuard. `snow` = fallback.
- **Identity:** per-server static X25519 keypair (pubkey in client config) + shared
  **PSK** entered at start; client static key authenticates the admin. All rotatable.
- **Multiplexing:** yamux over the Noise transport.
- **Throughput:** small **TCP connection pool** per server, streams sharded across it.
- **Egress:** **deny-all by default** (`allow = []`); operator enumerates each target.
- **Platform:** server = Linux + root (`CAP_NET_RAW` + `CAP_NET_ADMIN`, nftables,
  AF_PACKET/NFLOG). Client = cross-platform (Windows admin box runs it directly).

---

## Phase 1 — Secure tunnel (Noise IKpsk2)  ← cross-platform, build first
- [ ] Key input wiring: no-echo passphrase prompt / `--key-file` / `HYPERION_PSK` env
      (core derivation done; CLI/config wiring lands with Phase 3/4 config).
- [ ] Cipher-suite negotiation: add AES-256-GCM alongside ChaCha20-Poly1305 default.
- [ ] Transport rekey policy (periodic `CipherState` rekey) + zero-copy relay buffers.

## Phase 2 — Multiplexing & stream protocol
- [ ] Deep flow-control tuning: per-connection receive-window sizing under load
      (basic config done — 512 streams, 16 KiB split; deferred to Phase 8 perf).

## Phase 3 — Server daemon (relay core, no SPA yet)
- [ ] Per-source-IP connection rate limit + max in-flight streams per conn
      (handshake timeout done; rate limit belongs with the Phase 5 SPA gate).
- [ ] Graceful drain of in-flight streams on shutdown (currently stops accepting only).

## Phase 4b — L3 TUN mode (default feature; transparent real-IP)
Done (compiles Linux cross-check + Windows/Wintun): `client tun` (TUN + `ipstack`,
dest-IP→server, dest-port→remote, egress-checked); **`SO_MARK` bypass on dial sockets**
(Linux) + **`print-routes`** emitting `ip route`/`ip rule` (tested); zero `[[forward]]`
config needed (just servers). Remaining:
- [ ] **Runtime verification on Linux + root** (knock + route + browse real IP).
- [ ] Windows socket-bypass (no `SO_MARK`; bind-to-interface / metric) — Linux-only now.
- [ ] UDP support (currently TCP-only; UDP streams dropped).
- [ ] `[tun]` config section (addr/prefix/mtu/mark) instead of only CLI flags.

## Phase 5 — Single Packet Authorization (Linux server gate)
Implemented + cross-checked for Linux (`cargo check --target x86_64-unknown-linux-gnu`);
knock crypto / packet parse / nft arg-building unit-tested cross-platform. Also done:
knock bound to the target server's static pubkey (AEAD AAD — cross-server replay dead);
kernel BPF filter on the sniffer socket (only knock-port UDP reaches userspace);
per-source-IP allow cooldown (caps `nft` churn from repeated valid knocks). Remaining:
- [ ] **Runtime verification on a real Linux host** (root): `nft -f` the base ruleset
      (`hyperion-server print-firewall`), enable `[knock]`, confirm: scanner sees
      all-filtered, a valid knock opens tcp/<port> for the source IP only, the set
      element expires, established conns survive, replay/stale/forged knocks are dropped.
- [ ] Privilege model: acquire `CAP_NET_RAW` + `CAP_NET_ADMIN`, drop the rest, run as a
      dedicated unprivileged user (+ systemd `AmbientCapabilities`).
- [ ] Per-source-IP connection rate limit; startup reconcile of stale set elements.
- [ ] Optional: single crafted-TCP-packet knock variant; NFLOG/iptables fallbacks.

## Phase 6 — Reliability
Done: supervised self-healing pool (re-knock + backoff/jitter on drop), TCP keepalive
(conntrack-warm + dead-peer detection), IP-change auto-reconnect, local listeners
survive flaps + open() grace, owned mux driver (no task leak), server-restart reconnect
test. Remaining:
- [ ] App-level keepalive ping/pong for faster liveness than TCP keepalive's idle timer.
- [ ] Audit every await for an explicit timeout (handshake + connect + per-stream
      connect-request/response exchange covered).
- [ ] Extended chaos on Linux: `netem` packet loss + client-IP flip mid-transfer.

## Phase 7 — Security hardening
Done: `THREAT_MODEL.md`; `zeroize` on keys/PSK + core-dump disable (Linux); bounded wire
allocations + panic-safety tests on every parser (knock/packet/ConnectRequest/frame);
`deny.toml` + CI (`cargo-deny` advisories/licenses/bans/sources, fmt, clippy `-D warnings`).
- [ ] `cargo fuzz` (libFuzzer) targets for deeper coverage (panic-safety tests cover
      basics; needs Linux + nightly).
- [ ] `systemd` sandbox unit + `CAP_NET_RAW`/`CAP_NET_ADMIN` ambient caps, drop the rest.
- [ ] **External crypto/protocol review before any production use.**

## Phase 8 — Performance
- [ ] `TCP_NODELAY` everywhere; tune SO_SNDBUF/SO_RCVBUF; tune yamux window + pool size.
- [ ] Zero-copy relay path (`bytes`, vectored IO); right-sized relay buffers.
- [ ] AEAD per host (AES-GCM with AES-NI, else ChaCha20-Poly1305).
- [ ] Benchmarks: single-stream throughput, many-stream fan-out, handshake/sec, knock
      latency, overhead vs raw TCP; under 0/1/5% simulated loss.
- [ ] Flamegraph the hot path; ensure crypto + copy dominate.

## Phase 11 — Testing
- [ ] Unit tests per module (knock, crypto, framing, mux, egress, config).
- [ ] Integration: loopback client↔server tunnel + forward to a throwaway TCP echo.
- [ ] Property tests for framing/parsers (`proptest`).
- [ ] Concurrency tests for the reconnect/supervisor logic.
- [ ] Load: N servers × M forwards × K conns; soak for leaks/fd exhaustion.
- [ ] Interop: forward to real `sshd:22`, run an SSH session through the tunnel.

## Phase 12 — Packaging & deployment
- [ ] Static musl server build (`x86_64`, `aarch64`); cross-platform client builds.
- [ ] Hardened `systemd` unit + sample nftables base ruleset for the server.
- [ ] Signed releases + checksums; reproducible builds.

---

## Resolved decisions
- [x] Closed-port model = **SPA / port-knock**, direct data path (no broker/relay/P2P).
- [x] Tunnel = **Noise IKpsk2** via `noise-rust` (not WireGuard); `snow` fallback.
- [x] Identity = per-server static X25519 keys + shared PSK; rotatable.
- [x] Per-server **TCP connection pool**.
- [x] Egress = **deny-all by default**, explicit provided allow-list.
- [x] No UDP/QUIC data path now (knock packet aside); revisit only if TCP HoL bites.

## Still open
- [x] Knock transport default — single **UDP** datagram
- [x] Firewall TTL for the NEW-connection allow window - 60s
- [x] ChaCha20-Poly1305 default per host
