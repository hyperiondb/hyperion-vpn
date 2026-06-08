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

## Phase 0 — Project setup
- [ ] `rust-toolchain.toml` pinning the toolchain + `rustfmt.toml` + `clippy` in CI.
- [ ] `deny.toml` (`cargo-deny`) for license + advisory + duplicate-dep gates.
- [ ] CI: fmt, clippy `-D warnings`, test, `cargo-audit`, Linux + Windows + musl matrix.

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
- [ ] Passphrase/Argon2id PSK source in config (currently base64 via env/file/value).
- [ ] Egress: IPv6 literals + CIDR host matching (currently exact host string + port).

## Phase 4 — Admin client (forwards, multi-server, pool)
- [ ] `status` command/endpoint: per-server state, pool size, live stream counts,
      throughput (deferred to Phase 9 observability).
- [ ] Live two-binary smoke in CI (in-process end-to-end test covers the data path;
      blocked locally by host AV behavioral block on the process orchestration).

## Phase 5 — Single Packet Authorization (Linux server gate)
- [ ] Knock packet: `{version, timestamp, nonce, tunnel_port}` sealed with a
      PSK-derived key (HKDF/BLAKE2, domain-separated) + ChaCha20-Poly1305.
- [ ] Client sender: single UDP datagram by default (no privileges); optional single
      crafted TCP packet for all-TCP environments.
- [ ] Server sniffer: passive capture via **AF_PACKET** (fallback **NFLOG** /
      `libnetfilter_log`); no bound port; bounded parse + per-IP rate limit.
- [ ] Anti-replay: reject stale timestamps (±window); bounded nonce cache.
- [ ] Firewall driver: **nftables** (preferred) / iptables fallback. Standing rules:
      default DROP + `ct state established,related accept`. On valid knock: add
      `allow <src_ip> -> tcp/<tunnel_port>` for NEW conns with short TTL; auto-expire.
- [ ] Idempotent rule add/remove; reconcile orphaned rules on startup.
- [ ] Privilege model: acquire `CAP_NET_RAW` + `CAP_NET_ADMIN`, drop the rest, run as
      dedicated unprivileged user.
- [ ] Tests (Linux/WSL2/VM): scanner sees all-filtered; valid knock opens for src IP
      only; replayed/stale/forged knock rejected; rule expires; established survives.

## Phase 6 — Reliability
- [ ] Per-server supervisor: on drop, **re-knock then reconnect**, exp backoff + jitter.
- [ ] Keepalive ping/pong; keeps conntrack warm; declare dead on miss → reconnect.
- [ ] Admin IP change mid-session → clean re-knock from the new IP.
- [ ] Local listeners survive tunnel flaps; new conns queue/fail fast cleanly.
- [ ] End-to-end backpressure via yamux flow control; bounded channels; await timeouts.
- [ ] Chaos test: kill/restart server mid-transfer, drop packets, flip client IP.

## Phase 7 — Security hardening
- [ ] Threat model doc (assets, adversaries, trust boundaries, abuse cases).
- [ ] `systemd` sandbox unit (NoNewPrivileges, ProtectSystem=strict, capability set).
- [ ] Memory hygiene: `zeroize` all key material; disable core dumps for the daemon.
- [ ] Bound every wire allocation (frame, header, streams, nonce cache).
- [ ] `cargo audit` / `cargo deny` clean; pin transitive crypto deps.
- [ ] Fuzz wire parsers (`cargo fuzz`: framing, ConnectRequest, knock packet).
- [ ] External crypto/protocol review before any production use.

## Phase 8 — Performance
- [ ] `TCP_NODELAY` everywhere; tune SO_SNDBUF/SO_RCVBUF; tune yamux window + pool size.
- [ ] Zero-copy relay path (`bytes`, vectored IO); right-sized relay buffers.
- [ ] AEAD per host (AES-GCM with AES-NI, else ChaCha20-Poly1305).
- [ ] Benchmarks: single-stream throughput, many-stream fan-out, handshake/sec, knock
      latency, overhead vs raw TCP; under 0/1/5% simulated loss.
- [ ] Flamegraph the hot path; ensure crypto + copy dominate.

## Phase 9 — Observability
- [ ] Structured `tracing` spans per knock/tunnel/stream; redact secrets.
- [ ] Optional Prometheus metrics (knocks, conns, streams, bytes, reconnects, fails).
- [ ] `--log-format json`; sane defaults; rate-limited error logs.

## Phase 10 — Config & UX
- [ ] Finalize TOML schema for both binaries + `--print-config-schema`.
- [ ] `hyperion keygen` (static keypairs) + passphrase/PSK docs.
- [ ] Config validation with clear errors (empty egress, dup local ports, bad keys).
- [ ] `hyperion doctor`: knock + handshake only, no forward (connectivity check).

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
- [ ] Minimal container image for the server (caps, net namespace notes).
- [ ] Signed releases + checksums; reproducible builds.

## Phase 13 — Docs
- [ ] README quickstart (keygen → server + nftables base → client → knock → SSH through).
- [ ] Security model & ops (key rotation, egress hygiene, knock replay window).
- [ ] Troubleshooting (firewall reconcile, MTU/HoL, reconnect storms, IP changes).
- [ ] Write up the SPA stealth-not-auth framing + the TCP-over-TCP trade-off plainly.

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
