# Hyperion VPN — Architecture

## Problem

An administrator must reach one or more servers whose firewalls **drop all inbound
traffic** — no port answers a scanner. The admin needs a secure, fast, reliable,
bidirectional tunnel to each server and must be able to reach **any** service port on
that server (e.g. SSH on 22) while connected to **many** servers at once.

Constraints (from requirements):

- Rust, modern fast cryptography, shared key entered at start.
- Client (admin) initiates; servers' public IPv4 addresses are known ahead of time.
- The **server has no reachable ports** and must stay that way to the outside world.
- The **admin's IP is dynamic** (ISP-assigned); the server cannot pre-know it.
- No P2P — direct connections only, for speed.
- TCP tunnel (UDP not required for the data path).
- Speed, security, reliability are the top priorities.

## The "no open ports" reality

TCP is connect-to-listener: for the admin to open a connection, *something on the
server must accept it*. A host with zero reachable ports cannot be connected to.
So "all ports closed" cannot mean "nothing ever accepts" — it means **closed to
everyone except the cryptographically authenticated admin, and invisible to
scanners.** Hyperion achieves that with **Single Packet Authorization (SPA)**:

- The firewall default-DROPs everything, including the tunnel port → `nmap` sees a
  fully filtered host.
- The admin sends one authenticated **knock** packet. The server has **no bound port**
  for it; a daemon passively sniffs inbound packets (AF_PACKET / NFLOG), so there is
  nothing to scan or fingerprint.
- A valid knock makes the server insert a **short-lived** firewall rule permitting the
  admin's *current source IP* to open the tunnel port. The admin connects; the rule
  expires; the established tunnel survives via conntrack.

This also solves the dynamic-IP problem for free: the knock packet *reveals* the
admin's current source address, which is exactly what the temporary rule needs.

> SPA is a stealth / attack-surface-reduction layer, **not** the primary
> authentication. A spoofed or replayed knock at most re-opens the port to an IP the
> attacker does not control; they still face the Noise `IKpsk2` handshake (static
> server identity + static client identity + shared PSK). The cryptographic gate is
> the tunnel, not the knock.

## Shape of the solution

Hyperion's default data path is a **layer-4 multiplexed port-forwarding tunnel** —
closer to `ssh -L` with many channels — which needs no TUN device or root on the client
and keeps the relay a simple byte copy. An **optional L3 TUN mode** (`--features tun`,
client root) layers a userspace TCP/IP stack on top so you reach the server's real
`IP:port` transparently; the wire protocol and relay are identical underneath.

```
  admin host (dynamic IP)                       server (firewall: default DROP,
                                                 no reachable port)
  ┌--------------------┐                         ┌---------------------------────┐
  │ hyperion-client    │  (1) authenticated      │ knock sniffer (AF_PACKET,     │
  │                    │      knock packet  ────> │  no bound port)               │
  │                    │                          │     │ valid? nft: allow       │
  │                    │  (2) nft allow <my_ip>   │     ▼ <admin_ip> -> :8443 60s │
  │ local listeners    │      -> tcp/8443, TTL    │ hyperion tunnel listener      │
  │  127.0.0.1:2201 ─┐ │  (3) TCP connect + Noise │  (bound, but firewalled to    │
  │  127.0.0.1:2202 ─┼─┼===== IKpsk2 + yamux ====>│   the authorized IP only)     │
  │  127.0.0.1:5432 ─┘ │      (small TCP pool)    │   ┌── dials (egress allow) ─┐  │
  │                    │                          │   │ 127.0.0.1:22  (sshd)    │  │
  └--------------------┘                          │   │ 127.0.0.1:5432 ...      │  │
                                                  │   └─────────────────────────┘  │
                                                  └────────────────────────────────┘
```

## Connection lifecycle

1. **Knock.** Client sends one packet sealed with a key derived from the shared PSK,
   carrying `{version, timestamp, nonce, tunnel_port}`. Default transport is a single
   UDP datagram (no client privileges needed); a single crafted TCP packet is an
   option for all-TCP environments. The server sniffs it regardless of firewall DROP.
2. **Authorize.** Server validates AEAD tag, timestamp freshness, and nonce
   uniqueness, then adds `allow <src_ip> -> tcp/<tunnel_port>` for NEW connections with
   a short TTL (e.g. 30 s). Existing connections are covered by a standing
   `ct state established,related accept` rule.
3. **Tunnel.** Client opens the TCP connection(s) and runs the Noise `IKpsk2`
   handshake (server static key known to client; client static key + PSK authenticate
   the admin). On success, yamux runs over the encrypted transport.
4. **Forward.** Each local accept → one yamux stream carrying a `ConnectRequest` (just
   the destination port); the server checks the **egress allowlist** (deny-all by
   default), dials its own `127.0.0.1:<port>`, and relays with `copy_bidirectional`.
5. **Teardown / reconnect.** TTL removes the NEW-connection rule; conntrack keeps the
   live tunnel. If the tunnel drops (or the admin's IP changes), the client re-knocks
   and reconnects.

## Layered data path

```
TCP socket  (reachable only after a valid knock)
  └─ Noise IKpsk2 secure transport    (X25519 static+ephemeral, ChaCha20-Poly1305)
       └─ yamux multiplexer           (logical streams, flow control)
            └─ per-stream header       (ConnectRequest{port} / ConnectResponse)
                 └─ raw relayed bytes   (e.g. an SSH session)
```

## Cryptography

### Knock authentication
- Key = HKDF/BLAKE2 over the shared PSK (domain-separated from the tunnel key).
- Payload sealed with ChaCha20-Poly1305; `{version, timestamp, nonce, tunnel_port}`.
- Anti-replay: reject stale timestamps (±window) and cache recent nonces.
- Threat framing: surface reduction only — see the note above.

### Tunnel (the real gate)
- **Framework:** Noise Protocol Framework via **`noise-rust`** (`noise-protocol` +
  `noise-rust-crypto`, RustCrypto backend) — same construction family as WireGuard,
  but **not** WireGuard: no kernel module, no `wg` interface, no UDP data path. Modern,
  analyzed, fast. (`snow` is the drop-in fallback if `IKpsk2`+PSK wiring hits friction.)
- **Pattern:** `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s`.
  - `IK` — the initiator (admin) **already knows the responder's static X25519 key**
    (distributed in client config), and sends its own static key authenticated in the
    first message. ⇒ mutual identity auth, KCI resistance, initiator identity hiding.
  - `psk2` — the shared key is mixed in, so possessing the PSK is also required.
  - Ephemeral X25519 every session ⇒ **forward secrecy**.
  - `ChaChaPoly` — ChaCha20-Poly1305 AEAD: fast in software, constant-time, no AES-NI
    dependency. AES-256-GCM selectable where hardware AES is present.
  - `BLAKE2s` — fast hashing.
- **Key material:**
  - **Shared PSK** — entered at start (passphrase prompt / key file / env), stretched
    from a passphrase with **Argon2id**. Used for the knock and mixed into the tunnel.
  - **Server static keypair** — one per server; its public key is in the client config.
  - **Client static keypair** — admin identity; its public key may be allow-listed on
    the server, authenticating the admin independent of the dynamic IP.
  - All static keys are rotatable/regenerable.
- **Hygiene:** all key material wrapped in `Zeroize`; constant-time comparisons; never
  logged; bounded wire allocations.

## Multiplexing

A single TCP connection carries many logical streams via **yamux** (flow-controlled,
battle-tested). One admin↔server tunnel therefore supports many simultaneous forwards
and many concurrent connections per forward.

**TCP-over-TCP caveat (honest):** relaying TCP streams inside one TCP tunnel means a
single loss head-of-line-blocks all multiplexed streams, and the two TCP control loops
can interact poorly under heavy loss ("TCP meltdown"). We accept this because the
data path is mandated TCP. Mitigation (chosen): a **small pool of parallel TCP
connections** per server, sharding streams across them; plus `TCP_NODELAY`, large
socket buffers, and a pure byte relay (never an inner reliability layer). One knock
authorizes the source IP, so the whole pool connects within the same window.

## Concurrency & performance

- `tokio` multi-threaded runtime; one task per stream direction; zero-copy relay with
  `bytes` and `copy_bidirectional`.
- `TCP_NODELAY` everywhere; tuned send/recv buffers; configurable yamux window.
- Per-server connection pool (default) to cut head-of-line blocking.
- Each server tunnel is independent — many servers = many independent async sessions.

## Reliability

- Per-server supervisor: on disconnect, **re-knock then reconnect** with exponential
  backoff + jitter.
- Keepalive ping/pong keeps conntrack warm and detects dead paths fast.
- yamux flow control = end-to-end backpressure; bounded channels; explicit timeouts.
- Local listeners survive tunnel flaps; admin IP changes trigger a clean re-knock.

## Server-side safety

- No reachable port until a valid knock; everything else silently dropped at the
  firewall → inert to scanners.
- **Egress allowlist is deny-all by default** (`allow = []`): the server dials only its
  own loopback on the explicitly listed ports (`allow = [22, 5432]`); it never dials any
  other host. A leaked PSK cannot turn the daemon into an open proxy or LAN pivot.
- Per-source-IP rate limiting on knocks and connections; handshake timeouts; bounded
  in-flight streams; nonce cache bounded.
- Privilege model: needs `CAP_NET_RAW` (sniff) + `CAP_NET_ADMIN` (firewall). Acquire
  capabilities, drop the rest; run as a dedicated unprivileged user under a hardened
  `systemd` sandbox.

## Platform

- **Server:** Linux. SPA needs packet capture (AF_PACKET or NFLOG via
  `libnetfilter_log`) and firewall control (**nftables** preferred, iptables fallback).
  Requires root / the two capabilities above.
- **Client:** cross-platform (Linux/macOS/Windows). Only sends a knock packet and opens
  TCP. The Windows admin box runs the client directly; the Linux SPA server is
  developed/tested under WSL2, a VM, or a remote host.

## Components

| Crate              | Kind | Responsibility                                                  |
|--------------------|------|----------------------------------------------------------------|
| `hyperion-vpn-core`    | lib  | Knock seal/open, Noise channel, yamux glue, framing, protocol, config |
| `hyperion-vpn-server`  | bin  | Knock sniffer, firewall control, tunnel listener, egress, relay |
| `hyperion-vpn-client`  | bin  | Knock sender, multi-server sessions, pool, local forwards, reconnect |

## Non-goals

- No layer-3 by default; an **optional** L3 TUN mode exists (client root) but the core
  is a layer-4 relay — not a full mesh/routing VPN.
- No P2P / NAT traversal — servers have known public IPv4; the admin always initiates.
- No UDP **data path** (a single UDP knock packet aside). QUIC is out of scope unless
  TCP HoL blocking ever proves intolerable.
