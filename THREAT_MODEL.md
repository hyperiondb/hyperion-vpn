# Hyperion VPN — Threat Model

Scope: the tunnel as built (Phases 0–6) plus the SPA gate (Phase 5). This is an
engineering threat model, not a substitute for an external crypto/protocol review,
which is required before production use.

## Assets

- **Shared PSK** — entered at start; gates both the knock and the tunnel handshake.
- **Static X25519 keys** — one per server (identity) + the admin identity key.
- **Confidentiality/integrity of relayed traffic** (e.g. SSH sessions, DB protocols).
- **Reachability of the servers' service ports** — must stay unreachable to everyone
  except the authenticated admin.

## Trust boundaries

```
[admin host] --- untrusted public Internet --- [server: firewall + daemon] --- [loopback services]
```

- The admin host is trusted (holds admin key + PSK).
- The network in between is fully untrusted (active on-path attacker assumed).
- The server's loopback/LAN services are reached only via the egress allowlist.

## Adversaries & what defends against them

| Adversary capability | Defense |
|---|---|
| Internet scanner mapping open ports | SPA: firewall default-DROP; no bound port for the knock (AF_PACKET sniff) → host shows fully filtered. |
| Passive eavesdropper | Noise `IKpsk2`: X25519 ephemerals ⇒ forward secrecy; ChaCha20-Poly1305 AEAD. |
| Active on-path MITM (modify/inject) | AEAD integrity on every frame; handshake binds protocol version via prologue; tampered frames → connection drops. |
| Attacker without the PSK | Cannot complete the Noise handshake (psk2) and cannot forge a knock (PSK-derived AEAD key). |
| Stolen/leaked PSK | Still needs a valid **admin static key** (server allowlists admin pubkeys) to pass the handshake. Egress deny-all caps what a compromised tunnel can reach. |
| Stolen admin static key | Combined with the PSK, authenticates as the admin — **rotate keys**; this is the crown-jewel compromise. |
| Replayed knock | Timestamp window + bounded nonce cache reject replays; a replay only re-opens the port for an IP the attacker doesn't control. |
| Spoofed-source knock | Opens the firewall for a forged IP the attacker cannot receive from; the Noise handshake still gates the tunnel. |
| Server used as an open proxy / pivot | **Egress allowlist is deny-all by default**, and the server only ever dials its own `127.0.0.1` on the explicitly listed ports — it cannot be told to reach any other host (no LAN/internet pivot by construction). |
| Resource exhaustion via the wire | Bounded allocations: Noise frame ≤ ~16 KiB (u16 prefix), handshake msg ≤ 4 KiB, `ConnectRequest` is a fixed 2-byte port, knock fixed 44 B, replay cache capped, yamux max-streams + receive-window caps. Parsers are panic-safety tested against random input. |

## Key framing: SPA is stealth, not authentication

The port-knock is an **attack-surface-reduction** layer. A forged or replayed knock at
most opens the firewall to an IP the attacker does not control. The **cryptographic
gate is the Noise `IKpsk2` tunnel** (server static identity + admin static identity +
shared PSK). Never rely on the knock alone for security.

## Residual risks / known limitations

- **No external review yet.** The protocol composition (knock + Noise + yamux) has not
  been formally analyzed.
- **TCP-over-TCP.** Relaying TCP inside one TCP tunnel can head-of-line-block and
  interact poorly under heavy loss. Accepted per requirements; mitigated by a small
  connection pool, `TCP_NODELAY`, and a pure byte relay.
- **Knock source-IP trust.** SPA opens the port for the source IP in the knock packet;
  on networks where an attacker can both spoof and receive for that IP, the surface
  reduction weakens (the Noise gate still holds).
- **Default-drop firewall is dangerous to apply.** `print-firewall` emits a `policy
  drop` ruleset; an operator who installs it without an out-of-band recovery path can
  lock themselves out. Document and test on a console-accessible host.
- **PSK distribution** is out of band and the operator's responsibility.
- **DoS.** An attacker can still flood the tunnel port with TCP SYNs (dropped by the
  firewall) or the sniffer with junk UDP (cheap to reject, but unbounded volume).
  Per-source-IP knock rate-limiting is a TODO.

## Operational requirements

- Run the server unprivileged with only `CAP_NET_RAW` + `CAP_NET_ADMIN` (TODO: drop).
- Rotate the PSK and static keys on a schedule and on suspected compromise.
- Keep `Cargo.lock` committed; gate CI on `cargo audit` + `cargo deny`.
- Disable core dumps for the daemon (avoid key material on disk).
