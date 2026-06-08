# Hyperion VPN

A fast, secure, reliable TCP tunnel for administrators to reach servers whose
firewalls drop **all** inbound traffic. The admin (client) sends an authenticated
**knock** that briefly opens the tunnel port to their current IP, connects out
directly, authenticates with a shared key, and forwards local ports to **any** service
on the server — including SSH on 22 — across **many** servers at once.

Like NetBird's "no open ports" property, but **without P2P and without WireGuard**:
Single Packet Authorization keeps the server unscannable, and the data path stays
**direct** (no relay, no broker, no hole-punching).

It is a layer-4 multiplexed port-forwarding tunnel (think `ssh -L` with many encrypted
channels), not a layer-3 packet VPN. No TUN device.

- **Stealth:** Single Packet Authorization (SPA). Firewall default-DROPs everything;
  an authenticated knock transiently opens the tunnel port to your current IP only.
  Nothing is scannable. (Server side is Linux + root: nftables + AF_PACKET/NFLOG.)
- **Crypto:** Noise Protocol via `noise-rust`
  (`Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s`) — per-server static X25519 identities,
  ephemerals for forward secrecy, ChaCha20-Poly1305 AEAD, shared key (PSK) entered at
  start. The Noise framework WireGuard is built on, but **not** WireGuard. See
  `ARCHITECTURE.md`.
- **Transport:** TCP data path, yamux multiplexing, small per-server connection pool.
- **Priorities:** security → reliability → speed.

> Status: **scaffold.** The workspace builds and the binaries run, but the tunnel,
> knock, and firewall control are not implemented yet. Work is tracked in `TODO.md`.

## Layout

```
vpn/
├─ Cargo.toml                 workspace
├─ ARCHITECTURE.md            design + decisions (read this first)
├─ TODO.md                    phased implementation plan
├─ examples/                  sample config files
└─ crates/
   ├─ hyperion-core/          knock, secure channel, mux, protocol, config
   ├─ hyperion-server/        server daemon (knock sniffer + firewall + relay)
   └─ hyperion-client/        admin client (knock, forwards, multi-server)
```

## Build & run (scaffold)

```sh
cargo build
cargo run -p hyperion-server -- --config examples/hyperion-server.toml
cargo run -p hyperion-client -- --config examples/hyperion-client.toml
```

## Intended usage (once implemented)

```sh
# server (Linux): firewall default-DROP, daemon sniffs for knocks, opens on demand
hyperion-server --config /etc/hyperion/server.toml

# admin host: knocks each server, opens the tunnel, forwards local 2201 -> serverA:22
hyperion-client --config ~/.config/hyperion/client.toml
ssh -p 2201 root@127.0.0.1     # tunnels to serverA:22
```

## Platform

- **Server:** Linux + root (`CAP_NET_RAW` + `CAP_NET_ADMIN`) — needs nftables and
  packet capture for SPA.
- **Client:** cross-platform (Linux/macOS/Windows) — only sends a knock and opens TCP.

## License

MIT OR Apache-2.0.
