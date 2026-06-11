# Hyperion VPN

A fast, secure, reliable TCP tunnel for administrators to reach servers whose firewalls
drop **all** inbound traffic. The admin (client) sends an authenticated **knock** that
briefly opens the tunnel port to its current IP, connects out **directly** (no relay,
no broker, no P2P), authenticates with a shared key, and forwards local ports to **any**
service on the server — including SSH on 22 — across **many** servers at once.

Like NetBird's "no open ports" property, but **without P2P and without WireGuard**:
Single Packet Authorization keeps the server unscannable, and the data path stays direct.

Status: **in progress**

- **Stealth:** Single Packet Authorization (SPA). The firewall default-DROPs everything;
  an authenticated knock — bound to that server's identity, so a capture is useless
  against the rest of the fleet — transiently opens the tunnel port to your current IP only.
- **Crypto:** Noise `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s` via `noise-rust` — per-server
  static X25519 identities, ephemerals for forward secrecy, ChaCha20-Poly1305 AEAD, and a
  shared key (PSK) entered at start. The Noise framework WireGuard is built on, but **not**
  WireGuard (no kernel module, no `wg`, no UDP data path).
- **Transport:** TCP, yamux multiplexing, a small self-healing per-server connection pool.
- **Priorities:** security → reliability → speed.

See [`ARCHITECTURE.md`](ARCHITECTURE.md) for the design and [`THREAT_MODEL.md`](THREAT_MODEL.md)
for the security model. **Status:** functional core (tunnel, mux, relay, pooled client,
SPA). The SPA path is implemented and type-checks for Linux but is not yet runtime-verified
on a live host, and the protocol has **not had an external review** — do not use in
production yet.

## Build

```sh
cargo build --release
# binaries: target/release/hyperion-server, target/release/hyperion-client
```

The client includes **L3 TUN mode by default** (pulls in a userspace TUN/IP stack). For a
lean client without it: `cargo build --release -p hyperion-vpn-client --no-default-features`.

## Quickstart (managed — `init` / `up` / `down`)

The fast path. Config and keys live in your **user config dir** (`%APPDATA%\hyperion` on
Windows, `~/.config/hyperion` on Linux) — generated, not hand-written. Each server is
reached at a stable **fake IP** inside the client's TUN subnet (`10.99.0.0/24`), so there
are no local ports, no route scripts, and no Linux-only socket tricks — it works on the
Windows admin box.

**1. Admin (Windows) — initialize.** Prints your admin public key and the shared salt:
```sh
hyperion-client init
```

**2. Each Linux server — initialize** with the admin key + salt from step 1, then start it.
`up` runs the daemon in the background; the firewall stays a separate, deliberate step:
```sh
hyperion-server init --salt <SALT> --admin-key <ADMIN_PUBKEY> --allow 22,5432
#   prints the server's public key — copy it for step 3
hyperion-server print-firewall --tunnel-port 8443 | sudo nft -f -   # review first (default-DROP)
sudo hyperion-server up
```

**3. Admin — add each server by its public key** (auto-assigns a fake IP), then go up:
```sh
hyperion-client add-server web1 203.0.113.10:8443 <SERVER_PUBKEY>
hyperion-client up            # run elevated; needs wintun.dll alongside the exe on Windows
hyperion-client status        # shows the server → fake-IP table
```

**4. Use it** — reach each server at its fake IP with any app:
```sh
ssh user@10.99.0.10
hyperion-client down          # stop the tunnel
```

Both sides take `up` / `down` / `status`; `--foreground` runs in the current shell instead
of detaching. The SPA firewall is **never** applied automatically — apply and remove it
yourself (it is default-DROP and can lock you out).

## Quickstart (local loopback, no SPA — low-level)

Proves the tunnel end-to-end on one machine. Run a throwaway service to reach (here, an
SSH server on 22, or any TCP service).

1. **Generate keys.**
   ```sh
   hyperion-server keygen --out server.key      # prints the server PUBLIC key
   hyperion-client keygen --out admin.key       # prints the admin  PUBLIC key
   ```

2. **`server.toml`** — note the admin public key in the allowlist, egress limited to the
   one service you want to reach:
   ```toml
   listen = "127.0.0.1:8443"

   [key]
   source = "passphrase"
   salt   = "change-me-shared-salt"      # same on client and server

   [identity]
   static_key_file = "server.key"
   admin_pubkeys   = ["<ADMIN_PUBLIC_KEY>"]

   [egress]
   allow = [22] # deny-all by default; list each port (server dials its own loopback)
   ```

3. **`client.toml`** — forward a local port to the server's service:
   ```toml
   admin_static_key_file = "admin.key"

   [key]
   source = "passphrase"
   salt   = "change-me-shared-salt"      # MUST match the server

   [[server]]
   name          = "srvA"
   addr          = "127.0.0.1:8443"
   server_pubkey = "<SERVER_PUBLIC_KEY>"

   [[forward]]
   local       = "127.0.0.1:2201"
   server      = "srvA"
   remote_port = 22
   ```

4. **Run** (each prompts once, no-echo, for the shared passphrase):
   ```sh
   hyperion-server run --config server.toml
   hyperion-client run --config client.toml
   ```

5. **Use it.** This simple (no-root) mode exposes each service on a **local port** you
   pick; for the real `<server-ip>:<port>` with no local ports, use **L3 TUN mode**
   (below) instead.
   ```sh
   hyperion-client doctor --config client.toml   # check knock + handshake first
   ssh -p 2201 user@127.0.0.1                     # 2201 is the chosen local port → server's :22
   ```

Ad-hoc forwards without editing config: `hyperion-client run -L 2201:srvA:22`.

## Production (Linux server + SPA)

The SPA gate needs Linux, root (`CAP_NET_RAW` + `CAP_NET_ADMIN`), and `nftables`.

1. **Install the base firewall ruleset** (default-drop; only conntrack + loopback +
   knock-opened IPs may reach the tunnel port). Generate and review it, then apply on a
   host you have console/out-of-band access to:
   ```sh
   hyperion-server print-firewall --tunnel-port 8443 | sudo nft -f -
   ```
   > WARNING: this sets `policy drop` on input. Ensure you have a recovery path before
   > applying it remotely, or you can lock yourself out.

2. **Enable SPA** in `server.toml`:
   ```toml
   listen = "0.0.0.0:8443"
   [knock]
   enabled     = true
   window_secs = 30
   [firewall]
   table    = "hyperion"
   set      = "knock_allow"
   ttl_secs = 60
   ```

3. **Enable knock** in `client.toml` (knocks each server before dialing):
   ```toml
   [knock]
   enabled = true
   ```

4. Run the server as root (or with the two capabilities). On a valid knock it adds the
   admin's source IP to the `knock_allow` set with a 60 s timeout; the client connects
   within that window and the established tunnel survives via conntrack.

## L3 TUN mode (transparent — Linux/root) — best for many ports/servers

For **many ports across many servers**, this is the simple path: the client lists **only
the servers** (no `[[forward]]` blocks at all) and you reach any `<server-ip>:<port>`
directly. The server's egress allowlist still caps which ports. Built **by default**
(`--no-default-features` for the lean local-forward-only build).

- Needs **root / `CAP_NET_ADMIN`** on the client and a TUN driver (Linux; Windows via
  Wintun, but the routing/bypass below is **Linux-only**). **Status: compiles for Linux +
  Windows; not yet runtime-verified.**

`client.toml` for e.g. 4 servers (10 ports each) — *just the servers*:

```toml
admin_static_key_file = "admin.key"
[key]
source = "passphrase"
salt = "change-me-shared-salt"

[[server]]
name = "srvA"
addr = "203.0.113.10:8443"
server_pubkey = "<SRVA_PUBKEY>"
# …srvB / srvC / srvD the same — and NO [[forward]] blocks
```

Each `server.toml` lists its ports once: `[egress] allow = [22, 80, 443, 5432, …]`.

Run it (two steps — the client marks its own sockets with `SO_MARK` automatically):

```sh
# 1. start the tunnels + the hyperion0 TUN device
sudo hyperion-client tun --config client.toml

# 2. install routing: route each server IP via the tun, but keep the tunnel's own
#    (marked) sockets on the physical route so it can't loop through itself
hyperion-client print-routes --config client.toml | sudo sh
#    tear down later: hyperion-client print-routes --config client.toml --down | sudo sh
```

Then reach everything at its **real address** — no local ports, any app:

```sh
ssh user@203.0.113.10
curl http://203.0.113.11:8080
psql -h 203.0.113.12 -p 5432
```

Notes: TCP only (UDP dropped). On **Windows** the TUN device works but `SO_MARK` + `ip
rule` don't — that socket-bypass is a TODO, so run the **TUN client on Linux** (your
Windows box can still use the lean local-forward build).

## CLI reference

Config defaults to the user config dir when `--config` is omitted (`%APPDATA%\hyperion` /
`~/.config/hyperion`); override the whole dir with the `HYPERION_HOME` env var.

**hyperion-server**
- `init --salt <s> --admin-key <pk> [--allow 22,5432] [--listen <a:p>] [--force]` — generate
  the server key + config in the user config dir.
- `up [--foreground]` / `down` / `status` — start (background) / stop / inspect the daemon.
- `run [--config <file>]` — foreground: load config, (Linux) start the SPA sniffer, listen, relay.
- `keygen [--out <file>]` — generate a server static X25519 keypair.
- `print-firewall --tunnel-port <p> [--table <t>] [--set <s>]` — emit the base nft ruleset.

**hyperion-client**
- `init [--force]` — generate the admin key + config; prints the admin pubkey + shared salt.
- `add-server <name> <host:port> <server_pubkey>` / `rm-server <name>` / `ls` — manage servers
  (each gets a stable fake IP); no hand-editing.
- `up [--foreground]` / `down` / `status` — start (background) / stop / inspect the fake-IP tunnel.
- `run [--config <file>] [-L lport:server:rport ...]` — foreground local-port forwards.
- `keygen [--out <file>]` — generate the admin static keypair.
- `doctor [--config <file>]` — knock + handshake against every server; no forwarding.
- `tun --config <file> [--tun-addr <ip>] [--prefix <n>] [--mtu <n>]` — L3 TUN mode
  (requires the `tun` build feature + root; see *L3 TUN mode* above).
- `print-routes --config <file> [--dev <name>] [--mark <n>] [--table <n>] [--down]` —
  emit the `ip route`/`ip rule` commands to route server IPs via the TUN (pipe to `sh`).

Set `RUST_LOG=info` (or `debug`) for logs.

## Configuration reference

**Shared key (`[key]`)** — `source` is one of:
- `passphrase` — `salt` required; reads `passphrase_env` or prompts (no-echo); Argon2id.
- `env` — base64 PSK in `env_var`.
- `file` — base64 PSK in `file` (server only).
- `value` — inline base64 PSK (discouraged).

The client `[key]` is the fleet default; a `[[server]]` may override with `key_env` /
`key_value`. The PSK and `salt` must be identical on both ends.

**Identity** — per-server static keypair (`server keygen`); the public key goes in the
client's `server_pubkey`. The admin keypair (`client keygen`); its public key goes in the
server's `identity.admin_pubkeys`. The server rejects any peer whose static key is not
allow-listed, independent of the (dynamic) source IP.

**Egress (server)** — `allow` is **deny-all by default** and is a list of **port
numbers** (e.g. `allow = [22, 5432]`). The server only ever dials its own loopback
(`127.0.0.1:<port>`), so no host is configured; this caps what a leaked PSK can reach.

## Operations

- **Key rotation:** regenerate server/admin keypairs and rotate the PSK on a schedule and
  on suspected compromise. Update `admin_pubkeys` / `server_pubkey` accordingly.
- **Egress hygiene:** keep the allowlist minimal (loopback services only, where possible).
- **Knock window:** `window_secs` bounds replay/clock-skew; keep it tight (≈30 s) and run
  NTP on both ends.
- **Keepalive:** tunnels use TCP keepalive (20 s idle) to keep conntrack warm; the client
  pool reconnects with backoff (and re-knocks) on any drop.

## Troubleshooting

- **`doctor` says connection refused / timed out:** server not running, wrong `addr`, or
  (with SPA) the knock didn't open the port — check the server log for `knock accepted`.
- **Knock not accepted:** PSK/`salt` mismatch, clock skew beyond `window_secs`, or the
  sniffer isn't running (Linux + root required; non-Linux logs a warning and skips SPA).
- **Locked out after `nft -f`:** the base ruleset is default-drop — recover via console and
  flush the table.
- **Slow/stalls under heavy loss:** inherent TCP-over-TCP head-of-line blocking; raise the
  per-server `pool_size` and ensure `TCP_NODELAY` paths (default). See `THREAT_MODEL.md`.
- **Forward fails with denied/unreachable:** the target isn't in the server `[egress]`
  allowlist, or nothing is listening on it.

## Platform

- **Server:** Linux + root (`CAP_NET_RAW` + `CAP_NET_ADMIN`) for SPA (nftables + AF_PACKET).
  Without SPA the relay runs anywhere, but then the tunnel port must be reachable.
- **Client:** cross-platform (Linux/macOS/Windows) — only sends a knock and opens TCP.

## License

GPL-3.0-or-later.
