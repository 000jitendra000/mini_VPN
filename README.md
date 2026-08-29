# tiny-vpn

A small VPN built from scratch in Rust, as a learning project. Built up
incrementally:

```text
v0.1   TCP byte tunnel                          <- done
v0.2   TUN interface                            <- done
v0.3   IP packet tunnel                         <- done
v0.4   UDP transport                            <- done
v0.5   Packet framing                           <- done
v0.6   ChaCha20-Poly1305 encryption              <- done
v0.6.5 Platform-independent TUN abstraction     <- done
v0.7   PSK authentication + session establishment <- done
v0.8   Routing + NAT (this version)             <- done
v0.9   Android / Windows platform implementations
v1.0   Tiny VPN
```

## What v0.8 adds

Through v0.7, tiny-vpn was a point-to-point encrypted tunnel: packets sent
into the client's TUN interface arrived at the server's TUN interface,
and nowhere else. v0.8 turns the server into an actual **gateway**: once
a client's session is authenticated, the server can also:

- enable Linux IP forwarding,
- install NAT (MASQUERADE) so packets from the VPN subnet
  (`10.13.13.0/24`) can reach the server's outbound network, and
- restore all of that automatically (forwarding sysctl, iptables rules)
  when the server shuts down -- including on a clean Ctrl+C, not just a
  normal exit.

This is entirely optional and configurable (`[routing]` in
`config/server.toml`); with it disabled, the server behaves exactly as it
did in v0.7 (tunnel only, no Internet access via the server).

**Platform status: Linux only.** Windows and Android are explicit future
targets (see `src/tun/` and `src/routing/` for the platform-independent
boundaries already in place for them), but neither has a routing/NAT
backend implemented yet. Building this project for a non-Linux target
fails at compile time with a clear message rather than linking in a fake
backend.

## Linux requirements

- `iptables` (used for NAT and forwarding-policy rules)
- `ip` (used to auto-detect the outbound interface from the default
  route)
- Read/write access to `/proc/sys/net/ipv4/ip_forward`

## Required privileges

Creating the TUN interface and configuring routing/NAT both need
`CAP_NET_ADMIN` -- in practice, running as root (`sudo`) is the simplest
way to get this. If `iptables` isn't installed, or the process isn't
privileged enough, the server fails immediately with a clear error
message (from the underlying `iptables`/`ip` command or a permission
error) rather than silently doing nothing.

## How forwarding/NAT works

Once a client's v0.7 handshake completes and the server's TUN interface
is up, and only if `[routing] nat_enabled` is not set to `false`, the
server (`src/routing/linux.rs`):

1. Reads the current value of `/proc/sys/net/ipv4/ip_forward` and
   remembers it, then sets it to `1` if it wasn't already.
2. Determines the outbound interface: either `[routing]
   outbound_interface` from the config file, or auto-detected by parsing
   `ip route show default`.
3. Installs three `iptables` rules, each tagged `-m comment --comment
   tiny-vpn` so they're identifiable and so cleanup only ever touches
   rules tiny-vpn itself added:
   - `-t nat -A POSTROUTING -s 10.13.13.0/24 -o <iface> -j MASQUERADE`
     -- rewrites the VPN subnet's source address for outbound traffic.
   - `-A FORWARD -i tiny-tun-server -o <iface> -j ACCEPT` -- allows
     VPN-subnet traffic out.
   - `-A FORWARD -i <iface> -o tiny-tun-server -m state --state
     ESTABLISHED,RELATED -j ACCEPT` -- allows return traffic back in.

If any step fails partway through, everything already configured by that
attempt is rolled back before the error is returned -- a failed setup
never leaves the host half-configured. When the server process exits
(normally, on error, or via Ctrl+C -- see below), all three rules are
removed (in reverse order) and the forwarding sysctl is restored to
whatever it was before the server touched it.

**Ctrl+C handling:** a `SIGINT` doesn't kill this process outright the
way it would by default -- the server installs a handler that interrupts
its blocking socket read instead, so it can notice, return normally, and
run the same RAII cleanup described above. A `SIGKILL` (`kill -9`),
which cannot be caught by any process, bypasses this entirely and *will*
leave forwarding/NAT state behind; avoid it for anything but emergencies,
and clean up manually (see "Manual cleanup" below) if it happens.

The client performs no NAT and requires no special privileges beyond
what earlier versions already needed (TUN creation).

## How to start the server

```bash
sudo ./target/debug/tiny-vpn udp-server 0.0.0.0:9001
```

Optionally pass a config path (default `config/server.toml`):

```bash
sudo ./target/debug/tiny-vpn udp-server 0.0.0.0:9001 path/to/server.toml
```

To disable routing/NAT (tunnel-only, matching v0.7 behavior), set in the
config file:

```toml
[routing]
nat_enabled = false
```

## How to start the client

```bash
sudo ./target/debug/tiny-vpn udp-client <server-address>:9001
```

The client's own TUN interface gets a connected route for
`10.13.13.0/24` automatically (from the interface's address/netmask), so
traffic addressed within that subnet reaches the tunnel with no extra
configuration. **This is not yet a full default-route VPN**: the client
does not redirect all of its Internet traffic through the tunnel, only
traffic explicitly destined for the VPN subnet (or forced onto the TUN
interface, e.g. with `ping -I tiny-tun-client <destination>` for
testing). Routing *all* client traffic through the tunnel by default is
future work, not yet implemented or claimed here.

## How to test Internet connectivity

Once both sides show `session established` and the server logs `NAT/forwarding
rules installed`, from the client:

```bash
ping -I tiny-tun-client -c 3 <some external IPv4 address>
```

A successful reply demonstrates the full path: client TUN → encrypted
tunnel → server TUN → Linux forwarding → NAT → external network → NAT
reverse-translation → Linux routing → server TUN → encrypted tunnel →
client TUN.

**Known limitation of the development/test environment this project was
built in:** that sandbox's own virtualized network drops forwarded/NAT'd
traffic before it reaches the wider Internet -- confirmed by a control
test using a plain TUN device and hand-written `iptables` rules with no
tiny-vpn code involved at all, which failed identically. This is a
restriction of that specific sandboxed network (likely a hypervisor-level
anti-spoofing or source-binding check), not a defect in tiny-vpn's
routing/NAT implementation. In that environment, Stage A (client TUN →
tunnel → server TUN) and the routing/NAT *configuration* mechanism
(forwarding enabled, correct `iptables` rules installed with matching
criteria, clean rollback on shutdown) were fully, directly verified;
actual external round-trip traffic (Stage B) could not be. On a normal
Linux host without that restriction, the same code should complete Stage
B -- but that claim has not been verified end-to-end and should be
treated as untested until it is.

## How to inspect routing/NAT state

```bash
cat /proc/sys/net/ipv4/ip_forward        # should be 1 while a session is active
sudo iptables -t nat -L POSTROUTING -n -v
sudo iptables -L FORWARD -n -v
```

Every rule tiny-vpn adds carries `/* tiny-vpn */` as its comment.

## How cleanup works

See "How forwarding/NAT works" above. In short: an RAII guard
(`routing::RoutingGuard`) is held for as long as the session is active;
dropping it (on normal return, an error, or a caught `SIGINT`) removes
exactly the rules that guard's `apply()` call added and restores the
forwarding sysctl to its prior value. Nothing is ever flushed wholesale,
and nothing belonging to another application is touched.

### Manual cleanup

If a server process is killed with `SIGKILL` (or otherwise crashes before
cleanup can run), remove the leftover state by hand:

```bash
sudo iptables -t nat -D POSTROUTING -s 10.13.13.0/24 -o <iface> -m comment --comment tiny-vpn -j MASQUERADE
sudo iptables -D FORWARD -i tiny-tun-server -o <iface> -m comment --comment tiny-vpn -j ACCEPT
sudo iptables -D FORWARD -i <iface> -o tiny-tun-server -m state --state ESTABLISHED,RELATED -m comment --comment tiny-vpn -j ACCEPT
echo 0 | sudo tee /proc/sys/net/ipv4/ip_forward   # only if it wasn't enabled before you started the server
```

## Current platform limitations

- **Linux only.** No Windows (Wintun) or Android (`VpnService`) backend
  exists for TUN or for routing/NAT. Compiling for either target fails
  at compile time with an explicit message rather than pretending to
  work.
- **Single client only.** The server tracks exactly one session (in
  progress or established) at a time; a second client's handshake
  attempt is rejected while a session is already established.
- **No default-route client VPN.** Only explicit VPN-subnet traffic is
  routed through the tunnel; not a full "route everything" VPN client.
- **No persistent reconnect.** If the connection drops, both sides simply
  stop; there is no automatic retry (planned for v0.9).
- Earlier, still-accurate limitations from v0.7 remain: no intra-session
  replay window, no forward secrecy beyond one session's lifetime, and
  this project has not been audited and is not production-ready at any
  version so far.

## Usage

```text
tiny-vpn server <address>                        # v0.1: raw TCP byte tunnel server
tiny-vpn client <address>                        # v0.1: raw TCP byte tunnel client
tiny-vpn tun                                     # v0.2: standalone TUN packet dump
tiny-vpn vpn-server <address>                    # v0.3: TUN <-> TCP server
tiny-vpn vpn-client <address>                    # v0.3: TUN <-> TCP client
tiny-vpn udp-server <address> [config-path]      # v0.4-v0.8: encrypted, authenticated, gateway-capable TUN <-> UDP server
tiny-vpn udp-client <address> [config-path]      # v0.4-v0.8: encrypted, authenticated TUN <-> UDP client
```

See the module docs in `src/` for details on each mode.