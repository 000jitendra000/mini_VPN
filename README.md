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
v0.8   Linux server routing + NAT               <- done
v0.8.5 Linux client routing                     <- done
v0.9   DNS configuration / leak mitigation      <- done
v1.0   Tiny VPN
```

## What v0.8.5 adds

v0.8 made the server a gateway; v0.8.5 makes the **client** actually route
traffic into the tunnel, via `[routing]` in `config/client.toml`. Three
modes, in increasing order of how much traffic gets pulled in:

- **`disabled` (the default).** No client-side route changes at all --
  installing v0.8.5 does not by itself change any existing client's
  routing behavior. Only the VPN subnet (`10.13.13.0/24`, via the TUN
  device's own automatic connected route) reaches the tunnel, exactly as
  in v0.7/v0.8.
- **`split`.** Route only the CIDRs listed in `routes = [...]` through
  the VPN TUN device. Everything else -- including the default route --
  is completely untouched.
- **`full`.** Route *all* IPv4 traffic through the VPN TUN device, except
  the VPN server's own endpoint, which is explicitly pinned to keep using
  the client's normal pre-VPN route to it (see "The VPN server endpoint
  exception" below) -- otherwise the tunnel would try to route its own
  traffic through itself.

Both `split` and `full` are tracked by an RAII guard
(`routing::ClientRouteGuard`), the exact same pattern as the server's
NAT/forwarding guard from v0.8: dropping it (on normal return, an error,
or a caught `SIGINT`) removes exactly the routes that were added, in
reverse order.

## The VPN server endpoint exception

This is the part that matters most for `full` mode. Before adding any VPN
route, the client asks the OS how it currently reaches the VPN server
(`ip route get <server-ip>`) and remembers that exact answer -- gateway
and device, or just a device for a directly-connected/local address.
That captured route becomes a `/32` host route pinned to the server's
address, added as part of the *same* routing plan as the tunnel-wide
routes, so the VPN server's own traffic can never be routed back into the
tunnel that carries it (which would be a routing loop: TUN → encrypted
packet destined for the server → routed back into TUN → ...).

`full` mode does **not** touch, delete, or replace the literal
`0.0.0.0/0` default route entry at all. Instead, it adds two
more-specific routes -- `0.0.0.0/1` and `128.0.0.0/1` via the TUN device
-- which together cover the entire IPv4 address space and win over the
existing `/0` default route by longest-prefix match. This is the same
technique established VPN clients use (OpenVPN's `redirect-gateway`,
WireGuard's `wg-quick`) specifically because it needs no backup/restore
logic for the original default route: removing the two `/1` routes on
shutdown transparently and immediately restores the original
default-route behavior, since it was never modified.

**Simplifying assumption, documented as requested:** the VPN server
address is resolved via the same DNS resolution `UdpSocket::connect`
already performs, read back via `socket.peer_addr()`, so it reflects
whatever the OS actually resolved and connected to (handling hostnames,
non-default ports, etc. for free). Only IPv4 server endpoints are
supported for client routing; if the resolved address is IPv6, `split`/
`full` mode fail with a clear error rather than silently skipping route
configuration or routing the wrong thing. IPv6 full-tunnel routing is not
implemented and not claimed.

## What v0.8 added (server-side; unchanged in v0.8.5)

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

Creating the TUN interface and configuring routing/NAT (server) or client
routes (client) all need `CAP_NET_ADMIN` -- in practice, running as root
(`sudo`) is the simplest way to get this on both sides. If `iptables`/`ip`
isn't installed, or the process isn't privileged enough, the affected side
fails immediately with a clear error message (from the underlying command
or a permission error) rather than silently doing nothing.

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

The client performs no NAT and needs no privileges beyond what earlier
versions already needed (TUN creation), plus (as of v0.8.5, and only when
`split`/`full` routing is enabled) the ability to add/remove routes.

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

Optionally pass a config path (default `config/client.toml`):

```bash
sudo ./target/debug/tiny-vpn udp-client <server-address>:9001 path/to/client.toml
```

With `[routing] mode = "disabled"` (the default), the client's own TUN
interface gets a connected route for `10.13.13.0/24` automatically, and
that's the only route touching it -- no other traffic uses the tunnel.
Set `mode = "split"` with a `routes = [...]` list, or `mode = "full"`, to
route more; see "What v0.8.5 adds" above.

## DNS Configuration (v0.9)

v0.9 introduces portable OS-level DNS integration configured via `[dns]` in `config/client.toml`. The VPN does **not** implement a DNS server internally but will natively instruct the OS to query specified resolvers routing them robustly inside the VPN interfaces.

A basic setup:
```toml
[dns]
enabled = true
servers = ["1.1.1.1", "10.13.13.2"]
```
If disabled or absent, OS DNS configurations remain completely untouched natively as default.

**DNS Leak Limitations & Architecture**:
The `tinyvpn` engine dynamically integrates with standard OS resolvers ensuring conventional DNS requests successfully route across encrypted sessions securely. However, applications manually embedding customized recurse/encryption strategies (e.g. DoT / DoH implemented statically inside Google Chrome / Firefox bypassing traditional OS paths mapping directly to 8.8.8.8:443) inherently evade `resolvectl` bindings unless explicitly neutered externally. Android and Windows architecture mappings safely compile native interfaces structurally but currently evaluate to explicitly `Unsupported` bounds effectively rejecting OS-level modifications safely natively while pending future milestone extensions. Linux explicitly drives `resolvectl` safely unbinding seamlessly via local `DnsGuard` structures immediately terminating mappings natively.

## How to test split-tunnel routing

```bash
# config/client.toml: [routing] mode = "split", routes = ["203.0.113.0/24"]
sudo ./target/debug/tiny-vpn udp-server 0.0.0.0:9001
sudo ./target/debug/tiny-vpn udp-client 127.0.0.1:9001
ip route show 203.0.113.0/24       # should show: ... dev tiny-tun-client
ip route show default              # should be completely unchanged
ping -c 3 203.0.113.5              # ordinary ping, no -I needed -- the
                                    # route table itself sends it into the tunnel
```

## How to test full-tunnel routing (and the routing-loop check)

```bash
# config/client.toml: [routing] mode = "full"
sudo ./target/debug/tiny-vpn udp-server 0.0.0.0:9001
sudo ./target/debug/tiny-vpn udp-client <server-address>:9001

# Mandatory check: the VPN server's own endpoint must still use its
# original route, NOT the tunnel (otherwise: a routing loop).
ip route get <server-address>

# The literal default route entry must be untouched:
ip route show default

# But general traffic should now prefer the tunnel:
ip route get 8.8.8.8               # should show: ... dev tiny-tun-client
```

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

See "How forwarding/NAT works" above for the server side. In short: an
RAII guard is held for as long as the session is active; dropping it (on
normal return, an error, or a caught `SIGINT`) removes exactly what it
added and restores whatever it changed to its prior value. Nothing is
ever flushed wholesale, and nothing belonging to another application is
touched. The client-side routing guard (`routing::ClientRouteGuard`,
v0.8.5) works identically: it removes exactly the routes it added, in
reverse order, on the same triggers (normal return, error, or `SIGINT` --
the client now installs the same shutdown handler the server does, since
it also has state to clean up).

### Manual cleanup

If a server process is killed with `SIGKILL` (or otherwise crashes before
cleanup can run), remove the leftover state by hand:

```bash
sudo iptables -t nat -D POSTROUTING -s 10.13.13.0/24 -o <iface> -m comment --comment tiny-vpn -j MASQUERADE
sudo iptables -D FORWARD -i tiny-tun-server -o <iface> -m comment --comment tiny-vpn -j ACCEPT
sudo iptables -D FORWARD -i <iface> -o tiny-tun-server -m state --state ESTABLISHED,RELATED -m comment --comment tiny-vpn -j ACCEPT
echo 0 | sudo tee /proc/sys/net/ipv4/ip_forward   # only if it wasn't enabled before you started the server
```

If a **client** process is killed with `SIGKILL` while `split`/`full`
routing was active, remove the leftover routes by hand. For `split`,
remove each configured CIDR:

```bash
sudo ip route del <cidr> dev tiny-tun-client
```

For `full`, remove the two override routes and the server-endpoint
exception (substitute the actual server IP, gateway, and device from
whatever your setup used):

```bash
sudo ip route del 0.0.0.0/1 dev tiny-tun-client
sudo ip route del 128.0.0.0/1 dev tiny-tun-client
sudo ip route del <server-ip>/32 via <original-gateway> dev <original-device>
```

## Current platform limitations

- **Linux only.** No Windows (Wintun) or Android (`VpnService`) backend
  exists for TUN or for routing/NAT. Compiling for either target fails
  at compile time with an explicit message rather than pretending to
  work.
- **Single client only.** The server tracks exactly one session (in
  progress or established) at a time; a second client's handshake
  attempt is rejected while a session is already established.
- **Android / Windows DNS Unimplemented.** `v0.9` correctly abstracts DNS behaviors for native stubs, protecting execution pathways effectively, acting as a clear placeholder natively. 
- **IPv4 only for client routing.** An IPv6-resolved server endpoint
  causes `split`/`full` mode to fail with a clear error rather than
  silently misconfiguring routes.
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
tiny-vpn udp-client <address> [config-path]      # v0.4-v0.8.5: encrypted, authenticated, routing-capable TUN <-> UDP client
```

See the module docs in `src/` for details on each mode.