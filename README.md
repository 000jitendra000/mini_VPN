# tiny-vpn

A small VPN built from scratch in Rust, as a learning project. Built up
incrementally:

```text
v0.1   TCP byte tunnel          <- done
v0.2   TUN interface            <- done (this version)
v0.3   IP packet tunnel
v0.4   UDP transport
v0.5   Packet framing
v0.6   Encryption
v0.7   Authentication
v0.8   Routing + NAT
v0.9   Persistent server + reconnect
v1.0   Tiny VPN
```

## Usage

```text
tiny-vpn server <address>   # v0.1: run the TCP tunnel server
tiny-vpn client <address>   # v0.1: run the TCP tunnel client
tiny-vpn tun                # v0.2: create a TUN interface and print packets
```

See the module docs in `src/` for details on each mode.