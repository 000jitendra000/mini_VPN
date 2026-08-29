//! TCP byte-tunnel server (v0.1) and VPN server (v0.3, extended in v0.4
//! with UDP transport, in v0.6 with encryption, and in v0.7 with a
//! PSK-authenticated handshake and per-session keys).
//!
//! `run()` is the original v0.1 mode: it accepts one client connection at
//! a time and relays raw bytes between the tunnel and the client itself,
//! since there's no second endpoint yet in v0.1.
//!
//! `run_vpn()` is v0.3: it accepts one client, creates a TUN interface,
//! and relays raw IP packets between the TUN device and a TCP connection,
//! in both directions, concurrently.
//!
//! `run_udp_vpn()` is v0.4/v0.6/v0.7/v0.8: UDP transport, encrypted, and
//! (as of v0.7) session-based: the server no longer trusts a peer just
//! because a packet from them decrypted correctly under a static key.
//! Instead, a peer must first complete a PSK-authenticated handshake
//! (`HandshakeInit` -> `HandshakeResponse` -> `HandshakeConfirm`; see
//! `protocol.rs`/`crypto.rs`) that derives fresh, per-session encryption
//! keys before any `EncryptedData` from them is accepted. Only one
//! session (in progress or established) is tracked at a time -- there is
//! still no client table.
//!
//! As of v0.8, once a session is established (and the TUN interface is
//! up), the server also configures the host to act as a gateway for the
//! VPN subnet -- IP forwarding and NAT/MASQUERADE, via `routing.rs` --
//! before it starts relaying data. That configuration is held behind an
//! RAII guard, so it's automatically undone (forwarding sysctl restored,
//! NAT/forward rules removed) when the server shuts down, whether that's
//! because of an error or a clean Ctrl+C (SIGINT is specifically handled
//! so this cleanup runs -- see `routing::install_shutdown_handler`).
//!
//! The handshake/session state machine (`ServerSession`,
//! `handle_incoming_datagram`) is written as a pure function with no
//! socket or TUN I/O, specifically so it can be unit tested directly (see
//! the tests below) without needing a real network or a root-owned TUN
//! device.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::{Arc, Mutex};
use std::thread;

use crate::config;
use crate::crypto::{self, Cipher};
use crate::protocol;
use crate::routing;
use crate::transport;
use crate::tun;

/// Load and parse the pre-shared key from `config_path`. Wraps config/key
/// errors as `io::Error` so callers can use `?` alongside the rest of
/// this module's I/O.
fn load_psk(config_path: &str) -> io::Result<[u8; crypto::KEY_SIZE]> {
    let key_hex = config::load_crypto_key_hex(config_path)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    crypto::parse_key_hex(&key_hex).map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
}

/// Bind to `address` and serve one client connection at a time, forever.
pub fn run(address: &str) -> io::Result<()> {
    let listener = TcpListener::bind(address)?;
    println!("Listening on {address}");

    loop {
        match listener.accept() {
            Ok((stream, peer)) => {
                println!("Client connected: {peer}");
                if let Err(e) = handle_client(stream) {
                    eprintln!("Connection error ({peer}): {e}");
                }
                println!("Client disconnected: {peer}");
            }
            Err(e) => {
                eprintln!("Failed to accept connection: {e}");
                // Keep the server alive; try to accept the next connection.
            }
        }
    }
}

/// Relay bytes read from `stream` back to the same `stream`.
fn handle_client(mut stream: TcpStream) -> io::Result<()> {
    let mut read_stream = stream.try_clone()?;
    let mut buf = [0u8; 4096];

    loop {
        let n = read_stream.read(&mut buf)?;
        if n == 0 {
            // Client closed the connection.
            return Ok(());
        }
        stream.write_all(&buf[..n])?;
    }
}

/// Listen on `address`, accept a single VPN client, create the server TUN
/// interface, and relay raw IP packets between the TUN device and the TCP
/// connection in both directions, concurrently.
///
/// See `tun::relay_tun_to_writer` / `tun::relay_reader_to_tun` for the
/// important caveat that v0.3 does not yet frame packets on the wire.
pub fn run_vpn(address: &str) -> io::Result<()> {
    let listener = TcpListener::bind(address)?;
    println!("VPN server listening on {address}");

    let (stream, peer) = listener.accept()?;
    println!("Client connected: {peer}");

    let tun_device = tun::create_device(
        tun::SERVER_TUN_NAME,
        tun::SERVER_TUN_ADDRESS,
        tun::VPN_TUN_NETMASK,
    )?;
    let (a, b, c, d) = tun::SERVER_TUN_ADDRESS;
    println!(
        "Server TUN '{}' is up at {a}.{b}.{c}.{d}/24",
        tun::SERVER_TUN_NAME
    );

    let (tun_reader, tun_writer) = tun_device.split();
    let tcp_upload = stream.try_clone()?;
    let tcp_download = stream;

    // Thread: TUN -> TCP (packets captured from the server's TUN device
    // are sent to the client).
    let upload_thread = thread::spawn(move || {
        tun::relay_tun_to_writer(tun_reader, tcp_upload, "Server")
    });

    // Main thread: TCP -> TUN (packets arriving from the client are
    // written into the server's TUN device).
    let download_result = tun::relay_reader_to_tun(tcp_download, tun_writer, "Server");

    match upload_thread.join() {
        Ok(Ok(())) => {}
        Ok(Err(e)) => eprintln!("Server TUN->TCP error: {e}"),
        Err(_) => eprintln!("Server TUN->TCP thread panicked"),
    }

    download_result
}

/// Bind a UDP socket on `bind_address`, load the pre-shared key from
/// `config_path`, and wait for a peer to complete the PSK-authenticated
/// handshake (see the module docs and `handle_incoming_datagram`) before
/// creating the server TUN interface or relaying anything.
///
/// UDP is connectionless, so there's no "accept" step in the TCP sense;
/// instead, the server's receive loop doubles as the handshake responder.
/// Only one client (in progress or established) is supported at a time.
/// The TUN interface and the TUN->UDP upload thread are created only
/// once `handle_incoming_datagram` reports `ServerAction::EstablishSession`
/// -- see `run_server_receive_loop`.
pub fn run_udp_vpn(bind_address: &str, config_path: &str) -> io::Result<()> {
    let psk = load_psk(config_path)?;
    let routing_settings = config::load_routing_settings(config_path)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

    // Safe to install unconditionally: this only affects process signal
    // handling (letting a blocking recv return with Interrupted on
    // Ctrl+C so our RAII cleanup runs), not any networking state, and is
    // just as valid when routing/NAT is disabled (nothing to clean up
    // beyond the TUN device, which the OS removes on process exit
    // regardless).
    routing::install_shutdown_handler();

    let socket = UdpSocket::bind(bind_address)?;
    println!("VPN UDP server listening on {bind_address}");

    if routing_settings.nat_enabled {
        println!(
            "Server: routing/NAT will be configured once a session is established \
             (outbound interface: {})",
            routing_settings
                .outbound_interface
                .as_deref()
                .unwrap_or("auto-detect")
        );
    } else {
        println!("Server: routing/NAT is disabled (tunnel-only mode; no Internet access via this server)");
    }

    // Shared with the upload thread once it exists: the currently
    // established (peer, send cipher). Created up front (empty) since
    // `run_server_receive_loop` needs somewhere to put it once a session
    // is established; the upload thread itself isn't spawned until then.
    let established: Arc<Mutex<transport::EstablishedPeer>> = Arc::new(Mutex::new(None));

    run_server_receive_loop(&socket, &established, &psk, &routing_settings)
}

/// The server's session state machine. Exactly one session (in progress
/// or established) is tracked at a time -- there is no per-peer table,
/// consistent with this project's one-client-only design through v0.7.
#[derive(Debug)]
enum ServerSession {
    /// No client has started a handshake yet (or the last attempt failed
    /// authentication and was reset -- see the `Confirm` handling below).
    NoSession,
    /// A `HandshakeInit` was received from `peer` and a `HandshakeResponse`
    /// was sent back; waiting for that same peer's `HandshakeConfirm`.
    HandshakeInProgress {
        peer: SocketAddr,
        client_random: [u8; crypto::RANDOM_SIZE],
        server_random: [u8; crypto::RANDOM_SIZE],
    },
    /// Handshake completed and authenticated. Only `peer` may send
    /// `EncryptedData`, decrypted with `client_to_server`.
    Established {
        peer: SocketAddr,
        client_to_server: Arc<Cipher>,
    },
}

/// What the caller of `handle_incoming_datagram` should do in response to
/// one received UDP datagram. Kept free of any actual socket/TUN I/O so
/// the server's protocol/session logic is unit-testable without a real
/// network or TUN device.
#[derive(Debug)]
enum ServerAction {
    /// Send this already-encoded handshake message back to `SocketAddr`.
    Reply(SocketAddr, Vec<u8>),
    /// A session was just established: the upload side's shared
    /// `EstablishedPeer` cell should be set to this (peer, send cipher).
    EstablishSession(SocketAddr, Arc<Cipher>),
    /// Write this decrypted, decoded IP packet payload to the TUN device.
    WriteToTun(Vec<u8>),
    /// Nothing to do (message dropped; any logging already happened
    /// inside `handle_incoming_datagram`).
    Drop,
}

/// Decide what to do with one datagram (`bytes`, from `sender`) given the
/// server's current session state, mutating `session` as needed. This is
/// the entire v0.7 server-side protocol: handshake responder, handshake
/// authentication, and the gate that decides whether `EncryptedData` is
/// accepted at all.
///
/// Deliberately pure (no I/O): easy to unit test, and keeps `run_server_
/// receive_loop` a thin wrapper that only performs the I/O this function
/// decides on.
fn handle_incoming_datagram(
    session: &mut ServerSession,
    sender: SocketAddr,
    bytes: &[u8],
    psk: &[u8; crypto::KEY_SIZE],
) -> ServerAction {
    let message = match protocol::UdpMessage::decode(bytes) {
        Ok(message) => message,
        Err(e) => {
            eprintln!("Server: dropping malformed datagram from {sender} ({} bytes): {e}", bytes.len());
            return ServerAction::Drop;
        }
    };

    match message {
        protocol::UdpMessage::Handshake(protocol::HandshakeMessage::Init {
            version,
            client_random,
        }) => {
            if version != protocol::HANDSHAKE_VERSION {
                println!("Server: dropping HandshakeInit from {sender}: unsupported version {version}");
                return ServerAction::Drop;
            }
            // Reject new handshake attempts while a session is already
            // Established -- see the module docs: one session at a time,
            // no multi-client support. The existing session must end
            // (currently: the server process must be restarted) before a
            // new client can connect.
            if matches!(session, ServerSession::Established { .. }) {
                println!("Server: dropping HandshakeInit from {sender}: a session is already established");
                return ServerAction::Drop;
            }

            println!("Server: handshake received from {sender}");
            let server_random = crypto::generate_random();
            let tag = crypto::handshake_tag(
                protocol::MSG_TYPE_HANDSHAKE_RESPONSE,
                protocol::HANDSHAKE_VERSION,
                psk,
                &client_random,
                &server_random,
            );
            let response = protocol::HandshakeMessage::Response {
                version: protocol::HANDSHAKE_VERSION,
                server_random,
                tag,
            };

            *session = ServerSession::HandshakeInProgress {
                peer: sender,
                client_random,
                server_random,
            };
            ServerAction::Reply(sender, response.encode())
        }

        protocol::UdpMessage::Handshake(protocol::HandshakeMessage::Confirm { tag }) => {
            let (peer, client_random, server_random) = match session {
                ServerSession::HandshakeInProgress {
                    peer,
                    client_random,
                    server_random,
                } if *peer == sender => (*peer, *client_random, *server_random),
                _ => {
                    println!("Server: dropping HandshakeConfirm from {sender}: no matching in-progress handshake");
                    return ServerAction::Drop;
                }
            };

            let expected = crypto::handshake_tag(
                protocol::MSG_TYPE_HANDSHAKE_CONFIRM,
                protocol::HANDSHAKE_VERSION,
                psk,
                &client_random,
                &server_random,
            );
            if !crypto::verify_tag(&expected, &tag) {
                println!("Server: handshake authentication failed for {sender}");
                // Drop back to NoSession rather than leaving a
                // half-authenticated attempt around indefinitely.
                *session = ServerSession::NoSession;
                return ServerAction::Drop;
            }

            let session_ciphers = crypto::derive_session_ciphers(psk, &client_random, &server_random);
            println!("Server: handshake authenticated");
            println!(
                "Server: session established with {peer} (fingerprints c->s={} s->c={})",
                session_ciphers.client_to_server_fingerprint,
                session_ciphers.server_to_client_fingerprint
            );

            let client_to_server = Arc::new(session_ciphers.client_to_server);
            let server_to_client = Arc::new(session_ciphers.server_to_client);
            *session = ServerSession::Established {
                peer,
                client_to_server: Arc::clone(&client_to_server),
            };
            ServerAction::EstablishSession(peer, server_to_client)
        }

        protocol::UdpMessage::Handshake(protocol::HandshakeMessage::Response { .. }) => {
            // The server never receives its own message type.
            println!("Server: dropping unexpected HandshakeResponse from {sender}");
            ServerAction::Drop
        }

        protocol::UdpMessage::EncryptedData(body) => {
            let (established_peer, client_to_server) = match session {
                ServerSession::Established {
                    peer,
                    client_to_server,
                } if *peer == sender => (*peer, Arc::clone(client_to_server)),
                _ => {
                    println!(
                        "Server: dropped {} bytes from {sender}: no established session for this peer",
                        bytes.len()
                    );
                    return ServerAction::Drop;
                }
            };
            let _ = established_peer;

            println!("Server: UDP -> DECRYPT: {} bytes", bytes.len());
            let plaintext = match client_to_server.decrypt(crypto::Direction::ClientToServer, body) {
                Ok(plaintext) => plaintext,
                Err(e) => {
                    println!("Server: dropped packet: {e}");
                    return ServerAction::Drop;
                }
            };
            println!("Server: DECRYPT -> FRAME: {} bytes", plaintext.len());

            match protocol::Frame::decode(&plaintext) {
                Ok(frame) => {
                    println!("Server: FRAME -> TUN: {} byte payload", frame.payload.len());
                    ServerAction::WriteToTun(frame.payload)
                }
                Err(e) => {
                    eprintln!(
                        "Server: dropping malformed frame ({} bytes): {e}",
                        plaintext.len()
                    );
                    ServerAction::Drop
                }
            }
        }
    }
}

/// The server's UDP receive loop: read a datagram, decide what to do via
/// `handle_incoming_datagram`, then perform the resulting I/O.
///
/// The TUN interface, the TUN->UDP upload thread, and (if
/// `routing_settings.nat_enabled`) the host's forwarding/NAT
/// configuration do not exist until the handshake completes: this loop
/// creates all three, right here, the first (and only, given the
/// one-client-only policy) time `handle_incoming_datagram` returns
/// `ServerAction::EstablishSession`. Before that point, only handshake
/// messages are ever handled -- there is no TUN device, no upload
/// thread, and no routing/NAT state yet to route data through.
///
/// A `SIGINT` (Ctrl+C) interrupts the blocking `recv_from` below with
/// `io::ErrorKind::Interrupted` (see `routing::install_shutdown_handler`)
/// rather than killing the process outright, so this function can notice
/// it, return `Ok(())`, and let its local RAII guards (`routing_guard`,
/// and the upload-thread join below) run their cleanup.
fn run_server_receive_loop(
    socket: &UdpSocket,
    established: &Arc<Mutex<transport::EstablishedPeer>>,
    psk: &[u8; crypto::KEY_SIZE],
    routing_settings: &config::RoutingSettings,
) -> io::Result<()> {
    let mut session = ServerSession::NoSession;
    let mut buf = [0u8; transport::UDP_RECV_BUFFER_SIZE];

    // None of these exist until the handshake completes (see
    // `ServerAction::EstablishSession` below). `routing_guard` is only
    // ever set if `routing_settings.nat_enabled`; dropping it (when this
    // function returns) restores the host's forwarding/NAT state.
    let mut tun_writer: Option<tun::PacketWriter> = None;
    let mut upload_thread: Option<thread::JoinHandle<io::Result<()>>> = None;
    let mut routing_guard: Option<routing::RoutingGuard> = None;

    let loop_result: io::Result<()> = (|| loop {
        let (n, sender) = match socket.recv_from(&mut buf) {
            Ok(v) => v,
            Err(e) if e.kind() == io::ErrorKind::Interrupted && routing::shutdown_requested() => {
                println!("Server: shutdown requested, cleaning up");
                return Ok(());
            }
            // A spurious/unrelated EINTR (not our shutdown signal): just
            // retry the read instead of treating it as a hard error.
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        let action = handle_incoming_datagram(&mut session, sender, &buf[..n], psk);

        match action {
            ServerAction::Reply(addr, bytes) => {
                socket.send_to(&bytes, addr)?;
            }
            ServerAction::EstablishSession(peer, server_to_client) => {
                *established.lock().unwrap() = Some((peer, server_to_client));

                // Only now -- after the handshake has fully authenticated
                // this peer -- do we create the TUN interface and start
                // relaying. If TUN creation fails here, that failure
                // propagates out of this loop exactly like any other I/O
                // error below.
                let tun_device = tun::create_device(
                    tun::SERVER_TUN_NAME,
                    tun::SERVER_TUN_ADDRESS,
                    tun::VPN_TUN_NETMASK,
                )?;
                let (a, b, c, d) = tun::SERVER_TUN_ADDRESS;
                println!(
                    "Server TUN '{}' is up at {a}.{b}.{c}.{d}/24",
                    tun::SERVER_TUN_NAME
                );

                // Only now -- after the TUN interface exists -- do we
                // configure the host as a gateway for the VPN subnet.
                // Not enabling forwarding/NAT before the authenticated
                // session exists (or before its TUN interface exists) is
                // deliberate: there is nothing to forward or NAT for
                // until this point anyway, and configuring it earlier
                // would have no VPN-side counterpart to justify it.
                if routing_settings.nat_enabled {
                    let routing_config = routing::RoutingConfig {
                        vpn_subnet: routing::cidr_from_address_and_netmask(
                            tun::SERVER_TUN_ADDRESS,
                            tun::VPN_TUN_NETMASK,
                        ),
                        tun_interface: tun::SERVER_TUN_NAME.to_string(),
                        outbound_interface: routing_settings.outbound_interface.clone(),
                    };
                    routing_guard = Some(routing::apply(&routing_config)?);
                }

                let (tun_reader, writer) = tun_device.split();
                tun_writer = Some(writer);

                let upload_socket = socket.try_clone()?;
                let upload_established = Arc::clone(established);
                upload_thread = Some(thread::spawn(move || {
                    transport::relay_tun_to_udp_established(
                        tun_reader,
                        &upload_socket,
                        "Server",
                        upload_established,
                        crypto::Direction::ServerToClient,
                    )
                }));
            }
            ServerAction::WriteToTun(payload) => match &mut tun_writer {
                Some(writer) => writer.write_all(&payload)?,
                None => {
                    // Should not happen: `handle_incoming_datagram` only
                    // returns `WriteToTun` once `session` is
                    // `Established`, which is only reached via the
                    // `EstablishSession` arm above, which always creates
                    // `tun_writer` before returning. Defensive-only.
                    eprintln!("Server: dropping decrypted packet: TUN not ready yet");
                }
            },
            ServerAction::Drop => {}
        }
    })();

    if let Some(handle) = upload_thread {
        if loop_result.is_ok() {
            // Clean shutdown (the only way `loop_result` is `Ok(())` is
            // via the SIGINT path above): deliberately do NOT block
            // waiting for the upload thread here. A signal delivered to
            // this process is handled by whichever thread the kernel
            // picks -- not necessarily the upload thread, which is
            // blocked in its own TUN read -- so `handle.join()` could
            // hang indefinitely, and with it, the routing/NAT cleanup
            // below that a hung shutdown would never reach. The process
            // is about to exit right after this function returns; the OS
            // reclaims the abandoned thread's TUN fd and UDP socket the
            // same way it always has when this project's processes exit.
            drop(handle);
        } else {
            match handle.join() {
                Ok(Ok(())) => {}
                Ok(Err(e)) => eprintln!("Server TUN->UDP error: {e}"),
                Err(_) => eprintln!("Server TUN->UDP thread panicked"),
            }
        }
    }

    // `routing_guard` drops here (restoring forwarding/NAT state) as this
    // function returns, whether `loop_result` is `Ok` or `Err`.
    drop(routing_guard);

    loop_result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_psk(byte: u8) -> [u8; crypto::KEY_SIZE] {
        [byte; crypto::KEY_SIZE]
    }

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    /// Drive a full, valid handshake against a fresh `ServerSession`,
    /// returning the session (now `Established`) and the derived
    /// `client_to_server`/`server_to_client` ciphers the "client side"
    /// would have computed for itself. Used as a helper by several tests
    /// below, and doubles as test #1: "valid handshake succeeds with
    /// matching PSK".
    fn run_valid_handshake(psk: &[u8; crypto::KEY_SIZE], peer: SocketAddr) -> (ServerSession, crypto::SessionCiphers) {
        let mut session = ServerSession::NoSession;
        let client_random = crypto::generate_random();

        let init = protocol::HandshakeMessage::Init {
            version: protocol::HANDSHAKE_VERSION,
            client_random,
        }
        .encode();
        let action = handle_incoming_datagram(&mut session, peer, &init, psk);
        let server_random = match action {
            ServerAction::Reply(addr, bytes) => {
                assert_eq!(addr, peer);
                match protocol::HandshakeMessage::decode(&bytes).unwrap() {
                    protocol::HandshakeMessage::Response { server_random, .. } => server_random,
                    other => panic!("expected Response, got {other:?}"),
                }
            }
            other => panic!("expected Reply, got {other:?}"),
        };

        let client_tag = crypto::handshake_tag(
            protocol::MSG_TYPE_HANDSHAKE_CONFIRM,
            protocol::HANDSHAKE_VERSION,
            psk,
            &client_random,
            &server_random,
        );
        let confirm = protocol::HandshakeMessage::Confirm { tag: client_tag }.encode();
        let action = handle_incoming_datagram(&mut session, peer, &confirm, psk);
        assert!(matches!(action, ServerAction::EstablishSession(p, _) if p == peer));
        assert!(matches!(session, ServerSession::Established { .. }));

        let session_ciphers = crypto::derive_session_ciphers(psk, &client_random, &server_random);
        (session, session_ciphers)
    }

    #[test]
    fn valid_handshake_succeeds_with_matching_psk() {
        let psk = test_psk(0x01);
        let (session, _) = run_valid_handshake(&psk, addr(1));
        assert!(matches!(session, ServerSession::Established { .. }));
    }

    #[test]
    fn wrong_psk_fails_authentication() {
        let server_psk = test_psk(0x01);
        let client_psk = test_psk(0x02);
        let peer = addr(2);
        let mut session = ServerSession::NoSession;

        let client_random = crypto::generate_random();
        let init = protocol::HandshakeMessage::Init {
            version: protocol::HANDSHAKE_VERSION,
            client_random,
        }
        .encode();
        let action = handle_incoming_datagram(&mut session, peer, &init, &server_psk);
        let server_random = match action {
            ServerAction::Reply(_, bytes) => match protocol::HandshakeMessage::decode(&bytes).unwrap() {
                protocol::HandshakeMessage::Response { server_random, .. } => server_random,
                other => panic!("expected Response, got {other:?}"),
            },
            other => panic!("expected Reply, got {other:?}"),
        };

        // Client (wrongly) uses its own, different PSK to compute the tag.
        let bad_tag = crypto::handshake_tag(
            protocol::MSG_TYPE_HANDSHAKE_CONFIRM,
            protocol::HANDSHAKE_VERSION,
            &client_psk,
            &client_random,
            &server_random,
        );
        let confirm = protocol::HandshakeMessage::Confirm { tag: bad_tag }.encode();
        let action = handle_incoming_datagram(&mut session, peer, &confirm, &server_psk);
        assert!(matches!(action, ServerAction::Drop));
        assert!(matches!(session, ServerSession::NoSession));
    }

    #[test]
    fn modified_client_random_is_rejected() {
        // The server computed its Response tag over the client_random it
        // actually received; if an attacker changes the client_random
        // used to compute the Confirm tag, authentication must fail.
        let psk = test_psk(0x03);
        let peer = addr(3);
        let mut session = ServerSession::NoSession;

        let real_client_random = crypto::generate_random();
        let init = protocol::HandshakeMessage::Init {
            version: protocol::HANDSHAKE_VERSION,
            client_random: real_client_random,
        }
        .encode();
        let server_random = match handle_incoming_datagram(&mut session, peer, &init, &psk) {
            ServerAction::Reply(_, bytes) => match protocol::HandshakeMessage::decode(&bytes).unwrap() {
                protocol::HandshakeMessage::Response { server_random, .. } => server_random,
                other => panic!("expected Response, got {other:?}"),
            },
            other => panic!("expected Reply, got {other:?}"),
        };

        let wrong_client_random = crypto::generate_random();
        let forged_tag = crypto::handshake_tag(
            protocol::MSG_TYPE_HANDSHAKE_CONFIRM,
            protocol::HANDSHAKE_VERSION,
            &psk,
            &wrong_client_random, // does not match what the server stored
            &server_random,
        );
        let confirm = protocol::HandshakeMessage::Confirm { tag: forged_tag }.encode();
        let action = handle_incoming_datagram(&mut session, peer, &confirm, &psk);
        assert!(matches!(action, ServerAction::Drop));
    }

    #[test]
    fn modified_server_random_is_rejected() {
        let psk = test_psk(0x04);
        let peer = addr(4);
        let mut session = ServerSession::NoSession;

        let client_random = crypto::generate_random();
        let init = protocol::HandshakeMessage::Init {
            version: protocol::HANDSHAKE_VERSION,
            client_random,
        }
        .encode();
        let _ = handle_incoming_datagram(&mut session, peer, &init, &psk);

        // Attacker guesses/uses a different server_random than the one
        // actually sent.
        let wrong_server_random = crypto::generate_random();
        let forged_tag = crypto::handshake_tag(
            protocol::MSG_TYPE_HANDSHAKE_CONFIRM,
            protocol::HANDSHAKE_VERSION,
            &psk,
            &client_random,
            &wrong_server_random,
        );
        let confirm = protocol::HandshakeMessage::Confirm { tag: forged_tag }.encode();
        let action = handle_incoming_datagram(&mut session, peer, &confirm, &psk);
        assert!(matches!(action, ServerAction::Drop));
    }

    #[test]
    fn modified_authentication_data_is_rejected() {
        let psk = test_psk(0x05);
        let peer = addr(5);
        let mut session = ServerSession::NoSession;

        let client_random = crypto::generate_random();
        let init = protocol::HandshakeMessage::Init {
            version: protocol::HANDSHAKE_VERSION,
            client_random,
        }
        .encode();
        let _ = handle_incoming_datagram(&mut session, peer, &init, &psk);

        let mut tag = [0u8; crypto::HANDSHAKE_TAG_SIZE];
        tag[0] ^= 0xFF; // garbage tag, definitely wrong
        let confirm = protocol::HandshakeMessage::Confirm { tag }.encode();
        let action = handle_incoming_datagram(&mut session, peer, &confirm, &psk);
        assert!(matches!(action, ServerAction::Drop));
    }

    #[test]
    fn modified_protocol_version_is_rejected() {
        let psk = test_psk(0x06);
        let peer = addr(6);
        let mut session = ServerSession::NoSession;

        let init = protocol::HandshakeMessage::Init {
            version: protocol::HANDSHAKE_VERSION + 1, // unsupported
            client_random: crypto::generate_random(),
        }
        .encode();
        let action = handle_incoming_datagram(&mut session, peer, &init, &psk);
        assert!(matches!(action, ServerAction::Drop));
        assert!(matches!(session, ServerSession::NoSession));
    }

    #[test]
    fn truncated_handshake_is_rejected() {
        let psk = test_psk(0x07);
        let peer = addr(7);
        let mut session = ServerSession::NoSession;

        let full = protocol::HandshakeMessage::Init {
            version: protocol::HANDSHAKE_VERSION,
            client_random: crypto::generate_random(),
        }
        .encode();
        let truncated = &full[..full.len() - 5];
        let action = handle_incoming_datagram(&mut session, peer, truncated, &psk);
        assert!(matches!(action, ServerAction::Drop));
    }

    #[test]
    fn malformed_handshake_is_rejected_without_panic() {
        let psk = test_psk(0x08);
        let peer = addr(8);
        let mut session = ServerSession::NoSession;

        // Random garbage, including an empty message and an unknown type.
        assert!(matches!(
            handle_incoming_datagram(&mut session, peer, &[], &psk),
            ServerAction::Drop
        ));
        assert!(matches!(
            handle_incoming_datagram(&mut session, peer, &[0xFF, 0x01, 0x02], &psk),
            ServerAction::Drop
        ));
    }

    #[test]
    fn data_before_handshake_completion_is_rejected() {
        let psk = test_psk(0x09);
        let peer = addr(9);
        let mut session = ServerSession::NoSession;

        // Fabricate a plausible-looking EncryptedData datagram; its
        // contents don't matter because there's no session to decrypt it
        // under yet.
        let fake_envelope = vec![0u8; crypto::COUNTER_SIZE + 32];
        let datagram = protocol::encode_encrypted_data(&fake_envelope);
        let action = handle_incoming_datagram(&mut session, peer, &datagram, &psk);
        assert!(matches!(action, ServerAction::Drop));

        // Also rejected while a handshake is merely in progress (not yet
        // Established).
        let init = protocol::HandshakeMessage::Init {
            version: protocol::HANDSHAKE_VERSION,
            client_random: crypto::generate_random(),
        }
        .encode();
        let _ = handle_incoming_datagram(&mut session, peer, &init, &psk);
        assert!(matches!(session, ServerSession::HandshakeInProgress { .. }));
        let action = handle_incoming_datagram(&mut session, peer, &datagram, &psk);
        assert!(matches!(action, ServerAction::Drop));
    }

    #[test]
    fn old_session_data_is_rejected_after_a_new_session_starts() {
        // Establish session A, then start (but don't finish) a brand new
        // handshake attempt from a NEW peer while restarting the whole
        // state (simulating a server restart between sessions, which is
        // really just a fresh `ServerSession::NoSession`). Data encrypted
        // under session A's key must not be accepted by session B.
        let psk = test_psk(0x0A);
        let peer_a = addr(10);
        let (_, session_a_ciphers) = run_valid_handshake(&psk, peer_a);

        let old_envelope = session_a_ciphers
            .client_to_server
            .encrypt(crypto::Direction::ClientToServer, b"session A data");
        let old_datagram = protocol::encode_encrypted_data(&old_envelope);

        // Fresh session (as if the server restarted).
        let peer_b = addr(11);
        let (mut session_b, _) = run_valid_handshake(&psk, peer_b);

        // Session A's peer address is different from session B's, so
        // this is already rejected on the peer check -- but even if it
        // somehow arrived from the *same* address, the key would differ
        // (see crypto::tests::session_from_old_handshake_cannot_be_decrypted_by_new_session
        // for that half of the guarantee). Here we confirm the
        // server-level behavior end-to-end.
        let action = handle_incoming_datagram(&mut session_b, peer_a, &old_datagram, &psk);
        assert!(matches!(action, ServerAction::Drop));
    }

    #[test]
    fn unauthenticated_udp_traffic_cannot_establish_the_peer() {
        let psk = test_psk(0x0B);
        let attacker = addr(12);
        let mut session = ServerSession::NoSession;

        // A bare EncryptedData datagram, or a Confirm with no preceding
        // Init, must never move the session into Established.
        let fake_envelope = vec![0u8; crypto::COUNTER_SIZE + 32];
        let datagram = protocol::encode_encrypted_data(&fake_envelope);
        let _ = handle_incoming_datagram(&mut session, attacker, &datagram, &psk);
        assert!(matches!(session, ServerSession::NoSession));

        let random_tag = [0u8; crypto::HANDSHAKE_TAG_SIZE];
        let confirm = protocol::HandshakeMessage::Confirm { tag: random_tag }.encode();
        let _ = handle_incoming_datagram(&mut session, attacker, &confirm, &psk);
        assert!(matches!(session, ServerSession::NoSession));
    }

    #[test]
    fn confirm_from_different_address_than_init_is_rejected() {
        let psk = test_psk(0x0C);
        let real_peer = addr(13);
        let attacker = addr(14);
        let mut session = ServerSession::NoSession;

        let client_random = crypto::generate_random();
        let init = protocol::HandshakeMessage::Init {
            version: protocol::HANDSHAKE_VERSION,
            client_random,
        }
        .encode();
        let server_random = match handle_incoming_datagram(&mut session, real_peer, &init, &psk) {
            ServerAction::Reply(_, bytes) => match protocol::HandshakeMessage::decode(&bytes).unwrap() {
                protocol::HandshakeMessage::Response { server_random, .. } => server_random,
                other => panic!("expected Response, got {other:?}"),
            },
            other => panic!("expected Reply, got {other:?}"),
        };

        let tag = crypto::handshake_tag(
            protocol::MSG_TYPE_HANDSHAKE_CONFIRM,
            protocol::HANDSHAKE_VERSION,
            &psk,
            &client_random,
            &server_random,
        );
        let confirm = protocol::HandshakeMessage::Confirm { tag }.encode();
        // The (valid!) confirm arrives from a different address than the
        // one that sent Init -- must be rejected.
        let action = handle_incoming_datagram(&mut session, attacker, &confirm, &psk);
        assert!(matches!(action, ServerAction::Drop));
        assert!(matches!(session, ServerSession::HandshakeInProgress { .. }));
    }

    #[test]
    fn new_handshake_init_while_established_is_rejected() {
        let psk = test_psk(0x0D);
        let peer = addr(15);
        let (mut session, _) = run_valid_handshake(&psk, peer);

        let new_peer = addr(16);
        let init = protocol::HandshakeMessage::Init {
            version: protocol::HANDSHAKE_VERSION,
            client_random: crypto::generate_random(),
        }
        .encode();
        let action = handle_incoming_datagram(&mut session, new_peer, &init, &psk);
        assert!(matches!(action, ServerAction::Drop));
        // The existing session must remain untouched.
        assert!(matches!(session, ServerSession::Established { peer: p, .. } if p == peer));
    }

    /// v0.7 correction: the server must not create the TUN interface (or
    /// its upload thread) until the handshake has actually established a
    /// session. `handle_incoming_datagram` itself has no TUN dependency,
    /// so we can verify the *ordering guarantee* purely at the action
    /// level, with no real TUN device: `EstablishSession` must always be
    /// the action that authorizes TUN creation in the caller
    /// (`run_server_receive_loop`), and no `WriteToTun` action can ever
    /// be produced before that has happened for the current session.
    #[test]
    fn establish_session_action_precedes_any_write_to_tun_action() {
        let psk = test_psk(0x0E);
        let peer = addr(17);
        let mut session = ServerSession::NoSession;

        // Before any handshake at all: a plausible EncryptedData datagram
        // must never produce WriteToTun (there is no session, so no TUN
        // should exist yet in the real caller either).
        let fake_envelope = vec![0u8; crypto::COUNTER_SIZE + 32];
        let datagram = protocol::encode_encrypted_data(&fake_envelope);
        assert!(!matches!(
            handle_incoming_datagram(&mut session, peer, &datagram, &psk),
            ServerAction::WriteToTun(_) | ServerAction::EstablishSession(..)
        ));

        // Drive Init -> Response.
        let client_random = crypto::generate_random();
        let init = protocol::HandshakeMessage::Init {
            version: protocol::HANDSHAKE_VERSION,
            client_random,
        }
        .encode();
        let server_random = match handle_incoming_datagram(&mut session, peer, &init, &psk) {
            ServerAction::Reply(_, bytes) => match protocol::HandshakeMessage::decode(&bytes).unwrap() {
                protocol::HandshakeMessage::Response { server_random, .. } => server_random,
                other => panic!("expected Response, got {other:?}"),
            },
            other => panic!("expected Reply, got {other:?}"),
        };

        // Still mid-handshake: still no WriteToTun/EstablishSession yet.
        assert!(!matches!(
            handle_incoming_datagram(&mut session, peer, &datagram, &psk),
            ServerAction::WriteToTun(_) | ServerAction::EstablishSession(..)
        ));

        // Complete the handshake: THIS is the one and only point where
        // EstablishSession is produced -- the real server creates the
        // TUN device and spawns the upload thread exactly here.
        let client_tag = crypto::handshake_tag(
            protocol::MSG_TYPE_HANDSHAKE_CONFIRM,
            protocol::HANDSHAKE_VERSION,
            &psk,
            &client_random,
            &server_random,
        );
        let confirm = protocol::HandshakeMessage::Confirm { tag: client_tag }.encode();
        let action = handle_incoming_datagram(&mut session, peer, &confirm, &psk);
        assert!(matches!(action, ServerAction::EstablishSession(p, _) if p == peer));

        // Only now, after EstablishSession, can a real EncryptedData
        // packet from the established peer produce WriteToTun.
        let session_ciphers = crypto::derive_session_ciphers(&psk, &client_random, &server_random);
        let frame = protocol::Frame::data(vec![0xAB; 10]).unwrap();
        let envelope = session_ciphers
            .client_to_server
            .encrypt(crypto::Direction::ClientToServer, &frame.encode());
        let data_datagram = protocol::encode_encrypted_data(&envelope);
        let action = handle_incoming_datagram(&mut session, peer, &data_datagram, &psk);
        assert!(matches!(action, ServerAction::WriteToTun(ref payload) if *payload == vec![0xAB; 10]));
    }
}