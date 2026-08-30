//! TCP byte-tunnel client (v0.1) and VPN client (v0.3, extended in v0.4
//! with UDP transport, in v0.6 with encryption, in v0.7 with a
//! PSK-authenticated handshake and per-session keys, and in v0.8.5 with
//! client-side routing).
//!
//! `run()` is the original v0.1 mode: it relays stdin -> socket and
//! socket -> stdout, so the raw byte tunnel can be exercised interactively
//! or with piped input.
//!
//! `run_vpn()` is v0.3: it creates a TUN interface, connects to a VPN
//! server over TCP, and relays raw IP packets between the two, in both
//! directions, concurrently.
//!
//! `run_udp_vpn()` is v0.4/v0.6/v0.7/v0.8.5: the client performs a
//! PSK-authenticated handshake with the server (`perform_handshake`)
//! before any VPN data flows, deriving fresh per-session encryption keys
//! instead of using the static PSK directly (see `crypto.rs`). Only after
//! that succeeds does it create the TUN interface; only after THAT does
//! it (optionally, per `[routing]` in config) configure client-side
//! routing (`configure_client_routing`) -- split-tunnel (selected CIDRs)
//! or full-tunnel (all IPv4 traffic, except the VPN server's own
//! endpoint, which always keeps using the client's normal physical
//! route -- see `routing::build_client_routing_plan`). Routing defaults
//! to disabled: installing v0.8.5 does not by itself change any existing
//! client's routing behavior.

use std::io::{self, Read, Write};
use std::net::{IpAddr, TcpStream, UdpSocket};
use std::thread;
use std::time::Duration;

use crate::config::{self, RoutingMode};
use crate::crypto::{self, SessionCiphers};
use crate::protocol;
use crate::routing;
use crate::transport;
use crate::tun;

/// How long to wait for the server's `HandshakeResponse` before giving
/// up. There is no retry/reconnect logic in this project (out of scope
/// through v0.7) -- a single bounded wait, not a retry loop.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// Load and parse the pre-shared key from `config_path`. Wraps config/key
/// errors as `io::Error` so callers can use `?` alongside the rest of
/// this module's I/O.
pub fn load_psk(config_path: &str) -> io::Result<[u8; crypto::KEY_SIZE]> {
    let key_hex = config::load_crypto_key_hex(config_path)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    crypto::parse_key_hex(&key_hex).map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
}

/// Connect to `address` and relay bytes between stdio and the connection.
pub fn run(address: &str) -> io::Result<()> {
    let stream = TcpStream::connect(address)?;
    println!("Connected to {address}");

    let mut writer = stream.try_clone()?;
    let mut reader = stream;

    // Thread 1: read from stdin, write to the TCP connection.
    let stdin_thread = thread::spawn(move || -> io::Result<()> {
        let stdin = io::stdin();
        let mut handle = stdin.lock();
        let mut buf = [0u8; 4096];
        loop {
            let n = handle.read(&mut buf)?;
            if n == 0 {
                // stdin closed (e.g. EOF from a pipe). Stop sending.
                return Ok(());
            }
            writer.write_all(&buf[..n])?;
        }
    });

    // Thread 2 (main thread): read from the TCP connection, write to stdout.
    let stdout_result: io::Result<()> = (|| {
        let stdout = io::stdout();
        let mut handle = stdout.lock();
        let mut buf = [0u8; 4096];
        loop {
            let n = reader.read(&mut buf)?;
            if n == 0 {
                // Server closed the connection.
                return Ok(());
            }
            handle.write_all(&buf[..n])?;
            handle.flush()?;
        }
    })();

    // Don't propagate a stdin-thread panic as a hard error; just report it.
    match stdin_thread.join() {
        Ok(Ok(())) => {}
        Ok(Err(e)) => eprintln!("stdin/send error: {e}"),
        Err(_) => eprintln!("stdin thread panicked"),
    }

    stdout_result
}

/// Create the client TUN interface, connect to `address`, and relay raw IP
/// packets between the TUN device and the TCP connection in both
/// directions, concurrently.
///
/// See `tun::relay_tun_to_writer` / `tun::relay_reader_to_tun` for the
/// important caveat that v0.3 does not yet frame packets on the wire.
pub fn run_vpn(address: &str) -> io::Result<()> {
    let tun_device = tun::create_device(
        tun::CLIENT_TUN_NAME,
        tun::CLIENT_TUN_ADDRESS,
        tun::VPN_TUN_NETMASK,
    )?;
    let (a, b, c, d) = tun::CLIENT_TUN_ADDRESS;
    println!(
        "Client TUN '{}' is up at {a}.{b}.{c}.{d}/24",
        tun::CLIENT_TUN_NAME
    );

    let stream = TcpStream::connect(address)?;
    println!("Connected to server at {address}");

    let (tun_reader, tun_writer) = tun_device.split();
    let tcp_upload = stream.try_clone()?;
    let tcp_download = stream;

    // Thread: TUN -> TCP (packets captured from the local TUN device are
    // sent to the server).
    let upload_thread = thread::spawn(move || {
        tun::relay_tun_to_writer(tun_reader, tcp_upload, "Client")
    });

    // Main thread: TCP -> TUN (packets arriving from the server are
    // written into the local TUN device).
    let download_result = tun::relay_reader_to_tun(tcp_download, tun_writer, "Client");

    match upload_thread.join() {
        Ok(Ok(())) => {}
        Ok(Err(e)) => eprintln!("Client TUN->TCP error: {e}"),
        Err(_) => eprintln!("Client TUN->TCP thread panicked"),
    }

    download_result
}

/// Perform the v0.7 handshake over an already-connected `socket`:
///
/// ```text
/// Client -> Server: HandshakeInit    { version, client_random }
/// Server -> Client: HandshakeResponse{ version, server_random, tag }
/// Client -> Server: HandshakeConfirm { tag }
/// ```
///
/// The client authenticates the server's response by recomputing its tag
/// locally from the PSK, its own `client_random`, and the received
/// `server_random`; on success it derives fresh session keys and sends
/// its own tag back to prove it also knows the PSK. Returns the derived
/// `SessionCiphers` on success. Never prints the PSK, either random
/// value, or any derived key -- only high-level progress and (via
/// `SessionCiphers`'s fingerprints) a safe, non-secret confirmation that
/// keys were derived.
fn perform_handshake(socket: &UdpSocket, psk: &[u8; crypto::KEY_SIZE]) -> io::Result<SessionCiphers> {
    let client_random = crypto::generate_random();

    let init = protocol::HandshakeMessage::Init {
        version: protocol::HANDSHAKE_VERSION,
        client_random,
    };
    socket.send(&init.encode())?;
    println!("Client: handshake started");

    socket.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
    let mut buf = [0u8; transport::UDP_RECV_BUFFER_SIZE];
    let n = socket.recv(&mut buf).map_err(|e| match e.kind() {
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => {
            io::Error::new(io::ErrorKind::TimedOut, "timed out waiting for handshake response")
        }
        _ => e,
    })?;

    let message = protocol::UdpMessage::decode(&buf[..n]).map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidData, format!("malformed handshake response: {e}"))
    })?;

    let (version, server_random, tag) = match message {
        protocol::UdpMessage::Handshake(protocol::HandshakeMessage::Response {
            version,
            server_random,
            tag,
        }) => (version, server_random, tag),
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "expected a HandshakeResponse",
            ))
        }
    };

    if version != protocol::HANDSHAKE_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported handshake version {version}"),
        ));
    }

    let expected_tag = crypto::handshake_tag(
        protocol::MSG_TYPE_HANDSHAKE_RESPONSE,
        protocol::HANDSHAKE_VERSION,
        psk,
        &client_random,
        &server_random,
    );
    if !crypto::verify_tag(&expected_tag, &tag) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "handshake authentication failed",
        ));
    }
    println!("Client: handshake authenticated");

    let session_ciphers = crypto::derive_session_ciphers(psk, &client_random, &server_random);

    let client_tag = crypto::handshake_tag(
        protocol::MSG_TYPE_HANDSHAKE_CONFIRM,
        protocol::HANDSHAKE_VERSION,
        psk,
        &client_random,
        &server_random,
    );
    socket.send(&protocol::HandshakeMessage::Confirm { tag: client_tag }.encode())?;

    // The handshake is done; the data-relay loops that follow should
    // block indefinitely waiting for traffic, not time out.
    socket.set_read_timeout(None)?;

    println!(
        "Client: session established (fingerprints c->s={} s->c={})",
        session_ciphers.client_to_server_fingerprint, session_ciphers.server_to_client_fingerprint
    );

    Ok(session_ciphers)
}

/// Create the client TUN interface, load the pre-shared key from
/// `config_path`, bind a UDP socket, connect it to the server, complete
/// the v0.7 handshake, and relay raw IP packets between the TUN device
/// and the socket in both directions, concurrently, using the
/// freshly-derived per-session keys.
///
/// As of v0.8.5, once the TUN interface exists, `[routing]` in the config
/// file (see `config::load_client_routing_settings`) optionally routes
/// selected traffic (`mode = "split"`) or all IPv4 traffic except the VPN
/// server's own endpoint (`mode = "full"`) through that TUN device. With
/// no `[routing]` section (or `mode = "disabled"`, the default), client
/// routing behaves exactly as it did before v0.8.5: no route changes at
/// all beyond the TUN device's own connected route for the VPN subnet.
///
/// A VPN data packet that fails authentication (which should only happen
/// under corruption, since the session key is by now confirmed correct)
/// is dropped and logged -- never written to TUN.
pub struct AuthenticatedClient {
    socket: UdpSocket,
    session_ciphers: SessionCiphers,
}

pub fn authenticate(server_address: &str, psk: &[u8; crypto::KEY_SIZE]) -> io::Result<AuthenticatedClient> {
    // Bind to an OS-assigned local port; we only ever talk to one server.
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    authenticate_with_socket(socket, server_address, psk)
}

pub fn authenticate_with_socket(socket: UdpSocket, server_address: &str, psk: &[u8; crypto::KEY_SIZE]) -> io::Result<AuthenticatedClient> {
    // Reuses the exact same SIGINT handler/flag the v0.8 server installs
    // (see routing::install_shutdown_handler) rather than duplicating it:
    // a plain Ctrl+C would otherwise terminate this process immediately,
    // skipping cleanup.
    routing::install_shutdown_handler();

    socket.connect(server_address)?;
    println!(
        "UDP socket bound to {} and connected to server at {server_address}",
        socket.local_addr()?
    );

    let session_ciphers = perform_handshake(&socket, psk)?;
    Ok(AuthenticatedClient { socket, session_ciphers })
}

impl AuthenticatedClient {
    pub fn server_ip(&self) -> io::Result<IpAddr> {
        Ok(self.socket.peer_addr()?.ip())
    }

    pub fn start_relay(self, tun_device: tun::PacketDevice) -> io::Result<()> {
        let client_to_server = self.session_ciphers.client_to_server;
        let server_to_client = self.session_ciphers.server_to_client;

        let (tun_reader, tun_writer) = tun_device.split();
        let upload_socket = self.socket.try_clone()?;

        // Thread: TUN -> UDP (packets captured from the local TUN device are
        // framed, encrypted with this session's client-to-server key, and
        // sent to the server).
        let upload_thread = thread::spawn(move || {
            transport::relay_tun_to_udp_session(
                tun_reader,
                &upload_socket,
                "Client",
                &client_to_server,
                crypto::Direction::ClientToServer,
            )
        });

        // Main thread: UDP -> TUN (datagrams arriving from the server are
        // decrypted with this session's server-to-client key, authenticated,
        // and written into the local TUN device).
        let download_result = transport::relay_udp_to_tun_session(
            &self.socket,
            tun_writer,
            "Client",
            &server_to_client,
            crypto::Direction::ServerToClient,
        );

        // A SIGINT-interrupted read is a clean shutdown request, not an
        // error -- see `routing::install_shutdown_handler`.
        let download_result = match download_result {
            Err(e) if e.kind() == io::ErrorKind::Interrupted && routing::shutdown_requested() => {
                println!("Client: shutdown requested, cleaning up");
                Ok(())
            }
            other => other,
        };

        match &download_result {
            Ok(()) => {
                // Clean shutdown: deliberately do NOT block waiting for the
                // upload thread here.
                drop(upload_thread);
            }
            Err(_) => match upload_thread.join() {
                Ok(Ok(())) => {}
                Ok(Err(e)) => eprintln!("Client TUN->UDP error: {e}"),
                Err(_) => eprintln!("Client TUN->UDP thread panicked"),
            },
        }

        download_result
    }
}

/// Configure client-side routing per `settings`, if enabled. Returns
/// `None` for `RoutingMode::Disabled` (the default) -- no routes are
/// touched at all. For `Split`/`Full`, determines the VPN server's
/// resolved IPv4 endpoint and its pre-VPN route (so the tunnel's own
/// traffic can never loop back into itself -- see
/// `routing::build_client_routing_plan`), builds the routing plan, and
/// applies it, returning a guard that removes the added routes when
/// dropped.
///
/// IPv4 is the only supported case for the VPN server's endpoint in this
/// milestone: if it resolved to IPv6, this returns an error rather than
/// silently skipping route configuration or routing the wrong thing.
pub fn configure_client_routing(
    settings: &config::ClientRoutingSettings,
    server_ip: IpAddr,
) -> io::Result<Option<routing::ClientRouteGuard>> {
    if settings.mode == RoutingMode::Disabled {
        return Ok(None);
    }

    let server_ip = match server_ip {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(_) => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "client routing (split/full) only supports an IPv4 VPN server endpoint \
                 in this version; the resolved server address is IPv6",
            ));
        }
    };
    let server_ip_str = server_ip.to_string();

    // Captured BEFORE any client VPN routes exist, so this reflects the
    // host's genuine pre-VPN route to the server -- exactly what the
    // server-endpoint exception (full-tunnel mode) needs to pin to.
    let server_route = routing::current_route_to(&server_ip_str)?;

    let mode = match settings.mode {
        RoutingMode::Disabled => unreachable!("handled above"),
        RoutingMode::Split => routing::ClientRoutingMode::Split(settings.routes.clone()),
        RoutingMode::Full => routing::ClientRoutingMode::Full,
    };

    let plan = routing::build_client_routing_plan(
        &mode,
        tun::CLIENT_TUN_NAME,
        &server_ip_str,
        &server_route,
    )
    .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;

    println!(
        "Client: routing mode is {mode:?}; VPN server endpoint {server_ip_str} stays on its \
         existing route"
    );

    let guard = routing::apply_client_routes(&plan)?;
    Ok(Some(guard))
}