//! TCP byte-tunnel server (v0.1).
//!
//! Accepts one client connection at a time and relays raw bytes between
//! the tunnel and the client itself: whatever the client sends is relayed
//! back over the same TCP connection. There is no second endpoint yet in
//! v0.1, so this is the simplest possible "forward bytes between
//! endpoints" behavior, and it doubles as an end-to-end smoke test for the
//! tunnel plumbing that later versions will build on.

use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};

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