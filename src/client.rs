//! TCP byte-tunnel client (v0.1).
//!
//! Connects to the server and relays stdin -> socket and socket -> stdout
//! concurrently, so the tunnel can be exercised interactively or with
//! piped input.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::thread;

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