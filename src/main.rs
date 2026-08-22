use std::env;
use std::process;

mod auth;
mod client;
mod config;
mod crypto;
mod protocol;
mod routing;
mod server;
mod transport;
mod tun;

fn main() {
    let args: Vec<String> = env::args().collect();
    let program = args.first().map(String::as_str).unwrap_or("tiny-vpn");

    let mode = match args.get(1) {
        Some(mode) => mode.as_str(),
        None => {
            print_usage(program);
            process::exit(1);
        }
    };

    let result = match mode {
        "server" => server::run(&require_address(program, &args, mode)),
        "client" => client::run(&require_address(program, &args, mode)),
        "tun" => {
            if args.len() != 2 {
                eprintln!("Usage: {program} tun");
                process::exit(1);
            }
            tun::run()
        }
        other => {
            eprintln!("Unknown mode '{other}'. Expected 'server', 'client', or 'tun'.");
            print_usage(program);
            process::exit(1);
        }
    };

    if let Err(e) = result {
        eprintln!("Error: {e}");
        process::exit(1);
    }
}

/// Extract the `<address>` argument for `server`/`client` mode, or print
/// usage and exit if it's missing/extra.
fn require_address(program: &str, args: &[String], mode: &str) -> String {
    match args.get(2) {
        Some(address) if args.len() == 3 => address.clone(),
        _ => {
            eprintln!("Usage: {program} {mode} <address>");
            process::exit(1);
        }
    }
}

fn print_usage(program: &str) {
    eprintln!("Usage:");
    eprintln!("  {program} server <address>");
    eprintln!("  {program} client <address>");
    eprintln!("  {program} tun");
}