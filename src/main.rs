use std::env;
use std::process;

use tinyvpn::{client, config, routing, server, tun, dns};

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
        "vpn-server" => server::run_vpn(&require_address(program, &args, mode)),
        "vpn-client" => client::run_vpn(&require_address(program, &args, mode)),
        "udp-server" => run_udp_server(program, &args, mode),
        "udp-client" => run_udp_client(program, &args, mode),
        other => {
            eprintln!(
                "Unknown mode '{other}'. Expected 'server', 'client', 'tun', 'vpn-server', 'vpn-client', 'udp-server', or 'udp-client'."
            );
            print_usage(program);
            process::exit(1);
        }
    };

    if let Err(e) = result {
        eprintln!("Error: {e}");
        process::exit(1);
    }
}

fn run_udp_server(program: &str, args: &[String], mode: &str) -> std::io::Result<()> {
    let address = require_udp_address(program, args, mode);
    let config_path = optional_config_path(args, "config/server.toml");
    
    let psk = server::load_psk(&config_path)?;
    let routing_settings = config::load_routing_settings(&config_path)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

    let tunnel_settings = config::load_tunnel_settings(&config_path)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
    let address_plan = tun::TunnelAddressPlan::from_topology(&tunnel_settings.topology);

    let auth_server = server::wait_for_client_and_authenticate(&address, psk)?;
    
    let tun_device = tun::create_device(
        tun::SERVER_TUN_NAME,
        address_plan.server_address,
        tun::VPN_TUN_NETMASK,
    )?;
    let (a, b, c, d) = address_plan.server_address;
    println!("Server TUN '{}' is up at {a}.{b}.{c}.{d}/24", tun::SERVER_TUN_NAME);

    let mut _routing_guard = None;
    if routing_settings.nat_enabled {
        let routing_config = routing::RoutingConfig {
            vpn_subnet: routing::cidr_from_address_and_netmask(
                address_plan.server_address,
                tun::VPN_TUN_NETMASK,
            ),
            tun_interface: tun::SERVER_TUN_NAME.to_string(),
            outbound_interface: routing_settings.outbound_interface.clone(),
            address_plan: address_plan.clone(),
        };
        _routing_guard = Some(routing::apply(&routing_config)?);
    } else {
        println!("Server: routing/NAT is disabled (tunnel-only mode; no Internet access via this server)");
    }

    auth_server.start_relay(tun_device)
}

fn run_udp_client(program: &str, args: &[String], mode: &str) -> std::io::Result<()> {
    let address = require_udp_address(program, args, mode);
    let config_path = optional_config_path(args, "config/client.toml");
    
    let psk = client::load_psk(&config_path)?;
    let mut routing_settings = config::load_client_routing_settings(&config_path)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
    let dns_settings = config::load_dns_settings(&config_path)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

    // Application-level enforcement: If VPN DNS is enabled and we are in Split mode,
    // the DNS servers MUST be actively routed through the VPN to be queryable securely.
    if dns_settings.enabled && routing_settings.mode == config::RoutingMode::Split {
        for ip in &dns_settings.servers {
            let cidr = format!("{}/32", ip);
            if !routing_settings.routes.contains(&cidr) {
                routing_settings.routes.push(cidr);
            }
        }
    }

    let tunnel_settings = config::load_tunnel_settings(&config_path)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
    let address_plan = tun::TunnelAddressPlan::from_topology(&tunnel_settings.topology);

    let auth_client = client::authenticate(&address, &psk)?;
    
    let tun_device = tun::create_device(
        tun::CLIENT_TUN_NAME,
        address_plan.client_address,
        tun::VPN_TUN_NETMASK,
    )?;
    let (a, b, c, d) = address_plan.client_address;
    println!("Client TUN '{}' is up at {a}.{b}.{c}.{d}/24", tun::CLIENT_TUN_NAME);

    let server_ip = auth_client.server_ip()?;
    let _routing_guard = client::configure_client_routing(&routing_settings, server_ip)?;

    let dns_config = dns::DnsConfig {
        enabled: dns_settings.enabled,
        servers: dns_settings.servers,
    };
    
    let _dns_guard = dns::apply(&dns_config, tun::CLIENT_TUN_NAME)?;
    
    auth_client.start_relay(tun_device)
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

/// Like `require_address`, but also allows one optional trailing
/// `<config-path>` argument (used by `udp-server`/`udp-client` to load the
/// pre-shared encryption key from a non-default config file).
fn require_udp_address(program: &str, args: &[String], mode: &str) -> String {
    match args.get(2) {
        Some(address) if args.len() == 3 || args.len() == 4 => address.clone(),
        _ => {
            eprintln!("Usage: {program} {mode} <address> [config-path]");
            process::exit(1);
        }
    }
}

/// Extract the optional `<config-path>` argument (position 3), falling
/// back to `default` if it wasn't given.
fn optional_config_path(args: &[String], default: &str) -> String {
    args.get(3).cloned().unwrap_or_else(|| default.to_string())
}

fn print_usage(program: &str) {
    eprintln!("Usage:");
    eprintln!("  {program} server <address>                        (v0.1: raw TCP byte tunnel server)");
    eprintln!("  {program} client <address>                        (v0.1: raw TCP byte tunnel client)");
    eprintln!("  {program} tun                                     (v0.2: standalone TUN packet dump)");
    eprintln!("  {program} vpn-server <address>                    (v0.3: TUN <-> TCP server)");
    eprintln!("  {program} vpn-client <address>                    (v0.3: TUN <-> TCP client)");
    eprintln!("  {program} udp-server <address> [config-path]      (v0.4/v0.6/v0.7: handshake-authenticated, encrypted TUN <-> UDP server, default config/server.toml)");
    eprintln!("  {program} udp-client <address> [config-path]      (v0.4/v0.6/v0.7: handshake-authenticated, encrypted TUN <-> UDP client, default config/client.toml)");
}