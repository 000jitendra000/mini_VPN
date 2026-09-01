//! Minimal config-file loading (v0.6, extended in v0.8 for routing/NAT
//! settings).
//!
//! Just enough hand-written parsing to read `[section] key = value`
//! entries out of a TOML-flavored config file, without adding a
//! TOML/serde dependency (none is needed for something this small).
//!
//! This is intentionally NOT a general TOML parser: it understands only
//! `[section]` headers and `key = value` lines within a section (with an
//! optional surrounding pair of double quotes on the value), skips blank
//! lines and `#` comments, and only ever looks inside the one section a
//! caller asks for. That covers everything this project's config files
//! need right now. If a real TOML parser is ever warranted, it should
//! replace this rather than grow it.
//!
//! This module only extracts raw strings from config; it does not
//! validate key bytes (see `crypto::parse_key_hex`) or touch any
//! networking code (see `routing.rs`) itself.

use std::fmt;
use std::fs;
use std::io;

/// Errors from loading/parsing a config file.
#[derive(Debug)]
pub enum ConfigError {
    Io(io::Error),
    MissingCryptoSection,
    MissingKey,
    /// A `[routing]` value was present but not one of the values that key
    /// accepts (currently `nat_enabled`, which must be `true`/`false`,
    /// and `mode`, which must be `disabled`/`split`/`full`).
    InvalidRoutingValue { key: &'static str, found: String },
    /// A `[routing] routes` entry was present but not a `[...]`-bracketed
    /// list, e.g. `routes = ["10.20.0.0/24"]`.
    InvalidRouteList { found: String },
    /// A `[dns]` value was present but invalid.
    InvalidDnsValue { key: &'static str, found: String },
    /// A `[tunnel]` value was present but invalid.
    InvalidTunnelValue { key: &'static str, found: String },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::Io(e) => write!(f, "could not read config file: {e}"),
            ConfigError::MissingCryptoSection => write!(f, "config file has no [crypto] section"),
            ConfigError::MissingKey => write!(f, "[crypto] section has no 'key' entry"),
            ConfigError::InvalidRoutingValue { key, found } => {
                write!(f, "[routing] '{key}' has an invalid value: {found:?}")
            }
            ConfigError::InvalidRouteList { found } => {
                write!(
                    f,
                    "[routing] 'routes' must be a bracketed list like [\"10.20.0.0/24\"], found: {found:?}"
                )
            }
            ConfigError::InvalidDnsValue { key, found } => {
                write!(f, "[dns] '{key}' has an invalid value: {found:?}")
            }
            ConfigError::InvalidTunnelValue { key, found } => {
                write!(f, "[tunnel] '{key}' has an invalid value: {found:?}")
            }
        }
    }
}

impl std::error::Error for ConfigError {}

impl From<io::Error> for ConfigError {
    fn from(e: io::Error) -> Self {
        ConfigError::Io(e)
    }
}

/// Scan `contents` for a `[section]` header followed by a `key = value`
/// line, and return the value (unquoted, if it was a quoted string).
/// Shared by every `load_*` function below so there's exactly one place
/// that understands this project's tiny config-file dialect.
fn find_value(contents: &str, section: &str, key: &str) -> Option<String> {
    let mut in_section = false;

    for raw_line in contents.lines() {
        let line = raw_line.trim();

        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if let Some(name) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            in_section = name.trim() == section;
            continue;
        }

        if !in_section {
            continue;
        }

        if let Some((found_key, value)) = line.split_once('=') {
            if found_key.trim() == key {
                let value = value.trim();
                let unquoted = value
                    .strip_prefix('"')
                    .and_then(|v| v.strip_suffix('"'))
                    .unwrap_or(value);
                return Some(unquoted.to_string());
            }
        }
    }

    None
}

/// Whether `contents` contains a `[section]` header at all (used to
/// distinguish "section missing" from "key missing within the section"
/// for clearer error messages).
fn has_section(contents: &str, section: &str) -> bool {
    contents
        .lines()
        .any(|line| line.trim().strip_prefix('[').and_then(|s| s.strip_suffix(']')) == Some(section))
}

/// Load the `[crypto] key = "..."` value from a config file at `path`,
/// returning the raw hex string exactly as written (not yet parsed or
/// validated as key bytes -- see `crypto::parse_key_hex` for that).
pub fn load_crypto_key_hex(path: &str) -> Result<String, ConfigError> {
    let contents = fs::read_to_string(path)?;

    match find_value(&contents, "crypto", "key") {
        Some(value) => Ok(value),
        None if has_section(&contents, "crypto") => Err(ConfigError::MissingKey),
        None => Err(ConfigError::MissingCryptoSection),
    }
}

/// Routing/NAT settings loaded from a server config file's `[routing]`
/// section. See `routing::RoutingConfig` for how this feeds into the
/// actual platform backend -- this type only carries what config files
/// can express; it does not know anything about iptables or TUN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingSettings {
    /// Whether the server should configure IP forwarding/NAT at all.
    /// Defaults to `true` if the `[routing]` section or this key is
    /// absent -- v0.8's whole point is to make the tunnel act as a
    /// gateway by default; set this to `false` to keep the older,
    /// tunnel-only (no Internet access) behavior instead.
    pub nat_enabled: bool,
    /// Outbound interface to forward/NAT through. `None` means
    /// "auto-detect from the host's default route" (the default when
    /// this key is absent).
    pub outbound_interface: Option<String>,
}

impl Default for RoutingSettings {
    fn default() -> Self {
        RoutingSettings {
            nat_enabled: true,
            outbound_interface: None,
        }
    }
}

/// Load the `[routing]` section from a config file at `path`. A totally
/// absent `[routing]` section (or an absent individual key within it) is
/// not an error -- it just means "use the default" (see
/// `RoutingSettings::default`), since routing/NAT configuration is
/// optional, unlike the `[crypto]` key.
pub fn load_routing_settings(path: &str) -> Result<RoutingSettings, ConfigError> {
    let contents = fs::read_to_string(path)?;

    let nat_enabled = match find_value(&contents, "routing", "nat_enabled") {
        Some(value) => match value.as_str() {
            "true" => true,
            "false" => false,
            other => {
                return Err(ConfigError::InvalidRoutingValue {
                    key: "nat_enabled",
                    found: other.to_string(),
                })
            }
        },
        None => RoutingSettings::default().nat_enabled,
    };

    let outbound_interface = find_value(&contents, "routing", "outbound_interface");

    Ok(RoutingSettings {
        nat_enabled,
        outbound_interface,
    })
}

// ============================================================================
// v0.8.5: client-side routing settings.
//
// These live in the SAME `[routing]` section name as the server's
// settings above, but with different keys (`mode`, `routes`) -- since
// they're always read from different files (config/client.toml vs.
// config/server.toml) in practice, there's no ambiguity, and reusing the
// section name keeps the config format uniform rather than inventing a
// second section just for this.
// ============================================================================

/// The client's routing mode, as read from config. See
/// `routing::ClientRoutingMode` for what each mode actually does --
/// this type only exists to represent what a config file can express;
/// it has no dependency on `routing.rs` or any networking code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoutingMode {
    Disabled,
    Split,
    Full,
}

/// Client routing settings loaded from a config file's `[routing]`
/// section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientRoutingSettings {
    pub mode: RoutingMode,
    /// Only meaningful when `mode` is `Split`; ignored otherwise.
    pub routes: Vec<String>,
}

impl Default for ClientRoutingSettings {
    /// `Disabled` -- installing v0.8.5 must not silently change an
    /// existing client's routing behavior. A client config with no
    /// `[routing]` section at all behaves exactly as it did in v0.7/v0.8:
    /// only the TUN device's own connected route for the VPN subnet
    /// exists.
    fn default() -> Self {
        ClientRoutingSettings {
            mode: RoutingMode::Disabled,
            routes: vec![],
        }
    }
}

/// Load the `[routing]` section from a client config file at `path`. A
/// totally absent `[routing]` section (or an absent `mode` key within
/// it) is not an error -- it just means "use the default"
/// (`ClientRoutingSettings::default`, i.e. `Disabled`).
pub fn load_client_routing_settings(path: &str) -> Result<ClientRoutingSettings, ConfigError> {
    let contents = fs::read_to_string(path)?;

    let mode = match find_value(&contents, "routing", "mode") {
        Some(value) => match value.as_str() {
            "disabled" => RoutingMode::Disabled,
            "split" => RoutingMode::Split,
            "full" => RoutingMode::Full,
            other => {
                return Err(ConfigError::InvalidRoutingValue {
                    key: "mode",
                    found: other.to_string(),
                })
            }
        },
        None => ClientRoutingSettings::default().mode,
    };

    let routes = match find_value(&contents, "routing", "routes") {
        Some(raw) => parse_route_list(&raw)?,
        None => vec![],
    };

    Ok(ClientRoutingSettings { mode, routes })
}

/// Parse a `routes = ["a", "b"]`-style bracketed list into its elements
/// (unquoted, trimmed). `find_value` already returns the bracketed
/// substring unmodified for values shaped like this (its own
/// quote-stripping only fires when the *whole* value starts with `"`,
/// which `[...]` never does), so this just needs to peel the brackets and
/// split on commas.
fn parse_route_list(raw: &str) -> Result<Vec<String>, ConfigError> {
    let inner = raw
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .ok_or_else(|| ConfigError::InvalidRouteList {
            found: raw.to_string(),
        })?;

    if inner.trim().is_empty() {
        return Ok(vec![]);
    }

    Ok(inner
        .split(',')
        .map(|item| {
            let item = item.trim();
            item.strip_prefix('"')
                .and_then(|s| s.strip_suffix('"'))
                .unwrap_or(item)
                .to_string()
        })
        .filter(|s| !s.is_empty())
        .collect())
}

// ============================================================================
// v0.9 DNS settings loaded from config file `[dns]` section.
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsSettings {
    pub enabled: bool,
    pub servers: Vec<std::net::IpAddr>,
}

impl Default for DnsSettings {
    fn default() -> Self {
        DnsSettings {
            enabled: false,
            servers: vec![],
        }
    }
}

pub fn load_dns_settings(path: &str) -> Result<DnsSettings, ConfigError> {
    let contents = fs::read_to_string(path)?;

    let enabled = match find_value(&contents, "dns", "enabled") {
        Some(value) => match value.as_str() {
            "true" => true,
            "false" => false,
            other => {
                return Err(ConfigError::InvalidDnsValue {
                    key: "enabled",
                    found: other.to_string(),
                })
            }
        },
        None => DnsSettings::default().enabled,
    };

    let servers = match find_value(&contents, "dns", "servers") {
        Some(raw) => {
            let list = parse_route_list(&raw)?;
            let mut ips = Vec::new();
            for s in list {
                match s.parse::<std::net::IpAddr>() {
                    Ok(ip) => {
                        // Prevent duplicates easily
                        if !ips.contains(&ip) {
                            ips.push(ip);
                        }
                    }
                    Err(_) => {
                        return Err(ConfigError::InvalidDnsValue {
                            key: "servers",
                            found: format!("Invalid IP address: {s}"),
                        });
                    }
                }
            }
            ips
        }
        None => vec![],
    };

    Ok(DnsSettings { enabled, servers })
}

// ============================================================================
// v0.9 (Stage 6.1) Tunnel topology settings loaded from config file `[tunnel]` section.
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Topology {
    Default,
    WindowsIcs,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelSettings {
    pub topology: Topology,
}

impl Default for TunnelSettings {
    fn default() -> Self {
        TunnelSettings {
            topology: Topology::Default,
        }
    }
}

pub fn load_tunnel_settings(path: &str) -> Result<TunnelSettings, ConfigError> {
    let contents = fs::read_to_string(path)?;

    let topology = match find_value(&contents, "tunnel", "topology") {
        Some(value) => match value.as_str() {
            "default" => Topology::Default,
            "windows-ics" => Topology::WindowsIcs,
            other => {
                return Err(ConfigError::InvalidTunnelValue {
                    key: "topology",
                    found: other.to_string(),
                })
            }
        },
        None => TunnelSettings::default().topology,
    };

    Ok(TunnelSettings { topology })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static TEST_FILE_COUNTER: AtomicUsize = AtomicUsize::new(0);

    /// Write `contents` to a fresh temp file and return its path. Each
    /// call gets a unique filename so parallel tests never collide.
    fn write_temp_config(contents: &str) -> std::path::PathBuf {
        let id = TEST_FILE_COUNTER.fetch_add(1, Ordering::SeqCst);
        let mut path = std::env::temp_dir();
        path.push(format!("tiny_vpn_test_config_{}_{id}.toml", std::process::id()));
        let mut file = fs::File::create(&path).unwrap();
        file.write_all(contents.as_bytes()).unwrap();
        path
    }

    #[test]
    fn loads_key_from_crypto_section() {
        let path = write_temp_config(
            "[server]\naddress = \"127.0.0.1:8080\"\n\n[crypto]\nkey = \"deadbeef\"\n",
        );
        let hex = load_crypto_key_hex(path.to_str().unwrap()).unwrap();
        assert_eq!(hex, "deadbeef");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn ignores_keys_outside_crypto_section() {
        let path = write_temp_config(
            "key = \"not-this-one\"\n[server]\nkey = \"also-not-this-one\"\n[crypto]\nkey = \"the-real-one\"\n",
        );
        let hex = load_crypto_key_hex(path.to_str().unwrap()).unwrap();
        assert_eq!(hex, "the-real-one");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn missing_section_is_reported() {
        let path = write_temp_config("[server]\naddress = \"127.0.0.1:8080\"\n");
        match load_crypto_key_hex(path.to_str().unwrap()) {
            Err(ConfigError::MissingCryptoSection) => {}
            other => panic!("expected MissingCryptoSection, got {other:?}"),
        }
        let _ = fs::remove_file(path);
    }

    #[test]
    fn missing_key_in_section_is_reported() {
        let path = write_temp_config("[crypto]\n# no key here\n");
        match load_crypto_key_hex(path.to_str().unwrap()) {
            Err(ConfigError::MissingKey) => {}
            other => panic!("expected MissingKey, got {other:?}"),
        }
        let _ = fs::remove_file(path);
    }

    #[test]
    fn missing_file_is_reported_as_io_error() {
        match load_crypto_key_hex("/nonexistent/path/to/config.toml") {
            Err(ConfigError::Io(_)) => {}
            other => panic!("expected Io error, got {other:?}"),
        }
    }

    // ------------------------------------------------------------------
    // v0.8 [routing] section tests
    // ------------------------------------------------------------------

    #[test]
    fn routing_settings_default_when_section_absent() {
        let path = write_temp_config("[crypto]\nkey = \"deadbeef\"\n");
        let settings = load_routing_settings(path.to_str().unwrap()).unwrap();
        assert_eq!(settings, RoutingSettings::default());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn routing_settings_parses_explicit_values() {
        let path = write_temp_config(
            "[routing]\nnat_enabled = false\noutbound_interface = \"eth0\"\n",
        );
        let settings = load_routing_settings(path.to_str().unwrap()).unwrap();
        assert_eq!(
            settings,
            RoutingSettings {
                nat_enabled: false,
                outbound_interface: Some("eth0".to_string()),
            }
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn routing_settings_nat_enabled_defaults_true_when_key_absent() {
        let path = write_temp_config("[routing]\noutbound_interface = \"eth0\"\n");
        let settings = load_routing_settings(path.to_str().unwrap()).unwrap();
        assert!(settings.nat_enabled);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn routing_settings_outbound_interface_defaults_none_when_absent() {
        let path = write_temp_config("[routing]\nnat_enabled = true\n");
        let settings = load_routing_settings(path.to_str().unwrap()).unwrap();
        assert_eq!(settings.outbound_interface, None);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn routing_settings_invalid_nat_enabled_value_is_rejected() {
        let path = write_temp_config("[routing]\nnat_enabled = maybe\n");
        match load_routing_settings(path.to_str().unwrap()) {
            Err(ConfigError::InvalidRoutingValue { key: "nat_enabled", .. }) => {}
            other => panic!("expected InvalidRoutingValue, got {other:?}"),
        }
        let _ = fs::remove_file(path);
    }

    // ------------------------------------------------------------------
    // v0.8.5 client [routing] section tests
    // ------------------------------------------------------------------

    #[test]
    fn client_routing_settings_default_when_section_absent() {
        let path = write_temp_config("[crypto]\nkey = \"deadbeef\"\n");
        let settings = load_client_routing_settings(path.to_str().unwrap()).unwrap();
        assert_eq!(settings, ClientRoutingSettings::default());
        assert_eq!(settings.mode, RoutingMode::Disabled);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn client_routing_settings_parses_split_mode_with_routes() {
        let path = write_temp_config(
            "[routing]\nmode = \"split\"\nroutes = [\"10.20.0.0/24\", \"10.30.0.0/16\"]\n",
        );
        let settings = load_client_routing_settings(path.to_str().unwrap()).unwrap();
        assert_eq!(settings.mode, RoutingMode::Split);
        assert_eq!(
            settings.routes,
            vec!["10.20.0.0/24".to_string(), "10.30.0.0/16".to_string()]
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn client_routing_settings_parses_full_mode() {
        let path = write_temp_config("[routing]\nmode = \"full\"\n");
        let settings = load_client_routing_settings(path.to_str().unwrap()).unwrap();
        assert_eq!(settings.mode, RoutingMode::Full);
        assert!(settings.routes.is_empty());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn client_routing_settings_invalid_mode_is_rejected() {
        let path = write_temp_config("[routing]\nmode = \"turbo\"\n");
        match load_client_routing_settings(path.to_str().unwrap()) {
            Err(ConfigError::InvalidRoutingValue { key: "mode", .. }) => {}
            other => panic!("expected InvalidRoutingValue, got {other:?}"),
        }
        let _ = fs::remove_file(path);
    }

    #[test]
    fn client_routing_settings_empty_route_list_parses_as_empty_vec() {
        let path = write_temp_config("[routing]\nmode = \"split\"\nroutes = []\n");
        let settings = load_client_routing_settings(path.to_str().unwrap()).unwrap();
        assert!(settings.routes.is_empty());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn client_routing_settings_malformed_route_list_is_rejected() {
        let path = write_temp_config("[routing]\nmode = \"split\"\nroutes = \"not-a-list\"\n");
        match load_client_routing_settings(path.to_str().unwrap()) {
            Err(ConfigError::InvalidRouteList { .. }) => {}
            other => panic!("expected InvalidRouteList, got {other:?}"),
        }
        let _ = fs::remove_file(path);
    }

    #[test]
    fn client_routing_settings_routes_ignored_in_full_mode_but_still_parsed() {
        let path = write_temp_config(
            "[routing]\nmode = \"full\"\nroutes = [\"10.20.0.0/24\"]\n",
        );
        let settings = load_client_routing_settings(path.to_str().unwrap()).unwrap();
        assert_eq!(settings.mode, RoutingMode::Full);
        // Parsed regardless, even though Full mode's plan doesn't use it
        // -- routing::build_client_routing_plan simply ignores `routes`
        assert_eq!(settings.routes, vec!["10.20.0.0/24".to_string()]);
        let _ = fs::remove_file(path);
    }
    
    // ------------------------------------------------------------------
    // v0.9 DNS tests
    // ------------------------------------------------------------------
    #[test]
    fn dns_settings_default_when_absent() {
        let path = write_temp_config("[client]\n");
        let settings = load_dns_settings(path.to_str().unwrap()).unwrap();
        assert_eq!(settings.enabled, false);
        assert!(settings.servers.is_empty());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn dns_settings_enabled_one_server() {
        let path = write_temp_config("[dns]\nenabled = true\nservers = [\"10.13.13.2\"]\n");
        let settings = load_dns_settings(path.to_str().unwrap()).unwrap();
        assert_eq!(settings.enabled, true);
        assert_eq!(settings.servers, vec!["10.13.13.2".parse::<std::net::IpAddr>().unwrap()]);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn dns_settings_enabled_multiple_servers_and_duplicates() {
        let path = write_temp_config("[dns]\nenabled = true\nservers = [\"10.13.13.2\", \"1.1.1.1\", \"10.13.13.2\"]\n");
        let settings = load_dns_settings(path.to_str().unwrap()).unwrap();
        assert_eq!(settings.enabled, true);
        assert_eq!(settings.servers.len(), 2);
        assert_eq!(settings.servers[0], "10.13.13.2".parse::<std::net::IpAddr>().unwrap());
        assert_eq!(settings.servers[1], "1.1.1.1".parse::<std::net::IpAddr>().unwrap());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn dns_settings_invalid_ip() {
        let path = write_temp_config("[dns]\nservers = [\"not.an.ip\"]\n");
        match load_dns_settings(path.to_str().unwrap()) {
            Err(ConfigError::InvalidDnsValue { key: "servers", .. }) => {}
            other => panic!("expected InvalidDnsValue, got {other:?}"),
        }
        let _ = fs::remove_file(path);
    }

    #[test]
    fn dns_settings_empty_list() {
        let path = write_temp_config("[dns]\nenabled = true\nservers = []\n");
        let settings = load_dns_settings(path.to_str().unwrap()).unwrap();
        assert_eq!(settings.enabled, true);
        assert!(settings.servers.is_empty());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn dns_settings_ipv6_support() {
        let path = write_temp_config("[dns]\nservers = [\"2606:4700:4700::1111\"]\n");
        let settings = load_dns_settings(path.to_str().unwrap()).unwrap();
        assert_eq!(settings.servers[0], "2606:4700:4700::1111".parse::<std::net::IpAddr>().unwrap());
        let _ = fs::remove_file(path);
    }
}