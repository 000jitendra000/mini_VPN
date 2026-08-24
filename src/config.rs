//! Minimal config-file loading (v0.6).
//!
//! Just enough hand-written parsing to read a `[crypto]` section's `key`
//! entry out of a TOML-flavored config file, without adding a TOML/serde
//! dependency (none is needed for something this small).
//!
//! This is intentionally NOT a general TOML parser: it understands only
//! `[section]` headers and `key = "quoted value"` lines within a section,
//! skips blank lines and `#` comments, and ignores every section except
//! `[crypto]`. That covers everything this project's config files need
//! right now. If a real TOML parser is ever warranted, it should replace
//! this rather than grow it.
//!
//! This module only extracts the raw hex string from config; it does not
//! validate it as key bytes or touch any cryptographic code -- see
//! `crypto::parse_key_hex` for that.

use std::fmt;
use std::fs;
use std::io;

/// Errors from loading/parsing a config file.
#[derive(Debug)]
pub enum ConfigError {
    Io(io::Error),
    MissingCryptoSection,
    MissingKey,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::Io(e) => write!(f, "could not read config file: {e}"),
            ConfigError::MissingCryptoSection => write!(f, "config file has no [crypto] section"),
            ConfigError::MissingKey => write!(f, "[crypto] section has no 'key' entry"),
        }
    }
}

impl std::error::Error for ConfigError {}

impl From<io::Error> for ConfigError {
    fn from(e: io::Error) -> Self {
        ConfigError::Io(e)
    }
}

/// Load the `[crypto] key = "..."` value from a config file at `path`,
/// returning the raw hex string exactly as written (not yet parsed or
/// validated as key bytes).
pub fn load_crypto_key_hex(path: &str) -> Result<String, ConfigError> {
    let contents = fs::read_to_string(path)?;

    let mut in_crypto_section = false;
    let mut found_crypto_section = false;

    for raw_line in contents.lines() {
        let line = raw_line.trim();

        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if let Some(section) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            in_crypto_section = section.trim() == "crypto";
            if in_crypto_section {
                found_crypto_section = true;
            }
            continue;
        }

        if !in_crypto_section {
            continue;
        }

        if let Some((name, value)) = line.split_once('=') {
            if name.trim() == "key" {
                let value = value.trim();
                let unquoted = value
                    .strip_prefix('"')
                    .and_then(|v| v.strip_suffix('"'))
                    .unwrap_or(value);
                return Ok(unquoted.to_string());
            }
        }
    }

    if found_crypto_section {
        Err(ConfigError::MissingKey)
    } else {
        Err(ConfigError::MissingCryptoSection)
    }
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
}