//! Linux routing/NAT backend (v0.8).
//!
//! This is the **only** file in the project that runs `iptables`, reads
//! or writes `/proc/sys/net/ipv4/ip_forward`, or installs a signal
//! handler. `src/routing/mod.rs` wraps what it needs into the
//! platform-independent `RoutingConfig`/`RoutingGuard` shapes; nothing
//! else in the codebase touches any of this directly.
//!
//! # What gets configured
//!
//! 1. **IP forwarding**: the previous value of
//!    `/proc/sys/net/ipv4/ip_forward` is read and remembered, then set to
//!    `1` if it wasn't already.
//! 2. **NAT**: one `iptables -t nat` `MASQUERADE` rule rewrites the VPN
//!    subnet's source address to the outbound interface's address for
//!    outbound traffic.
//! 3. **Forwarding policy**: two `iptables` `FORWARD` rules explicitly
//!    `ACCEPT` VPN-subnet-to-outbound traffic and its established/related
//!    return traffic. (Enabling the forwarding sysctl only makes the
//!    kernel *capable* of forwarding; if the host's `FORWARD` chain
//!    default policy is `DROP` -- common on hardened hosts -- packets
//!    would still be dropped without these.)
//!
//! Every rule this module adds carries `-m comment --comment
//! "tiny-vpn"` so cleanup (and a human inspecting `iptables -L -n -v`)
//! can tell tiny-vpn's rules apart from anything else already on the
//! host. Cleanup only ever removes rules this exact process added
//! (tracked in `Guard`, not discovered by searching for the comment) --
//! it never flushes a chain or touches a rule it didn't create.
//!
//! # Partial-failure safety
//!
//! `apply` tracks each already-applied step as it goes. If a later step
//! fails, everything applied so far is rolled back before the error is
//! returned, so a failed `apply` never leaves the host half-configured.

use std::fs;
use std::io;
use std::mem;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};

/// Tag applied to every iptables rule this module adds, so cleanup only
/// ever touches tiny-vpn's own rules.
const RULE_COMMENT: &str = "tiny-vpn";

const IP_FORWARD_PATH: &str = "/proc/sys/net/ipv4/ip_forward";

/// RAII handle: on drop, removes exactly the iptables rules this
/// `apply()` call added (in reverse order) and restores whatever the IP
/// forwarding sysctl was set to before `apply()` ran.
pub struct Guard {
    previous_forwarding_enabled: bool,
    /// Each entry is a complete `iptables` argument list (e.g. `-D
    /// FORWARD ...`) that undoes one rule this module added.
    added_rule_deletions: Vec<Vec<String>>,
}

impl Drop for Guard {
    fn drop(&mut self) {
        for delete_args in self.added_rule_deletions.iter().rev() {
            let args: Vec<&str> = delete_args.iter().map(String::as_str).collect();
            if let Err(e) = run_iptables(&args) {
                eprintln!("Server: failed to remove routing rule during cleanup: {e}");
            }
        }

        match write_ip_forward(self.previous_forwarding_enabled) {
            Ok(()) => println!(
                "Server: IP forwarding restored to previous state ({})",
                if self.previous_forwarding_enabled {
                    "enabled"
                } else {
                    "disabled"
                }
            ),
            Err(e) => eprintln!("Server: failed to restore IP forwarding state: {e}"),
        }
    }
}

/// Configure forwarding/NAT for `config` and return a `Guard`. See the
/// module docs for exactly what's configured and how failures/cleanup
/// are handled.
pub fn apply(config: &super::RoutingConfig) -> io::Result<Guard> {
    let outbound_interface = match &config.outbound_interface {
        Some(iface) => iface.clone(),
        None => detect_outbound_interface()?,
    };
    println!("Server: routing/NAT outbound interface is {outbound_interface}");

    let previous_forwarding_enabled = read_ip_forward()?;
    if previous_forwarding_enabled {
        println!("Server: IP forwarding was already enabled");
    } else {
        write_ip_forward(true)?;
        println!("Server: IP forwarding enabled (was previously disabled)");
    }

    let rules = [
        nat_masquerade_rule(&config.vpn_subnet, &outbound_interface),
        forward_outbound_rule(&config.tun_interface, &outbound_interface),
        forward_return_rule(&config.tun_interface, &outbound_interface),
    ];

    let mut added_rule_deletions: Vec<Vec<String>> = Vec::new();
    for (add_args, delete_args) in &rules {
        let add_refs: Vec<&str> = add_args.iter().map(String::as_str).collect();
        if let Err(e) = run_iptables(&add_refs) {
            // Roll back everything already applied before propagating.
            for already_added in added_rule_deletions.iter().rev() {
                let refs: Vec<&str> = already_added.iter().map(String::as_str).collect();
                let _ = run_iptables(&refs);
            }
            let _ = write_ip_forward(previous_forwarding_enabled);
            return Err(e);
        }
        added_rule_deletions.push(delete_args.clone());
    }

    println!(
        "Server: NAT/forwarding rules installed for {} via {outbound_interface}",
        config.vpn_subnet
    );

    Ok(Guard {
        previous_forwarding_enabled,
        added_rule_deletions,
    })
}

/// Build the (add, delete) argument lists for the MASQUERADE rule that
/// rewrites the VPN subnet's source address for outbound traffic.
fn nat_masquerade_rule(vpn_subnet: &str, outbound_interface: &str) -> (Vec<String>, Vec<String>) {
    let build = |action: &str| -> Vec<String> {
        vec![
            "-t".into(),
            "nat".into(),
            action.into(),
            "POSTROUTING".into(),
            "-s".into(),
            vpn_subnet.into(),
            "-o".into(),
            outbound_interface.into(),
            "-m".into(),
            "comment".into(),
            "--comment".into(),
            RULE_COMMENT.into(),
            "-j".into(),
            "MASQUERADE".into(),
        ]
    };
    (build("-A"), build("-D"))
}

/// Build the (add, delete) argument lists for the `FORWARD` rule that
/// allows VPN-subnet traffic out through the outbound interface.
fn forward_outbound_rule(tun_interface: &str, outbound_interface: &str) -> (Vec<String>, Vec<String>) {
    let build = |action: &str| -> Vec<String> {
        vec![
            action.into(),
            "FORWARD".into(),
            "-i".into(),
            tun_interface.into(),
            "-o".into(),
            outbound_interface.into(),
            "-m".into(),
            "comment".into(),
            "--comment".into(),
            RULE_COMMENT.into(),
            "-j".into(),
            "ACCEPT".into(),
        ]
    };
    (build("-A"), build("-D"))
}

/// Build the (add, delete) argument lists for the `FORWARD` rule that
/// allows established/related return traffic back into the VPN subnet.
fn forward_return_rule(tun_interface: &str, outbound_interface: &str) -> (Vec<String>, Vec<String>) {
    let build = |action: &str| -> Vec<String> {
        vec![
            action.into(),
            "FORWARD".into(),
            "-i".into(),
            outbound_interface.into(),
            "-o".into(),
            tun_interface.into(),
            "-m".into(),
            "state".into(),
            "--state".into(),
            "ESTABLISHED,RELATED".into(),
            "-m".into(),
            "comment".into(),
            "--comment".into(),
            RULE_COMMENT.into(),
            "-j".into(),
            "ACCEPT".into(),
        ]
    };
    (build("-A"), build("-D"))
}

/// Run `iptables` with `args`, returning a clear error (including
/// iptables' own stderr) on any failure -- including "not found" (not
/// installed) and "permission denied" (not root), so a missing privilege
/// is reported plainly rather than silently doing nothing.
fn run_iptables(args: &[&str]) -> io::Result<()> {
    let output = Command::new("iptables").args(args).output().map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("failed to run iptables (is it installed, and are you root?): {e}"),
        )
    })?;

    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(io::Error::new(
            io::ErrorKind::Other,
            format!("iptables {args:?} failed: {}", stderr.trim()),
        ))
    }
}

/// Read the current IP forwarding sysctl value.
fn read_ip_forward() -> io::Result<bool> {
    let contents = fs::read_to_string(IP_FORWARD_PATH)?;
    Ok(contents.trim() == "1")
}

/// Set the IP forwarding sysctl value.
fn write_ip_forward(enabled: bool) -> io::Result<()> {
    fs::write(IP_FORWARD_PATH, if enabled { "1" } else { "0" })
}

/// Determine the outbound interface by parsing `ip route show default`
/// (`default via <gateway> dev <iface> ...`), used when
/// `RoutingConfig::outbound_interface` is `None`.
fn detect_outbound_interface() -> io::Result<String> {
    let output = Command::new("ip")
        .args(["route", "show", "default"])
        .output()
        .map_err(|e| {
            io::Error::new(e.kind(), format!("failed to run 'ip route show default': {e}"))
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("'ip route show default' failed: {}", stderr.trim()),
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut tokens = stdout.split_whitespace();
    while let Some(token) = tokens.next() {
        if token == "dev" {
            if let Some(iface) = tokens.next() {
                return Ok(iface.to_string());
            }
        }
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!(
            "could not find an outbound interface in the default route (is there one? \
             output was: {stdout:?}). Set [routing] outbound_interface in the server \
             config to specify it explicitly."
        ),
    ))
}

// ============================================================================
// Graceful shutdown (SIGINT).
//
// Rust's default disposition for SIGINT is to terminate the process
// immediately, which would skip `Guard::drop` entirely and leave iptables
// rules and a flipped forwarding sysctl behind. Installing a handler here
// (with `sa_flags = 0`, deliberately *not* `SA_RESTART`) makes a blocking
// syscall like `UdpSocket::recv_from` return `io::ErrorKind::Interrupted`
// on Ctrl+C instead of the process dying underneath it, so the server's
// receive loop can notice, return normally, and let its `Guard` (and any
// other RAII cleanup) run. Verified directly in this environment before
// relying on it: a plain `libc::signal` handler was NOT sufficient on its
// own without confirming `sigaction`'s flags -- see the v0.8 test report.
// ============================================================================

static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

extern "C" fn handle_sigint(_signal: libc::c_int) {
    SHUTDOWN_REQUESTED.store(true, Ordering::SeqCst);
}

/// Install the SIGINT handler described above. Safe to call
/// unconditionally (including when NAT/routing is disabled) -- it only
/// affects process signal handling, not any networking state.
pub fn install_shutdown_handler() {
    unsafe {
        let mut action: libc::sigaction = mem::zeroed();
        action.sa_sigaction = handle_sigint as usize;
        action.sa_flags = 0; // deliberately not SA_RESTART
        libc::sigemptyset(&mut action.sa_mask);
        libc::sigaction(libc::SIGINT, &action, std::ptr::null_mut());
    }
}

/// Whether a shutdown (SIGINT) has been requested since
/// `install_shutdown_handler` was called.
pub fn shutdown_requested() -> bool {
    SHUTDOWN_REQUESTED.load(Ordering::SeqCst)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Only genuinely read-only/non-destructive checks belong here.
    // Anything that would actually flip `/proc/sys/net/ipv4/ip_forward`
    // or add/remove real iptables rules is deliberately NOT an automated
    // `cargo test` -- see the v0.8 report for the separate, deliberate,
    // manual root-run integration test that covers that instead.

    #[test]
    fn nat_masquerade_rule_add_and_delete_are_symmetric_besides_the_action_flag() {
        let (add, delete) = nat_masquerade_rule("10.13.13.0/24", "eth0");
        assert_eq!(add[2], "-A");
        assert_eq!(delete[2], "-D");
        // Every other argument must be identical, so `delete` undoes
        // exactly the rule `add` created.
        let mut add_other = add.clone();
        let mut delete_other = delete.clone();
        add_other[2] = "X".into();
        delete_other[2] = "X".into();
        assert_eq!(add_other, delete_other);
        assert!(add.iter().any(|a| a == "MASQUERADE"));
        assert!(add.iter().any(|a| a == RULE_COMMENT));
    }

    #[test]
    fn forward_rules_reference_both_interfaces_in_opposite_directions() {
        let (out_add, _) = forward_outbound_rule("tiny-tun-server", "eth0");
        let (ret_add, _) = forward_return_rule("tiny-tun-server", "eth0");

        // Outbound: VPN -> internet.
        let in_pos = out_add.iter().position(|a| a == "-i").unwrap();
        let out_pos = out_add.iter().position(|a| a == "-o").unwrap();
        assert_eq!(out_add[in_pos + 1], "tiny-tun-server");
        assert_eq!(out_add[out_pos + 1], "eth0");

        // Return: internet -> VPN, restricted to established/related.
        let in_pos = ret_add.iter().position(|a| a == "-i").unwrap();
        let out_pos = ret_add.iter().position(|a| a == "-o").unwrap();
        assert_eq!(ret_add[in_pos + 1], "eth0");
        assert_eq!(ret_add[out_pos + 1], "tiny-tun-server");
        assert!(ret_add.iter().any(|a| a == "ESTABLISHED,RELATED"));
    }

    #[test]
    fn read_ip_forward_returns_a_value_without_mutating_anything() {
        // Purely a read -- safe in any environment, including CI without
        // root or a real /proc/sys/net/ipv4 tree wired up unusually.
        match read_ip_forward() {
            Ok(_) => {}
            Err(e) => {
                // Only acceptable failure mode: the file doesn't exist in
                // this environment (e.g. some restricted containers).
                assert_eq!(e.kind(), io::ErrorKind::NotFound);
            }
        }
    }

    #[test]
    fn detect_outbound_interface_parses_a_real_default_route_if_one_exists() {
        // Read-only (`ip route show default`); does not modify the host.
        // If the test environment has no default route at all, that's a
        // legitimate NotFound/Other result, not a bug in the parser.
        match detect_outbound_interface() {
            Ok(iface) => assert!(!iface.is_empty()),
            Err(_) => {} // no default route in this environment; fine
        }
    }
}