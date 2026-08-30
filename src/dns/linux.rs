use std::io;
use std::process::Command;

pub struct Guard {
    tun_interface: String,
}

impl Drop for Guard {
    fn drop(&mut self) {
        println!("DNS: Reverting temporary resolver settings for {}...", self.tun_interface);
        let output = Command::new("resolvectl")
            .arg("revert")
            .arg(&self.tun_interface)
            .output();

        match output {
            Ok(out) if out.status.success() => {
                println!("DNS: Successfully reverted DNS settings for {}", self.tun_interface);
            }
            Ok(out) => {
                let err = String::from_utf8_lossy(&out.stderr);
                eprintln!("DNS: Failed to revert DNS settings: {}", err.trim());
            }
            Err(e) => {
                eprintln!("DNS: Execution of resolvectl revert failed: {}", e);
            }
        }
    }
}

pub fn apply(config: &super::DnsConfig, tun_interface: &str) -> io::Result<Guard> {
    if !config.enabled || config.servers.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Cannot apply inherently empty or disabled DNS definitions payload",
        ));
    }

    // Check if resolvectl exists
    match Command::new("resolvectl").arg("--version").output() {
        Ok(out) if out.status.success() => {
             // resolvectl is available
        }
        _ => {
            eprintln!("DNS: 'resolvectl' is missing or failed to run. This environment lacks the required DNS manager.");
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Linux resolvectl required for temporary non-destructive DNS bindings but missing.",
            ));
        }
    }

    println!("DNS: Binding configurations temporarily to {} via resolvectl...", tun_interface);

    let mut dns_args = vec!["dns".to_string(), tun_interface.to_string()];
    for ip in &config.servers {
        dns_args.push(ip.to_string());
    }

    let status = Command::new("resolvectl")
        .args(&dns_args)
        .status()?;

    if !status.success() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "Failed to configure resolvectl dns servers",
        ));
    }

    // Bind resolve domain defaults directly intercepting all requests safely routing through the tunnel interface.
    let domain_status = Command::new("resolvectl")
        .args(&["domain", tun_interface, "~."])
        .status()?;

    if !domain_status.success() {
        // Since dns servers were applied, we should probably manually revert them now but since we return an error, the Guard isn't dropping.
         Command::new("resolvectl")
            .arg("revert")
            .arg(tun_interface)
            .status()
            .unwrap_or_default();

        return Err(io::Error::new(
            io::ErrorKind::Other,
            "Failed to configure resolvectl domain ~.",
        ));
    }

    println!("DNS: Configured resolver settings mapping perfectly for link {}", tun_interface);

    Ok(Guard {
        tun_interface: tun_interface.to_string(),
    })
}
