//! Windows routing/NAT fallback + shutdown handler

use std::io;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};

static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

extern "system" fn ctrl_handler(_ctrl_type: u32) -> windows_sys::Win32::Foundation::BOOL {
    SHUTDOWN_REQUESTED.store(true, Ordering::SeqCst);
    crate::tun::windows::shutdown_active_sessions();
    windows_sys::Win32::Foundation::TRUE
}

pub fn install_shutdown_handler() {
    unsafe {
        windows_sys::Win32::System::Console::SetConsoleCtrlHandler(
            Some(ctrl_handler),
            windows_sys::Win32::Foundation::TRUE,
        );
    }
}

pub fn shutdown_requested() -> bool {
    SHUTDOWN_REQUESTED.load(Ordering::SeqCst)
}

/// Helper to run powershell commands safely and surface clear errors.
fn run_powershell(command: &str) -> io::Result<String> {
    let output = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", command])
        .output()
        .map_err(|e| io::Error::new(e.kind(), format!("failed to launch powershell: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!(
                "powershell command failed (status {}). Requires Administrator privileges? stderr: {}, stdout: {}",
                output.status,
                stderr.trim(),
                stdout.trim()
            ),
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

// ----------------------------------------------------------------------------
// Client Routing
// ----------------------------------------------------------------------------

pub struct ClientRouteGuard {
    added_route_deletions: Vec<String>,
}

impl Drop for ClientRouteGuard {
    fn drop(&mut self) {
        for remove_cmd in self.added_route_deletions.iter().rev() {
            if let Err(e) = run_powershell(remove_cmd) {
                eprintln!("Client: failed to remove route during cleanup: {e}");
            }
        }
        if !self.added_route_deletions.is_empty() {
            println!("Client: routing table restored to its pre-VPN state");
        }
    }
}

pub fn apply_client_routes(plan: &super::ClientRoutingPlan) -> io::Result<ClientRouteGuard> {
    let mut added_route_deletions: Vec<String> = Vec::new();

    for route in &plan.routes {
        let add_cmd: String;
        let del_cmd: String;

        match &route.via {
            super::RouteVia::Device(device) => {
                add_cmd = format!(
                    "New-NetRoute -DestinationPrefix '{}' -InterfaceAlias '{}' -PolicyStore ActiveStore -ErrorAction Stop",
                    route.destination, device
                );
                del_cmd = format!(
                    "Remove-NetRoute -DestinationPrefix '{}' -InterfaceAlias '{}' -Confirm:$false -ErrorAction Continue",
                    route.destination, device
                );
            }
            super::RouteVia::Gateway { gateway, device } => {
                add_cmd = format!(
                    "New-NetRoute -DestinationPrefix '{}' -NextHop '{}' -InterfaceAlias '{}' -PolicyStore ActiveStore -ErrorAction Stop",
                    route.destination, gateway, device
                );
                del_cmd = format!(
                    "Remove-NetRoute -DestinationPrefix '{}' -NextHop '{}' -InterfaceAlias '{}' -Confirm:$false -ErrorAction Continue",
                    route.destination, gateway, device
                );
            }
        }

        if let Err(e) = run_powershell(&add_cmd) {
            for already_added_del in added_route_deletions.iter().rev() {
                let _ = run_powershell(already_added_del);
            }
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to add route {}: {}", route.destination, e),
            ));
        }

        println!("Client: route added: {}", route.destination);
        added_route_deletions.push(del_cmd);
    }

    Ok(ClientRouteGuard {
        added_route_deletions,
    })
}

pub fn current_route_to(ip: &str) -> io::Result<super::RouteVia> {
    let find_cmd = format!(
        "Find-NetRoute -RemoteIPAddress '{}' -ErrorAction Stop | Select-Object -First 1 | ForEach-Object {{ $_.NextHop + '|' + $_.InterfaceAlias }}",
        ip
    );
    let out = run_powershell(&find_cmd)?;

    if out.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("No route found to {}", ip),
        ));
    }

    let parts: Vec<&str> = out.split('|').collect();
    if parts.len() != 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Unexpected output from Find-NetRoute: {}", out),
        ));
    }

    let next_hop = parts[0].trim();
    let interface_alias = parts[1].trim();

    if next_hop.is_empty() || next_hop == "0.0.0.0" || next_hop == "::" {
        Ok(super::RouteVia::Device(interface_alias.to_string()))
    } else {
        Ok(super::RouteVia::Gateway {
            gateway: next_hop.to_string(),
            device: interface_alias.to_string(),
        })
    }
}

// ----------------------------------------------------------------------------
// Server Forwarding & NAT
// ----------------------------------------------------------------------------

enum NatBackend {
    NetNat(String),
    Ics {
        public_interface: String,
        private_interface: String,
        original_scope_address: Option<String>,
        original_standalone_dhcp_address: Option<String>,
    },
}

pub struct Guard {
    previous_forwarding_enabled: bool,
    tun_interface: String,
    nat_backend: Option<NatBackend>,
}

impl Drop for Guard {
    fn drop(&mut self) {
        if let Some(backend) = &self.nat_backend {
            match backend {
                NatBackend::NetNat(name) => {
                    let del_nat = format!(
                        "Remove-NetNat -Name '{}' -Confirm:$false -ErrorAction Continue",
                        name
                    );
                    if let Err(e) = run_powershell(&del_nat) {
                        eprintln!("Server: failed to remove NAT {}: {}", name, e);
                        eprintln!("  Manual recovery: Remove-NetNat -Name '{}' -Confirm:$false", name);
                    } else {
                        println!("Server: removed NAT {}", name);
                    }
                }
                NatBackend::Ics {
                    public_interface,
                    private_interface,
                    original_scope_address,
                    original_standalone_dhcp_address,
                } => {
                    // 1. Disable ICS
                    let script = format!(
                        r#"
$netShare = New-Object -ComObject HNetCfg.HNetShare -ErrorAction SilentlyContinue
if ($netShare) {{
    foreach ($c in $netShare.EnumEveryConnection) {{
        $name = $netShare.NetConnectionProps($c).Name
        if ($name -eq '{}' -or $name -eq '{}') {{
            $netShare.INetSharingConfigurationForINetConnection($c).DisableSharing()
        }}
    }}
}}
"#,
                        public_interface, private_interface
                    );
                    if let Err(e) = run_powershell(&script) {
                        eprintln!("Server: failed to disable ICS during cleanup: {}", e);
                    } else {
                        println!("Server: ICS sharing disabled");
                    }

                    // 2. Restore Registry
                    let restore_reg = |name: &str, val: &Option<String>| {
                        let inner_cmd = match val {
                            Some(v) => format!("Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Services\\SharedAccess\\Parameters' -Name '{}' -Value '{}' -ErrorAction Continue", name, v),
                            None => format!("Remove-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Services\\SharedAccess\\Parameters' -Name '{}' -ErrorAction SilentlyContinue", name),
                        };
                        if let Err(e) = run_powershell(&inner_cmd) {
                            eprintln!("Server: failed to restore registry key {} during cleanup: {}", name, e);
                            eprintln!("  Manual recovery: Run PowerShell: {}", inner_cmd);
                        }
                    };
                    restore_reg("ScopeAddress", original_scope_address);
                    restore_reg("StandaloneDhcpAddress", original_standalone_dhcp_address);
                }
            }
        }

        if !self.previous_forwarding_enabled {
            let restore_fwd = format!(
                "Set-NetIPInterface -InterfaceAlias '{}' -Forwarding Disabled -ErrorAction Continue",
                self.tun_interface
            );
            if let Err(e) = run_powershell(&restore_fwd) {
                eprintln!(
                    "Server: failed to disable IP forwarding on tun interface: {}",
                    e
                );
            } else {
                println!(
                    "Server: IP forwarding restored to disabled on {}",
                    self.tun_interface
                );
            }
        }
    }
}

fn detect_outbound_interface() -> io::Result<String> {
    let cmd = "Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop | Sort-Object RouteMetric | Select-Object -First 1 -ExpandProperty InterfaceAlias";
    let iface = run_powershell(cmd)?;
    if iface.is_empty() {
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "Could not find default outbound interface",
        ))
    } else {
        Ok(iface)
    }
}

fn apply_ics_fallback(config: &super::RoutingConfig, outbound_interface: &str) -> io::Result<NatBackend> {
    println!("Server: attempting ICS fallback configuration...");

    let read_reg = |name: &str| -> io::Result<Option<String>> {
        let cmd = format!("Get-ItemPropertyValue -Path 'HKLM:\\System\\CurrentControlSet\\Services\\SharedAccess\\Parameters' -Name '{}' -ErrorAction SilentlyContinue", name);
        match run_powershell(&cmd) {
            Ok(v) if !v.is_empty() => Ok(Some(v)),
            _ => Ok(None),
        }
    };

    let original_scope_address = read_reg("ScopeAddress")?;
    let original_standalone_dhcp_address = read_reg("StandaloneDhcpAddress")?;

    // Create a temporary Drop guard in case enabling fails part-way
    struct TempIcsGuard {
        public_interface: String,
        private_interface: String,
        original_scope_address: Option<String>,
        original_standalone_dhcp_address: Option<String>,
        sharing_enabled: bool,
    }
    
    impl Drop for TempIcsGuard {
        fn drop(&mut self) {
            if self.sharing_enabled {
                let script = format!(
                    r#"
$netShare = New-Object -ComObject HNetCfg.HNetShare -ErrorAction SilentlyContinue
if ($netShare) {{
    foreach ($c in $netShare.EnumEveryConnection) {{
        $name = $netShare.NetConnectionProps($c).Name
        if ($name -eq '{}' -or $name -eq '{}') {{
            $netShare.INetSharingConfigurationForINetConnection($c).DisableSharing()
        }}
    }}
}}
"#,
                    self.public_interface, self.private_interface
                );
                let _ = run_powershell(&script);
            }
            
            let restore_reg = |name: &str, val: &Option<String>| {
                let inner_cmd = match val {
                    Some(v) => format!("Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Services\\SharedAccess\\Parameters' -Name '{}' -Value '{}' -ErrorAction Continue", name, v),
                    None => format!("Remove-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Services\\SharedAccess\\Parameters' -Name '{}' -ErrorAction SilentlyContinue", name),
                };
                let _ = run_powershell(&inner_cmd);
            };
            restore_reg("ScopeAddress", &self.original_scope_address);
            restore_reg("StandaloneDhcpAddress", &self.original_standalone_dhcp_address);
        }
    }

    let mut temp_guard = TempIcsGuard {
        public_interface: outbound_interface.to_string(),
        private_interface: config.tun_interface.clone(),
        original_scope_address: original_scope_address.clone(),
        original_standalone_dhcp_address: original_standalone_dhcp_address.clone(),
        sharing_enabled: false, // Wait until we touch ICS
    };

    // 1. Verify sharing state
    let verify_script = format!(
        r#"
$netShare = New-Object -ComObject HNetCfg.HNetShare
foreach ($c in $netShare.EnumEveryConnection) {{
    $name = $netShare.NetConnectionProps($c).Name
    $conf = $netShare.INetSharingConfigurationForINetConnection($c)
    if ($conf -and $conf.SharingEnabled) {{
        if ($name -ne '{}' -and $name -ne '{}') {{
            Write-Output "ALREADY_SHARED_$name"
            exit
        }}
    }}
}}
"#,
        outbound_interface, config.tun_interface
    );
    let verify_out = run_powershell(&verify_script)?;
    if verify_out.contains("ALREADY_SHARED") {
        return Err(io::Error::new(io::ErrorKind::AlreadyExists, format!("Another interface is already natively shared: {}", verify_out)));
    }

    // 2. Override the registry for ICS Subnet Assignment
    let expected_server_ip = format!("{}.{}.{}.{}", config.address_plan.server_address.0, config.address_plan.server_address.1, config.address_plan.server_address.2, config.address_plan.server_address.3);
    let set_reg = |name: &str, val: &str| -> io::Result<()> {
        let cmd = format!("Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Services\\SharedAccess\\Parameters' -Name '{}' -Value '{}' -ErrorAction Stop", name, val);
        run_powershell(&cmd).map(|_| ())
    };
    
    set_reg("ScopeAddress", &expected_server_ip)?;
    set_reg("StandaloneDhcpAddress", &expected_server_ip)?;

    // 3. Enable Sharing
    let enable_script = format!(
        r#"
$ErrorActionPreference = 'Stop'
$netShare = New-Object -ComObject HNetCfg.HNetShare
$pubConf = $null
$privConf = $null
foreach ($c in $netShare.EnumEveryConnection) {{
    $name = $netShare.NetConnectionProps($c).Name
    $conf = $netShare.INetSharingConfigurationForINetConnection($c)
    if ($name -eq '{}') {{ $pubConf = $conf }}
    if ($name -eq '{}') {{ $privConf = $conf }}
}}
if ($null -eq $pubConf -or $null -eq $privConf) {{
    throw "Required interfaces not found for ICS."
}}
$pubConf.EnableSharing(0)
$privConf.EnableSharing(1)
"#,
        outbound_interface, config.tun_interface
    );
    run_powershell(&enable_script)?;
    temp_guard.sharing_enabled = true;
    
    // Briefly poll and confirm IP assigned to the TUN Interface
    let poll_script = format!(
        "for ($i=0; $i -lt 10; $i++) {{ $ip = Get-NetIPAddress -InterfaceAlias '{}' -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty IPAddress; if ($ip) {{ Write-Output $ip; exit }}; Start-Sleep -Milliseconds 500 }}; Write-Output 'NONE'",
        config.tun_interface
    );
    let assigned_ip = run_powershell(&poll_script)?;
    
    if assigned_ip.contains("NONE") || assigned_ip.is_empty() {
        return Err(io::Error::new(io::ErrorKind::Other, "Outcome C: ICS left the interface without an IPv4 address."));
    }
    
    let assigned_ip = assigned_ip.trim();

    if assigned_ip == expected_server_ip {
        println!("Server: ICS configured correctly and preserved {} (Outcome A).", expected_server_ip);
    } else {
        return Err(io::Error::new(io::ErrorKind::Other, format!("Outcome B/C: ICS assigned unexpected IP {} to the private interface. We expected {}, this is likely a topology mismatch. Try setting `topology = \"windows-ics\"` in your `[tunnel]` config section.", assigned_ip, expected_server_ip)));
    }

    // Success! Forget the temp_guard (avoid running Drop) and return NatBackend::Ics
    let _ = std::mem::ManuallyDrop::new(temp_guard);

    println!("Server NAT backend: ICS fallback");
    println!("Server (ICS) active IP on '{}': {}", config.tun_interface, assigned_ip);

    Ok(NatBackend::Ics {
        public_interface: outbound_interface.to_string(),
        private_interface: config.tun_interface.clone(),
        original_scope_address,
        original_standalone_dhcp_address,
    })
}

pub fn apply(config: &super::RoutingConfig) -> io::Result<Guard> {
    let outbound_interface = match &config.outbound_interface {
        Some(iface) => iface.clone(),
        None => detect_outbound_interface()?,
    };

    println!(
        "Server (experimental Windows backend): NAT outbound interface is {}",
        outbound_interface
    );

    // 1. Check existing forwarding status for the tun interface
    let fwd_cmd = format!("Get-NetIPInterface -InterfaceAlias '{}' -ErrorAction Stop | Select-Object -ExpandProperty Forwarding", config.tun_interface);
    let fwd_status = run_powershell(&fwd_cmd)?;
    let previous_forwarding_enabled = fwd_status.eq_ignore_ascii_case("Enabled");

    if previous_forwarding_enabled {
        println!(
            "Server: IP forwarding was already enabled on {}",
            config.tun_interface
        );
    } else {
        let enable_cmd = format!("Set-NetIPInterface -InterfaceAlias '{}' -Forwarding Enabled -ErrorAction Stop", config.tun_interface);
        if let Err(e) = run_powershell(&enable_cmd) {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "Failed to enable IP forwarding on {}: {}",
                    config.tun_interface, e
                ),
            ));
        }
        println!(
            "Server: IP forwarding enabled on {}",
            config.tun_interface
        );
    }

    // 2. Create a unique NAT object
    let nat_name = format!("tiny-vpn-nat-{}", std::process::id());

    let verify_cmd = format!(
        "Get-NetNat -Name '{}' -ErrorAction SilentlyContinue",
        nat_name
    );
    if let Ok(out) = run_powershell(&verify_cmd) {
        if !out.trim().is_empty() {
            if !previous_forwarding_enabled {
                let _ = run_powershell(&format!("Set-NetIPInterface -InterfaceAlias '{}' -Forwarding Disabled -ErrorAction SilentlyContinue", config.tun_interface));
            }
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("NAT object '{}' already exists", nat_name),
            ));
        }
    }

    let nat_cmd = format!("New-NetNat -Name '{}' -InternalIPInterfaceAddressPrefix '{}' -ErrorAction Stop", nat_name, config.vpn_subnet);
    let backend_res = match run_powershell(&nat_cmd) {
        Ok(_) => {
            println!("Server NAT backend: NetNat");
            println!(
                "Server: NAT rule created: {} for subnet {}",
                nat_name, config.vpn_subnet
            );
            Ok(NatBackend::NetNat(nat_name.clone()))
        }
        Err(e) => {
            let err_str = format!("{}", e);
            if err_str.contains("Invalid class") && err_str.contains("MSFT_NetNat") {
                apply_ics_fallback(config, &outbound_interface)
            } else {
                Err(e)
            }
        }
    };

    match backend_res {
        Ok(backend) => Ok(Guard {
            previous_forwarding_enabled,
            tun_interface: config.tun_interface.clone(),
            nat_backend: Some(backend),
        }),
        Err(e) => {
            if !previous_forwarding_enabled {
                let _ = run_powershell(&format!("Set-NetIPInterface -InterfaceAlias '{}' -Forwarding Disabled -ErrorAction SilentlyContinue", config.tun_interface));
            }
            Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to configure NAT backend: {}", e),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_construction_device_route() {
        let route = super::super::ClientRoute {
            destination: "10.20.0.0/24".to_string(),
            via: super::super::RouteVia::Device("tun0".to_string()),
        };
        assert_eq!(route.destination, "10.20.0.0/24");
        if let super::super::RouteVia::Device(dev) = route.via {
            assert_eq!(dev, "tun0");
        } else {
            panic!("Expected Device route");
        }
    }
}
