use crate::routing::{RoutingConfig};
use std::io;

// On Android, routing is managed natively via Kotlin `Builder.addRoute()` before FD establishment.
// The Rust side explicitly does NOT execute route side-effects.

/// No-op server route guard. Server target is outside the immediate scope for Stage 5.
pub struct Guard;
pub struct ClientRouteGuard;

impl Drop for Guard {
    fn drop(&mut self) {}
}

impl Drop for ClientRouteGuard {
    fn drop(&mut self) {}
}

pub fn apply(_config: &RoutingConfig) -> io::Result<Guard> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Cannot apply server NAT routes internally on Android.",
    ))
}

pub fn current_route_to(_endpoint_ip: &str) -> io::Result<crate::routing::RouteVia> {
    // Under VpnService.protect() boundaries, this isn't actually invoked for routing rules locally in Rust.
    Ok(crate::routing::RouteVia::Gateway {
        gateway: "Android-VpnService".to_string(),
        device: "rmnet".to_string(),
    })
}

pub fn apply_client_routes(_plan: &crate::routing::ClientRoutingPlan) -> io::Result<ClientRouteGuard> {
    // Return functionally successful guard to allow loops to proceed uninhibited (Kotlin natively manages routing).
    Ok(ClientRouteGuard)
}

pub fn install_shutdown_handler() {}

pub fn shutdown_requested() -> bool {
    false // Shutdown natively interrupts standard FDs in JNI block instead of setting atomic flags via SIGINT handlers.
}
