//! Unsupported platform fallback for routing.
//!
//! Provides the required type shapes for `RoutingGuard` and `ClientRouteGuard`
//! so the cross-platform VPN core can compile cleanly on targets without a
//! configured platform routing backend, failing only at runtime.

use std::io;
use super::{RoutingConfig, ClientRoutingPlan};

pub struct Guard;
pub struct ClientRouteGuard;

pub fn apply(_config: &RoutingConfig) -> io::Result<Guard> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "Routing/NAT backend not implemented for this platform"))
}

pub fn apply_client_routes(_plan: &ClientRoutingPlan) -> io::Result<ClientRouteGuard> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "Client routing backend not implemented for this platform"))
}

pub fn install_shutdown_handler() {
}

pub fn shutdown_requested() -> bool {
    false
}

pub fn current_route_to(_endpoint: &str) -> io::Result<super::RouteVia> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "Routing not implemented for this platform"))
}
