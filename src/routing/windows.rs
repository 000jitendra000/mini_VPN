//! Windows routing/NAT fallback + shutdown handler
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};

pub struct Guard;

impl Drop for Guard {
    fn drop(&mut self) {}
}

pub struct ClientRouteGuard;

impl Drop for ClientRouteGuard {
    fn drop(&mut self) {}
}

pub fn apply(_config: &super::RoutingConfig) -> io::Result<Guard> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "Windows server routing not implemented in Stage 4"))
}

pub fn apply_client_routes(_plan: &super::ClientRoutingPlan) -> io::Result<ClientRouteGuard> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "Windows client routing not implemented in Stage 4"))
}

pub fn current_route_to(_ip: &str) -> io::Result<super::RouteVia> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "Windows routing not implemented in Stage 4"))
}

static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

extern "system" fn ctrl_handler(_ctrl_type: u32) -> windows_sys::Win32::Foundation::BOOL {
    SHUTDOWN_REQUESTED.store(true, Ordering::SeqCst);
    crate::tun::windows::shutdown_active_sessions();
    windows_sys::Win32::Foundation::TRUE
}

pub fn install_shutdown_handler() {
    unsafe {
        windows_sys::Win32::System::Console::SetConsoleCtrlHandler(Some(ctrl_handler), windows_sys::Win32::Foundation::TRUE);
    }
}

pub fn shutdown_requested() -> bool {
    SHUTDOWN_REQUESTED.load(Ordering::SeqCst)
}
