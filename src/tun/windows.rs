//! Windows Wintun packet device backend (Stage 4).
use std::io;
use std::sync::{Arc, Mutex, Weak};
use wintun::{Adapter, Session};

pub struct Device {
    #[allow(dead_code)] // Retained to keep the Wintun adapter alive
    adapter: Arc<Adapter>,
    session: Arc<Session>,
}

pub struct Reader {
    session: Arc<Session>,
}

pub struct Writer {
    session: Arc<Session>,
}

pub fn create_raw_device(name: &str, address: (u8, u8, u8, u8), netmask: (u8, u8, u8, u8)) -> io::Result<Device> {
    let wintun = if let Ok(path) = std::env::var("WINTUN_DLL_PATH") {
        unsafe { wintun::load_from_path(&path) }
            .map_err(|e| io::Error::new(io::ErrorKind::NotFound, format!("Failed to load WINTUN_DLL_PATH='{path}': {e}")))?
    } else {
        unsafe { wintun::load() }
            .map_err(|e| io::Error::new(io::ErrorKind::NotFound, format!("Failed to load wintun.dll (try setting WINTUN_DLL_PATH): {e}")))?
    };
    
    let adapter = match wintun::Adapter::open(&wintun, name) {
        Ok(a) => a,
        Err(_) => wintun::Adapter::create(&wintun, name, "TinyVPN", None).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to create Wintun adapter: {e}")))?
    };

    adapter.set_network_addresses_tuple(
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(address.0, address.1, address.2, address.3)),
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(netmask.0, netmask.1, netmask.2, netmask.3)),
        None
    ).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to configure Wintun IP/Netmask: {e}")))?;

    let session = adapter.start_session(wintun::MAX_RING_CAPACITY).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to start Wintun session: {e}")))?;
    let session = Arc::new(session);

    if let Ok(mut guard) = ACTIVE_SESSION.lock() {
        *guard = Some(Arc::downgrade(&session));
    }

    Ok(Device { adapter, session })
}

impl Device {
    pub fn split(self) -> (Reader, Writer) {
        (Reader { session: Arc::clone(&self.session) }, Writer { session: self.session })
    }
}

impl Reader {
    pub fn read_packet(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.session.receive_blocking() {
            Ok(packet) => {
                let bytes = packet.bytes();
                let len = bytes.len();
                if len > buf.len() {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "packet larger than buffer"));
                }
                buf[..len].copy_from_slice(bytes);
                Ok(len)
            }
            Err(wintun::Error::ShuttingDown) => {
                // Return EOF-like or interrupted when shutting down properly
                Err(io::Error::new(io::ErrorKind::Interrupted, "session shutting down"))
            }
            Err(e) => Err(io::Error::new(io::ErrorKind::Other, format!("Wintun receive error: {e}"))),
        }
    }
}

impl Writer {
    pub fn write_packet(&mut self, buf: &[u8]) -> io::Result<()> {
        let size = buf.len();
        if size > u16::MAX as usize {
             return Err(io::Error::new(io::ErrorKind::InvalidInput, "packet too big for wintun"));
        }
        let mut packet = self.session.allocate_send_packet(size as u16).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Wintun alloc error: {e}")))?;
        packet.bytes_mut().copy_from_slice(buf);
        self.session.send_packet(packet);
        Ok(())
    }
}

static ACTIVE_SESSION: Mutex<Option<Weak<Session>>> = Mutex::new(None);

pub fn shutdown_active_sessions() {
    if let Ok(guard) = ACTIVE_SESSION.lock() {
        if let Some(weak) = guard.as_ref() {
            if let Some(session) = weak.upgrade() {
                let _ = session.shutdown();
            }
        }
    }
}

pub fn run() -> io::Result<()> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "Standalone tun test not implemented for Windows"))
}
