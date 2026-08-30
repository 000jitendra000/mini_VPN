use jni::objects::{JClass, JString};
use jni::sys::jint;
use jni::JNIEnv;
use std::net::UdpSocket;
use std::os::fd::FromRawFd;

use crate::client;
use crate::crypto;
use crate::tun;

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_tinyvpn_TinyVpnService_startVpnSession(
    mut env: JNIEnv,
    _class: JClass,
    vpn_fd: jint,
    udp_fd: jint,
    psk_jstring: JString,
    server_address_jstring: JString,
) {
    let psk_str: String = env.get_string(&psk_jstring).unwrap().into();
    let server_address: String = env.get_string(&server_address_jstring).unwrap().into();

    let psk = crypto::parse_key_hex(&psk_str).expect("Invalid PSK format. Must be a 64-character hex string.");

    if vpn_fd < 0 || udp_fd < 0 {
        eprintln!("Android Native VPN Error: Invalid File Descriptor (vpn_fd: {vpn_fd}, udp_fd: {udp_fd})");
        return;
    }

    // Turn Android FDs into Rust-owned types safely natively.
    // The FDs are now rigorously owned by Rust due to `detachFd()` and API 29+ boundaries protecting JVM garbage collection panics.
    let udp_socket = unsafe { UdpSocket::from_raw_fd(udp_fd) };
    let tun_device = tun::create_device_from_fd(vpn_fd);

    // Call the core library boundary to start loops.
    // Notice how authentication acts natively independently from FD duplication lifecycle contexts inside Rust space!
    match client::authenticate_with_socket(udp_socket, &server_address, &psk) {
        Ok(auth_client) => {
            println!("Android Native VPN Client authenticated successfully");
            if let Err(e) = auth_client.start_relay(tun_device) {
                eprintln!("Android Native VPN Relay returned error on graceful end: {e}");
            }
        }
        Err(e) => {
            eprintln!("Android VPN authentication failed: {}", e);
        }
    }
}
