#[cfg(windows)]
#[path = "win32/mod.rs"]
mod platform;
#[cfg(unix)]
#[path = "unix/mod.rs"]
pub mod platform;
pub use platform::*;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SockAddrBuffer {
    pub family: u16,
    pub port: u16,
    pub buf: [u8; 24],
}

#[inline]
pub fn init() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| { let _ = std::net::UdpSocket::bind("127.0.0.1:34254"); });
}