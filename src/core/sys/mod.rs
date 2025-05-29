#![allow(dead_code)]

#[cfg(windows)]
#[path = "win32.rs"]
pub mod platform;
#[cfg(unix)]
#[path = "unix.rs"]
pub mod platform;
pub use platform::*;

pub trait SockAddrBuffer {
    type RawSockAddr;

    fn new() -> Self;

    #[inline(always)]
    fn as_raw_ptr(&self) -> *const Self::RawSockAddr {
        self as *const _ as *const Self::RawSockAddr
    }

    #[inline(always)]
    fn as_raw_mut_ptr(&mut self) -> *mut Self::RawSockAddr {
        self as *mut _ as *mut Self::RawSockAddr
    }

    #[inline(always)]
    fn as_raw(&self) -> &Self::RawSockAddr {
        unsafe { &*self.as_raw_ptr() }
    }

    #[inline(always)]
    fn as_ptr(&self) -> *const u8 {
        self as *const _ as *const u8
    }

    #[inline(always)]
    fn as_mut_ptr(&mut self) -> *mut u8 {
        self as *mut _ as *mut u8
    }

    #[inline(always)]
    fn len(&self) -> usize {
        std::mem::size_of::<Self::RawSockAddr>()
    }
    
}

pub trait ToIpv4Addr {
    fn to_addr(&self) -> std::net::Ipv4Addr;
    fn to_socket_addr(&self) -> std::net::SocketAddr;
}

#[repr(C)]
pub struct SockAddrV4Buffer {
    raw: std::mem::MaybeUninit<SockAddrIn>
}

impl SockAddrBuffer for SockAddrV4Buffer {
    type RawSockAddr = SockAddrIn;

    #[inline(always)]
    fn new() -> Self {
        Self {
            raw: std::mem::MaybeUninit::uninit()
        }
    }
}
#[repr(C)]
pub struct SockAddrV6Buffer {
    raw: std::mem::MaybeUninit<SockAddrIn6>
}
pub trait SockaddrConvert {
    fn to_socket_addr(&self) -> std::io::Result<std::net::SocketAddr>;
    fn addr_len(&self) -> usize;
}
pub trait SocketAddrV4IntoSockAddrV4Buffer {
    fn into_sockaddrv4(&self) -> SockAddrV4Buffer;
}

pub trait SocketAddrV6IntoSockAddrV6Buffer {
    fn into_sockaddrv6(&self) -> SockAddrV6Buffer;
}

pub trait TimeValFromDuration {
    fn from_duration(duration: std::time::Duration) -> TimeVal;
}

#[inline]
pub fn init() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| { let _ = std::net::UdpSocket::bind("127.0.0.1:34254"); });
}