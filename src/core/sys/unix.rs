use std::os::raw::{c_int, c_void};
use super::SockAddrBuffer;

pub const AF_UNIX: c_int = 1;
pub const AF_INET: c_int = 2;
pub const AF_INET6: c_int = 10;
pub const AF_PACKET: c_int = 17;

pub const SOCK_STREAM: c_int = 1;
pub const SOCK_DGRAM: c_int = 2;
pub const SOCK_RAW: c_int = 3;
pub const SOCK_SEQPACKET: c_int = 5;

pub const SOL_SOCKET: c_int = 1;

pub const SO_REUSEADDR: c_int = 2;
pub const SO_RCVBUF: c_int = 8;
pub const SO_SNDBUF: c_int = 7;
pub const SO_RCVTIMEO: c_int = 20;
pub const SO_SNDTIMEO: c_int = 21;

pub const IPPROTO_TCP: c_int = 6;
pub const IPPROTO_UDP: c_int = 17;
pub const IPPROTO_ICMP: c_int = 1;
pub const IPPROTO_SCTP: c_int = 132;

pub const TCP_NODELAY: c_int = 1;

pub const F_GETFL: c_int = 3;
pub const O_NONBLOCK: c_int = 0o4000;

pub const SHUT_RD: c_int = 0;
pub const SHUT_WR: c_int = 1;

#[repr(C)]
pub struct SockLen(c_int);

#[repr(C)]
pub struct SockAddr {
    pub sa_family: u16,
    pub sa_data: [u8; 14],
}

#[repr(C)]
pub struct InAddr {
    pub s_addr: u32,
}

#[repr(C)]
pub struct In6Addr {
    pub s6_addr: [u8; 16],
}

#[repr(C)]
pub struct SockAddrIn {
    pub sin_family: u16,
    pub sin_port: u16,
    pub sin_addr: InAddr,
    pub sin_zero: [u8; 8],
}

#[repr(C)]
pub struct SockAddrIn6 {
    pub sin6_family: u16,
    pub sin6_port: u16,
    pub sin6_flowinfo: u32,
    pub sin6_addr: In6Addr,
    pub sin6_scope_id: u32,
}

#[repr(C)]
pub struct TimeVal {
    pub tv_sec: i64,
    pub tv_usec: i64,
}

extern "C" {
    pub fn socket(domain: c_int, ty: c_int, protocol: c_int) -> c_int;
    pub fn listen(sockfd: c_int, backlog: c_int) -> c_int;
    pub fn accept(sockfd: c_int, addr: *mut SockAddr, addrlen: *mut c_int) -> c_int;
    pub fn bind(sockfd: c_int, addr: *const SockAddr, addrlen: c_int) -> c_int;
    pub fn connect(sockfd: c_int, addr: *const SockAddr, addrlen: c_int) -> c_int;
    pub fn getpeername(sockfd: c_int, addr: *mut SockAddr, addrlen: *mut c_int) -> c_int;
    pub fn getsockname(sockfd: c_int, addr: *mut SockAddr, addrlen: *mut c_int) -> c_int;
    pub fn getsockopt(sockfd: c_int, level: c_int, optname: c_int, optval: *mut c_void, optlen: *mut c_int) -> c_int;
    pub fn recvfrom(sockfd: c_int, buf: *mut c_void, len: c_int, flags: c_int, addr: *mut SockAddr, addrlen: *mut c_int) -> c_int;
    pub fn sendto(sockfd: c_int, buf: *const c_void, len: c_int, flags: c_int, addr: *const SockAddr, addrlen: c_int) -> c_int;
    pub fn recv(sockfd: c_int, buf: *mut c_void, len: c_int, flags: c_int) -> c_int;
    pub fn send(sockfd: c_int, buf: *const c_void, len: c_int, flags: c_int) -> c_int;
    pub fn shutdown(sockfd: c_int, how: c_int) -> c_int;
    pub fn close(sockfd: c_int) -> c_int;
    pub fn setsockopt(sockfd: c_int, level: c_int, optname: c_int, optval: *const c_void, optlen: c_int) -> c_int;
    pub fn fcntl(fd: c_int, cmd: c_int, ...) -> c_int;
}

impl super::TimeValFromDuration for TimeVal {
    fn from_duration(duration: std::time::Duration) -> TimeVal {
        TimeVal {
            tv_sec: duration.as_secs() as i64,
            tv_usec: duration.subsec_micros() as i64,
        }
    }
}

impl super::SockAddrBuffer for super::SockAddrV6Buffer {
    type RawSockAddr = SockAddrIn6;

    fn new() -> Self {
        Self { raw: std::mem::MaybeUninit::uninit() }
    }
}

impl super::SockaddrConvert for [u8; 128] {
    fn to_socket_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        let af_family = u16::from_le_bytes(self[0..2].try_into().unwrap());
        unsafe {
            match af_family as c_int {
                AF_INET => {
                    let addr_in = &*(self.as_ptr() as *const SockAddrIn);
                    Ok(std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
                        std::net::Ipv4Addr::from(u32::from_be(addr_in.sin_addr.s_addr)),
                        u16::from_be(addr_in.sin_port),
                    )))
                }
                AF_INET6 => {
                    let addr_in = &*(self.as_ptr() as *const SockAddrIn6);
                    Ok(std::net::SocketAddr::V6(std::net::SocketAddrV6::new(
                        std::net::Ipv6Addr::from(addr_in.sin6_addr.s6_addr),
                        u16::from_be(addr_in.sin6_port),
                        addr_in.sin6_flowinfo,
                        addr_in.sin6_scope_id,
                    )))
                }
                _ => Err(std::io::Error::new(std::io::ErrorKind::Other, "Unsupported address family")),
            }
        }
    }

    fn addr_len(&self) -> usize {
        let af_family = u16::from_le_bytes(self[0..2].try_into().unwrap());
        match af_family as c_int {
            AF_INET => std::mem::size_of::<SockAddrIn>(),
            AF_INET6 => std::mem::size_of::<SockAddrIn6>(),
            _ => 0,
        }
    }
}

impl super::SocketAddrV4IntoSockAddrV4Buffer for std::net::SocketAddrV4 {
    fn into_sockaddrv4(&self) -> super::SockAddrV4Buffer {
        let ip_octets = self.ip().octets();
        super::SockAddrV4Buffer {
            raw: std::mem::MaybeUninit::new(SockAddrIn {
                sin_family: AF_INET as u16,
                sin_port: self.port().to_be(),
                sin_addr: InAddr { s_addr: u32::from_ne_bytes(ip_octets) },
                sin_zero: [0; 8],
            })
        }
    }
}

impl super::SocketAddrV6IntoSockAddrV6Buffer for std::net::SocketAddrV6 {
    fn into_sockaddrv6(&self) -> super::SockAddrV6Buffer {
        let ip_octets = self.ip().octets();
        super::SockAddrV6Buffer {
            raw: std::mem::MaybeUninit::new(SockAddrIn6 {
                sin6_family: AF_INET6 as u16,
                sin6_port: self.port().to_be(),
                sin6_flowinfo: self.flowinfo(),
                sin6_addr: In6Addr { s6_addr: ip_octets },
                sin6_scope_id: self.scope_id(),
            })
        }
    }
}

impl super::ToIpv4Addr for super::SockAddrV4Buffer {
    fn to_addr(&self) -> std::net::Ipv4Addr {
        let addr_in = self.as_raw();
        std::net::Ipv4Addr::from(u32::from_be(addr_in.sin_addr.s_addr))
    }

    fn to_socket_addr(&self) -> std::net::SocketAddr {
        let addr_in = self.as_raw();
        std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
            std::net::Ipv4Addr::from(u32::from_be(addr_in.sin_addr.s_addr)),
            u16::from_be(addr_in.sin_port),
        ))
    }
}