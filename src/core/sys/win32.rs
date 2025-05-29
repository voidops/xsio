use std::os::raw::*;
use super::{SockAddrBuffer, SockAddrV4Buffer, SockAddrV6Buffer, SockaddrConvert, SocketAddrV4IntoSockAddrV4Buffer, SocketAddrV6IntoSockAddrV6Buffer, TimeValFromDuration, ToIpv4Addr};

pub const AF_UNIX: c_int = 1;
pub const AF_INET: c_int = 2;
pub const AF_INET6: c_int = 23;

pub const SOCK_STREAM: c_int =     1;               /* stream socket */
pub const SOCK_DGRAM: c_int =      2;               /* datagram socket */
pub const SOCK_RAW: c_int =        3;               /* raw-protocol interface */
pub const SOCK_RDM: c_int =        4;               /* reliably-delivered message */
pub const SOCK_SEQPACKET: c_int =  5;               /* sequenced packet stream */

pub const SOL_SOCKET: c_int = 0xffff;

pub const SO_DEBUG: c_int = 0x0001;
pub const SO_ACCEPTCONN: c_int = 0x0002;
pub const SO_REUSEADDR: c_int = 0x0004;
pub const SO_KEEPALIVE: c_int = 0x0008;
pub const SO_DONTROUTE: c_int = 0x0010;
pub const SO_BROADCAST: c_int = 0x0020;
pub const SO_USELOOPBACK: c_int = 0x0040;
pub const SO_LINGER: c_int = 0x0080;
pub const SO_OOBINLINE: c_int = 0x0100;
pub const SO_DONTLINGER: c_int = !SO_LINGER;
pub const SO_EXCLUSIVEADDRUSE: c_int = !SO_REUSEADDR;
pub const SO_SNDBUF: c_int = 0x1001;
pub const SO_RCVBUF: c_int = 0x1002;
pub const SO_SNDLOWAT: c_int = 0x1003;
pub const SO_RCVLOWAT: c_int = 0x1004;
pub const SO_SNDTIMEO: c_int = 0x1005;
pub const SO_RCVTIMEO: c_int = 0x1006;
pub const SO_ERROR: c_int = 0x1007;
pub const SO_TYPE: c_int = 0x1008;
pub const SO_BSP_STATE: c_int = 0x1009;
pub const SO_GROUP_ID: c_int = 0x2001;
pub const SO_GROUP_PRIORITY: c_int = 0x2002;
pub const SO_MAX_MSG_SIZE: c_int = 0x2003;
pub const SO_CONDITIONAL_ACCEPT: c_int = 0x3002;
pub const SO_PAUSE_ACCEPT: c_int = 0x3003;
pub const SO_COMPARTMENT_ID: c_int = 0x3004;
pub const SO_RANDOMIZE_PORT: c_int = 0x3005;
pub const SO_PORT_SCALABILITY: c_int = 0x3006;
pub const SO_REUSE_UNICASTPORT: c_int = 0x3007;
pub const SO_REUSE_MULTICASTPORT: c_int = 0x3008;

pub const IPPROTO_HOPOPTS: c_int = 0; // IPv6 Hop-by-Hop options
pub const IPPROTO_ICMP: c_int = 1;
pub const IPPROTO_IGMP: c_int = 2;
pub const IPPROTO_GGP: c_int = 3;
pub const IPPROTO_IPV4: c_int = 4;
pub const IPPROTO_ST: c_int = 5;
pub const IPPROTO_TCP: c_int = 6;
pub const IPPROTO_CBT: c_int = 7;
pub const IPPROTO_EGP: c_int = 8;
pub const IPPROTO_IGP: c_int = 9;
pub const IPPROTO_PUP: c_int = 12;
pub const IPPROTO_UDP: c_int = 17;
pub const IPPROTO_IDP: c_int = 22;
pub const IPPROTO_RDP: c_int = 27;
pub const IPPROTO_IPV6: c_int = 41; // IPv6 header
pub const IPPROTO_ROUTING: c_int = 43; // IPv6 Routing header
pub const IPPROTO_FRAGMENT: c_int = 44; // IPv6 fragmentation header
pub const IPPROTO_ESP: c_int = 50; // encapsulating security payload
pub const IPPROTO_AH: c_int = 51; // authentication header
pub const IPPROTO_ICMPV6: c_int = 58; // ICMPv6
pub const IPPROTO_NONE: c_int = 59; // IPv6 no next header
pub const IPPROTO_DSTOPTS: c_int = 60; // IPv6 Destination options
pub const IPPROTO_ND: c_int = 77;
pub const IPPROTO_ICLFXBM: c_int = 78;
pub const IPPROTO_PIM: c_int = 103;
pub const IPPROTO_PGM: c_int = 113;
pub const IPPROTO_L2TP: c_int = 115;
pub const IPPROTO_SCTP: c_int = 132;
pub const IPPROTO_RAW: c_int = 255;
pub const IPPROTO_MAX: c_int = 256;
pub const IPPROTO_RESERVED_RAW: c_int = 257;
pub const IPPROTO_RESERVED_IPSEC: c_int = 258;
pub const IPPROTO_RESERVED_IPSECOFFLOAD: c_int = 259;
pub const IPPROTO_RESERVED_WNV: c_int = 260;
pub const IPPROTO_RESERVED_MAX: c_int = 261;


pub const TCP_NODELAY: c_int = 0x0001;

pub const SHUT_RD: c_int = 0;
pub const SHUT_WR: c_int = 1;

#[repr(C)]
pub struct SockLen {
    pub len: c_int,
}

#[repr(C)]
pub struct SockAddr {
    pub sa_family: u16,
    pub sa_data: [i8; 14],
}

#[repr(C)]
pub struct InAddr {
    pub s_addr: [u8; 4]
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
#[derive(Debug)]
pub struct TimeVal {
    pub tv_sec: i64,
    pub tv_usec: i64,
}

impl TimeValFromDuration for TimeVal {
    fn from_duration(duration: std::time::Duration) -> TimeVal {
        TimeVal {
            tv_sec: duration.as_secs() as i64,
            tv_usec: (duration.subsec_micros() as i64),
        }
    }
}

extern "system" {
    pub fn socket(af: c_int, socket_type: c_int, protocol: c_int) -> usize;
    pub fn listen(s: usize, backlog: c_int) -> c_int;
    pub fn accept(s: usize, addr: *mut SockAddr, addrlen: *mut c_int) -> usize;
    pub fn bind(s: usize, name: *const SockAddr, namelen: c_int) -> c_int;
    pub fn connect(s: usize, name: *const SockAddr, namelen: c_int) -> c_int;
    pub fn getpeername(s: usize, name: *mut SockAddr, nameln: *mut c_int) -> c_int;
    pub fn getsockname(s: usize, name: *mut SockAddr, nameln: *mut c_int) -> c_int;
    pub fn getsockopt(s: usize, level: c_int, optname: c_int, optval: *mut i8, optlen: *mut c_int) -> c_int;
    pub fn recvfrom(s: usize, buf: *mut i8, len: c_int, flags: c_int, from: *mut SockAddr, fromlen: *mut c_int) -> c_int;
    pub fn sendto(s: usize, buf: *const i8, len: c_int, flags: c_int, to: *const SockAddr, tolen: c_int) -> c_int;
    pub fn recv(s: usize, buf: *mut i8, len: c_int, flags: c_int) -> c_int;
    pub fn send(s: usize, buf: *const i8, len: c_int, flags: c_int) -> c_int;
    pub fn shutdown(s: usize, how: c_int) -> c_int;
    pub fn closesocket(s: usize) -> c_int;
    pub fn setsockopt(s: usize, level: c_int,optname: c_int, optval: *const i8, optlen: c_int) -> c_int;
}
/*
impl<const SIZE: usize> SockaddrConvert for SockAddrBuffer<SIZE>
{
    #[inline(always)]
    fn to_socket_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        let af_family = u16::from_le_bytes(self.0[0..2].try_into().unwrap());
        unsafe {
            match af_family as c_int {
                AF_INET => {
                    let addr_in = &*(self.0.as_ptr() as *const SockAddrIn);
                    Ok(std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
                        std::net::Ipv4Addr::from(addr_in.sin_addr.s_addr),
                        addr_in.sin_port,
                    )))
                }
                AF_INET6 => {
                    let addr_in = &*(self.0.as_ptr() as *const SockAddrIn6);
                    Ok(std::net::SocketAddr::V6(std::net::SocketAddrV6::new(
                        std::net::Ipv6Addr::from(addr_in.sin6_addr.s6_addr),
                        addr_in.sin6_port,
                        addr_in.sin6_flowinfo,
                        addr_in.sin6_scope_id
                    )))
                }
                _ => Err(std::io::Error::new(std::io::ErrorKind::Other, "Unsupported address family")),
            }
        }
    }
    #[inline(always)]
    fn addr_len(&self) -> usize {
        let af_family = u16::from_le_bytes(self.0[0..2].try_into().unwrap());
        match af_family as c_int {
            AF_INET => std::mem::size_of::<SockAddrIn>(),
            AF_INET6 => std::mem::size_of::<SockAddrIn6>(),
            _ => 0
        }
    }
}
*/
impl SockaddrConvert for [u8; 128] {
    #[inline(always)]
    fn to_socket_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        let af_family = u16::from_le_bytes(self[0..2].try_into().unwrap());
        unsafe {
            match af_family as c_int {
                AF_INET => {
                    let addr_in = &*(self.as_ptr() as *const SockAddrIn);
                    Ok(std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
                        std::net::Ipv4Addr::from(addr_in.sin_addr.s_addr),
                        addr_in.sin_port,
                    )))
                }
                AF_INET6 => {
                    let addr_in = &*(self.as_ptr() as *const SockAddrIn6);
                    Ok(std::net::SocketAddr::V6(std::net::SocketAddrV6::new(
                        std::net::Ipv6Addr::from(addr_in.sin6_addr.s6_addr),
                        addr_in.sin6_port,
                        addr_in.sin6_flowinfo,
                        addr_in.sin6_scope_id
                    )))
                }
                _ => Err(std::io::Error::new(std::io::ErrorKind::Other, "Unsupported address family")),
            }
        }
    }
    #[inline(always)]
    fn addr_len(&self) -> usize {
        let af_family = u16::from_le_bytes(self[0..2].try_into().unwrap());
        match af_family as c_int {
            AF_INET => std::mem::size_of::<SockAddrIn>(),
            AF_INET6 => std::mem::size_of::<SockAddrIn6>(),
            _ => 0
        }
    }
}

impl SocketAddrV4IntoSockAddrV4Buffer for std::net::SocketAddrV4 {
    fn into_sockaddrv4(&self) -> SockAddrV4Buffer {
        let ip_octets = self.ip().octets();
        SockAddrV4Buffer {
            raw: std::mem::MaybeUninit::new(SockAddrIn {
                sin_family: AF_INET as u16,
                sin_port: self.port().to_be(),
                sin_addr: InAddr {
                    s_addr: ip_octets,
                },
                sin_zero: [0; 8],
            })
        }
    }
}

impl SocketAddrV6IntoSockAddrV6Buffer for std::net::SocketAddrV6 {
    fn into_sockaddrv6(&self) -> SockAddrV6Buffer {
        let ip_octets = self.ip().octets();
        SockAddrV6Buffer {
            raw: std::mem::MaybeUninit::new(SockAddrIn6 {
                sin6_family: AF_INET6 as u16,
                sin6_port: self.port().to_be(),
                sin6_flowinfo: self.flowinfo(),
                sin6_addr: In6Addr {
                    s6_addr: ip_octets,
                },
                sin6_scope_id: self.scope_id()
            })
        }
    }
}

impl ToIpv4Addr for SockAddrV4Buffer {
    #[inline(always)]
    fn to_addr(&self) -> std::net::Ipv4Addr {
        let addr_in = self.as_raw();
        std::net::Ipv4Addr::from(addr_in.sin_addr.s_addr)
    }

    #[inline(always)]
    fn to_socket_addr(&self) -> std::net::SocketAddr {
        let addr_in = self.as_raw();
        std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
            std::net::Ipv4Addr::from(addr_in.sin_addr.s_addr),
            addr_in.sin_port,
        ))
    }
}