use std::os::raw::*;
use crate::{SockaddrConvert, SocketAddrV4IntoSockAddrV4Buffer, SocketAddrV6IntoSockAddrV6Buffer, TimeValFromDuration, ToIpv4Addr, ToIpv6Addr};

pub mod def;
pub use def::*;
pub mod bpf;
pub use bpf::*;

impl TimeValFromDuration for TimeVal {
    fn from_duration(duration: std::time::Duration) -> TimeVal {
        TimeVal {
            tv_sec: duration.as_secs() as i64,
            tv_usec: (duration.subsec_micros() as i64),
        }
    }
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
    fn into_sockaddrv4(&self) -> SockAddrIn {
        let ip_octets = self.ip().octets();
        SockAddrIn {
            sin_family: AF_INET as u16,
            sin_port: self.port().to_be(),
            sin_addr: InAddr {
                s_addr: ip_octets,
            },
            sin_zero: [0; 8],
        }
    }
}

impl SocketAddrV6IntoSockAddrV6Buffer for std::net::SocketAddrV6 {
    fn into_sockaddrv6(&self) -> SockAddrIn6 {
        let ip_octets = self.ip().octets();
        SockAddrIn6 {
            sin6_family: AF_INET6 as u16,
            sin6_port: self.port().to_be(),
            sin6_flowinfo: self.flowinfo(),
            sin6_addr: In6Addr {
                s6_addr: ip_octets,
            },
            sin6_scope_id: self.scope_id()
        }
    }
}

impl ToIpv4Addr for SockAddrIn {
    #[inline(always)]
    fn to_ipv4_addr(&self) -> std::net::Ipv4Addr {
        std::net::Ipv4Addr::from(self.sin_addr.s_addr)
    }

    #[inline(always)]
    fn to_socket_addr_v4(&self) -> std::net::SocketAddrV4 {
        std::net::SocketAddrV4::new(
            self.to_ipv4_addr(),
            self.sin_port,
        )
    }
}

impl ToIpv6Addr for SockAddrIn6 {
    #[inline(always)]
    fn to_ipv6_addr(&self) -> std::net::Ipv6Addr {
        std::net::Ipv6Addr::from(self.sin6_addr.s6_addr)
    }

    #[inline(always)]
    fn to_socket_addr_v6(&self) -> std::net::SocketAddrV6 {
        std::net::SocketAddrV6::new(
            self.to_ipv6_addr(),
            self.sin6_port,
            self.sin6_flowinfo,
            self.sin6_scope_id,
        )
    }
}