pub use crate::*;
use super::sys;
use super::sys::*;

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};

#[inline(always)]
pub fn xsocket(af: i32, socket_type: i32, protocol: i32) -> Result<Socket> {
    sys::init();
    unsafe {
        let sock_id = sys::socket(af, socket_type, protocol) as SocketRaw;
        if sock_id != SocketRaw::MAX { Ok(std::mem::transmute::<SocketRaw, Socket>(sock_id)) } else { Err(std::io::Error::last_os_error()) }
    }
}

#[inline(always)]
pub fn xsetsockopt<T>(sock: Socket, level: i32, optname: i32, optval: &T, optlen: i32) -> Result<()> {
    let result = unsafe {
        sys::setsockopt(
            *sock, 
            level, 
            optname, 
            optval as *const _ as *const _, 
            optlen
        )
    };
    
    if result == 0 { Ok(()) } else { Err(std::io::Error::last_os_error()) }
}

#[inline(always)]
pub fn xbind<A: ToSocketAddrs>(sock: Socket, addr: A) -> Result<()> {
    let addr = addr.to_socket_addrs().ok();

    if addr.is_none() { return Ok(()) }

    let addr = addr.unwrap().next().unwrap();

    let mut sockaddr_storage = [0u8; 128];
    let len = socket_addr_to_raw(&addr, &mut sockaddr_storage);

    let result = unsafe { sys::bind(
        *sock,
        sockaddr_storage.as_ptr() as *const _,
        len as i32
    )};

    if result == 0 { Ok(()) } else { Err(std::io::Error::last_os_error()) }
}

#[inline(always)]
pub fn xlisten(sock: Socket, backlog: i32) -> Result<()> {
    let result = unsafe { sys::listen(*sock, backlog) };
    if result == 0 { Ok(()) } else { Err(std::io::Error::last_os_error()) }
}

#[inline(always)]
pub fn xaccept(sock: Socket) -> Result<Socket> {
    unsafe {
        let sock_id = sys::accept(*sock, std::ptr::null_mut(), std::ptr::null_mut());
        if sock_id != SocketRaw::MAX { Ok(std::mem::transmute::<SocketRaw, Socket>(sock_id)) } else { Err(std::io::Error::last_os_error()) }
    }
}

#[inline(always)]
pub fn xconnect<A: ToSocketAddrs>(sock: Socket, addr: A) -> Result<()> {
    let addr = addr.to_socket_addrs().ok();

    if addr.is_none() { return Err(std::io::ErrorKind::InvalidInput.into()); }

    let addr = addr.unwrap().next().unwrap();

    let mut sockaddr_storage = [0u8; 128];
    let len = socket_addr_to_raw(&addr, &mut sockaddr_storage);

    let result = unsafe { sys::connect(
        *sock,
        sockaddr_storage.as_ptr() as *const _,
        len as i32
    )};

    if result == 0 { Ok(()) } else { Err(std::io::Error::last_os_error()) }
}

#[inline(always)]
pub fn xsend(sock: Socket, buf: &[u8], flags: i32) -> Result<usize> {
    let result = unsafe { sys::send(*sock, buf.as_ptr() as *const _, buf.len() as std::os::raw::c_int, flags) };
    if result < 0 { Err(std::io::Error::last_os_error()) } else { Ok(result as usize) }
}

#[inline(always)]
pub fn xrecv(sock: Socket, buf: &mut [u8], flags: i32) -> Result<usize> {
    unsafe {
        let result = sys::recv(*sock, buf.as_mut_ptr() as *mut _, buf.len() as std::os::raw::c_int, flags);
        if result != 1 { Ok(result as usize) } else { Err(std::io::Error::last_os_error()) }
    }
}

#[inline(always)]
pub fn xsendto<A: SockAddrBuffer>(sock: Socket, buf: &[u8], flags: i32, addr: &A) -> Result<usize> {
    unsafe {
        let result = sys::sendto(
            *sock,
            buf.as_ptr() as *const _,
            buf.len() as i32,
            flags,
            addr.as_raw_ptr() as *const _,
            addr.len() as i32
        );
        if result < 0 { Err(std::io::Error::last_os_error()) } else { Ok(result as usize) }
    }
}

#[inline(always)]
pub fn xrecvfrom<A: SockAddrBuffer>(sock: Socket, buf: &mut [u8], addr_buf: &mut A, flags: i32) -> Result<usize> {
    let addrlen: i32 = addr_buf.len() as std::os::raw::c_int;
    unsafe {
        let result = sys::recvfrom(
            *sock,
            buf.as_mut_ptr() as *mut _,
            buf.len() as i32,
            flags,
            addr_buf.as_mut_ptr() as *mut _,
            (&addrlen as *const i32) as *mut _,
        );

        if result >= 0 {
            Ok(result as usize)
        } else {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::WouldBlock {
                #[cfg(unix)]
                {
                    // Linux returns EWOULDBLOCK when the socket is non-blocking and no data is available but also when the socket is blocking but a timeout is set.
                    // Therefore, we need to check if the socket is blocking and if a timeout is set **manually** to determine if we should return a TimedOut error.
                    use sys::{fcntl, F_GETFL, O_NONBLOCK, SOL_SOCKET, SO_RCVTIMEO};
                    let blocking = fcntl(*sock, F_GETFL) & O_NONBLOCK == 0;
                    let mut timeout = sys::TimeVal { tv_sec: 0, tv_usec: 0 };
                    let mut len = std::mem::size_of::<sys::TimeVal>() as i32;
                    let r = sys::getsockopt(*sock, SOL_SOCKET, SO_RCVTIMEO, &mut timeout as *mut _ as *mut _, &mut len);
                    let has_timeout = r == 0 && (timeout.tv_sec > 0 || timeout.tv_usec > 0);
                    if has_timeout && blocking {
                        return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, err));
                    }
                }
            }
            Err(err)
        }
    }
}


#[inline(always)]
pub fn xclose(sock: Socket) -> Result<()> {
    #[cfg(windows)]
    let result = unsafe { sys::closesocket(*sock) };
    #[cfg(unix)]
    let result = unsafe { sys::close(*sock) };
    if result == 0 { Ok(()) } else { Err(std::io::Error::last_os_error()) }
}

#[inline(always)]
pub fn xgetpeername<A: SockAddrBuffer>(sock: Socket, addr_buf: &mut A) -> Result<()> {
    let addrlen: i32 = addr_buf.len() as std::os::raw::c_int;
    unsafe {
        let result = sys::getpeername(
            *sock,
            addr_buf.as_mut_ptr() as *mut _,
            (&addrlen as *const i32) as *mut _
        );
        if result == 0 { Ok(()) } else { Err(std::io::Error::last_os_error()) }
    }
}

#[inline(always)]
pub fn socket_addr_from_raw(storage: &[u8; 128]) -> Option<SocketAddr> {
    let sockaddr_ptr = storage.as_ptr() as *const SockAddr;
    unsafe {
        match (*sockaddr_ptr).sa_family as i32 {
            AF_INET => {
                let sockaddr_in_ptr = sockaddr_ptr as *const SockAddrIn;
                let addr_in = std::ptr::read(sockaddr_in_ptr);
                let ip = Ipv4Addr::from(addr_in.sin_addr.s_addr);
                let port = u16::from_be(addr_in.sin_port);
                Some(SocketAddr::V4(std::net::SocketAddrV4::new(ip, port)))
            }
            AF_INET6 => {
                let sockaddr_in6_ptr = sockaddr_ptr as *const SockAddrIn6;
                let addr_in6 = std::ptr::read(sockaddr_in6_ptr);
                let ip = Ipv6Addr::from(addr_in6.sin6_addr.s6_addr);
                let port = u16::from_be(addr_in6.sin6_port);
                Some(SocketAddr::V6(std::net::SocketAddrV6::new(
                    ip,
                    port,
                    addr_in6.sin6_flowinfo,
                    addr_in6.sin6_scope_id,
                )))
            }
            _ => None, // Unsupported protocol family
        }
    }
}

#[inline(always)]
pub fn socket_addr_to_raw(sockaddr: &SocketAddr, out_sockaddr: &mut [u8]) -> usize {
    match sockaddr {
        SocketAddr::V4(addr_v4) => {
            
#[cfg(windows)]
            let sockaddr_in = SockAddrIn {
                sin_family: AF_INET as u16,
                sin_port: addr_v4.port().to_be(),
                sin_addr: InAddr {
                    s_addr: addr_v4.ip().octets(),
                },
                sin_zero: [0; 8],
            };
#[cfg(unix)]
            let sockaddr_in = SockAddrIn {
                sin_family: AF_INET as u16,
                sin_port: addr_v4.port().to_be(),
                sin_addr: InAddr {
                    s_addr: u32::from_ne_bytes(addr_v4.ip().octets()),
                },
                sin_zero: [0; 8],
            };
            let sockaddr_ptr = out_sockaddr.as_mut_ptr() as *mut SockAddrIn;
            unsafe { std::ptr::write(sockaddr_ptr, sockaddr_in) };

            std::mem::size_of::<SockAddrIn>()
        }
        SocketAddr::V6(addr_v6) => {
            let sockaddr_in6 = SockAddrIn6 {
                sin6_family: AF_INET6 as u16,
                sin6_port: addr_v6.port().to_be(),
                sin6_flowinfo: addr_v6.flowinfo(),
                sin6_addr: In6Addr {
                    s6_addr: addr_v6.ip().octets(),
                },
                sin6_scope_id: addr_v6.scope_id(),
            };
            let sockaddr_ptr = out_sockaddr.as_mut_ptr() as *mut SockAddrIn6;
            unsafe { std::ptr::write(sockaddr_ptr, sockaddr_in6) };

            std::mem::size_of::<SockAddrIn6>()
        }
    }
}