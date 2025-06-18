pub use crate::*;

use std::{mem::MaybeUninit, net::{Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs}};

#[inline(always)]
pub fn xsocket(af: i32, socket_type: i32, protocol: i32) -> Result<Socket> {
    sys::init();
    unsafe {
        let sock_id = sys::socket(af, socket_type, protocol) as SocketRaw;
        #[cfg(unix)]
        if sock_id >= 0 { Ok(std::mem::transmute::<SocketRaw, Socket>(sock_id)) } else { Err(std::io::Error::last_os_error()) }
        #[cfg(windows)]
        if sock_id != SocketRaw::MAX { Ok(std::mem::transmute::<SocketRaw, Socket>(sock_id)) } else { Err(std::io::Error::last_os_error()) }
    }
}

#[inline(always)]
pub fn xsetsockopt<T>(sock: Socket, level: i32, optname: i32, optval: &T, optlen: i32) -> Result<()> {
    let result = unsafe {
        sys::setsockopt(
            sock.as_raw(), 
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
        sock.as_raw(),
        sockaddr_storage.as_ptr() as *const _,
        len as i32
    )};

    if result == 0 { Ok(()) } else { Err(std::io::Error::last_os_error()) }
}

#[inline(always)]
pub fn xlisten(sock: Socket, backlog: i32) -> Result<()> {
    let result = unsafe { sys::listen(sock.as_raw(), backlog) };
    if result == 0 { Ok(()) } else { Err(std::io::Error::last_os_error()) }
}

#[inline(always)]
pub fn xaccept(sock: Socket) -> Result<Socket> {
    unsafe {
        let sock_id = sys::accept(sock.as_raw(), std::ptr::null_mut(), std::ptr::null_mut());
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
        sock.as_raw(),
        sockaddr_storage.as_ptr() as *const _,
        len as i32
    )};

    if result == 0 { Ok(()) } else { Err(std::io::Error::last_os_error()) }
}

#[inline(always)]
pub fn xsend(sock: Socket, buf: &[u8], flags: i32) -> Result<usize> {
    let result = unsafe { sys::send(sock.as_raw(), buf.as_ptr() as *const _, buf.len() as std::os::raw::c_int, flags) };
    if result < 0 { Err(std::io::Error::last_os_error()) } else { Ok(result as usize) }
}


#[inline(always)]
pub fn xrecv(sock: Socket, buf: &mut [u8], flags: i32) -> Result<usize> {
    unsafe {
        let result = sys::recv(sock.as_raw(), buf.as_mut_ptr() as *mut _, buf.len() as std::os::raw::c_int, flags);
        if result != 1 { Ok(result as usize) } else { Err(std::io::Error::last_os_error()) }
    }
}

#[inline(always)]
pub fn xsendto<A: SocketAddressBuffer>(sock: Socket, buf: &[u8], flags: i32, addr: &A) -> Result<usize> {
    unsafe {
        let result = sys::sendto(
            sock.as_raw(),
            buf.as_ptr() as *const _,
            buf.len() as i32,
            flags,
            addr.as_raw_ptr() as *const _,
            addr.len() as i32
        );
        if result < 0 { Err(std::io::Error::last_os_error()) } else { Ok(result as usize) }
    }
}

#[cfg(unix)]
#[inline(always)]
pub fn xmmap(addr: &mut [u8], prot: i32, flags: i32, sock: Socket, offset: u32) -> Result<usize> {
    unsafe {
        let result = sys::mmap(
            addr.as_mut_ptr() as *mut _,
            addr.len() as usize,
            prot,
            flags,
            sock.as_raw(),
            offset as i64
        );
        if result == sys::MAP_FAILED {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(addr.len())
        }
    }
}

#[cfg(unix)]
#[inline(always)]
pub fn xmunmap(addr: &mut [u8], length: usize) -> Result<usize> {
    unsafe {
        let result = sys::munmap(
            addr.as_mut_ptr() as *mut _,
            length,
        );
        if result < 0 { Err(std::io::Error::last_os_error()) } else { Ok(result as usize) }
    }
}

#[inline(always)]
pub fn xsendmmsg<A: SocketAddressBuffer>(
    sock: Socket,
    packets: &[(&[u8], &A)],
    flags: i32,
) -> Result<usize> {
    #[cfg(windows)]
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "xsendmmsg is not supported on Windows",
        ));
    }
    #[cfg(unix)] {
        let count = packets.len();
        if count == 0 {
            return Ok(0);
        }

        let mut iovecs = Vec::with_capacity(count);
        let mut msgs = Vec::with_capacity(count);
        let mut storage = Vec::with_capacity(count);

        for i in 0..count {
            let (data, addr) = packets[i];
            let addr_len = addr.len();

            let mut addr_buf = [0u8; 128];
            unsafe {
                std::ptr::copy_nonoverlapping(
                    addr.as_raw_ptr() as *const u8,
                    addr_buf.as_mut_ptr(),
                    addr_len,
                );
            }
            storage.push(addr_buf); // owns addr_buf now

            iovecs.push(Iovec {
                iov_base: data.as_ptr() as *mut u8,
                iov_len: data.len(),
            });
        }

        for i in 0..count {
            msgs.push(Mmsghdr {
                msg_hdr: Msghdr {
                    msg_name: storage[i].as_ptr() as *mut u8,
                    msg_namelen: packets[i].1.len() as u32,
                    msg_iov: &mut iovecs[i],
                    msg_iovlen: 1,
                    msg_control: std::ptr::null_mut(),
                    msg_controllen: 0,
                    msg_flags: 0,
                },
                msg_len: 0,
            });
        }

        let ret = unsafe {
            sendmmsg(sock.as_raw() as i32, msgs.as_mut_ptr(), count as u32, flags)
        };

        if ret < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(ret as usize)
        }
    }
}

#[inline(always)]
#[allow(unused)]
pub unsafe fn xlasterror(sock: Socket) -> std::io::Error {
    let err = std::io::Error::last_os_error();
    if err.kind() == std::io::ErrorKind::WouldBlock {
        #[cfg(unix)]
        {
            // Linux returns EWOULDBLOCK when the socket is non-blocking and no data is available but also when the socket is blocking but a timeout is set.
            // Therefore, we need to check if the socket is blocking and if a timeout is set **manually** to determine if we should return a TimedOut error.
            use sys::{fcntl, F_GETFL, O_NONBLOCK, SOL_SOCKET, SO_RCVTIMEO};
            let blocking = fcntl(sock.as_raw(), F_GETFL) & O_NONBLOCK == 0;
            let mut timeout = sys::TimeVal { tv_sec: 0, tv_usec: 0 };
            let mut len = std::mem::size_of::<sys::TimeVal>() as i32;
            let r = sys::getsockopt(sock.as_raw(), SOL_SOCKET, SO_RCVTIMEO, &mut timeout as *mut _ as *mut _, &mut len);
            let has_timeout = r == 0 && (timeout.tv_sec > 0 || timeout.tv_usec > 0);
            if has_timeout && blocking {
                return std::io::Error::new(std::io::ErrorKind::TimedOut, err);
            }
        }
    }
    err
}

#[inline(always)]
pub fn xrecvfrom<A: SocketAddressBuffer>(sock: Socket, buf: &mut [u8], addr_buf: &mut A, flags: i32) -> Result<usize> {
    let addrlen: i32 = addr_buf.len() as std::os::raw::c_int;
    unsafe {
        let result = sys::recvfrom(
            sock.as_raw(),
            buf.as_mut_ptr() as *mut _,
            buf.len() as i32,
            flags,
            addr_buf.as_mut_ptr() as *mut _,
            (&addrlen as *const i32) as *mut _,
        );
        if result >= 0 {
            Ok(result as usize)
        } else {
            Err(xlasterror(sock))
        }
    }
}

#[inline(always)]
#[cfg(unix)] 
pub fn unix_recvmmsg(sock: Socket, msgvec: &mut [Mmsghdr], flags: i32, timeout: Option<&mut Timespec>) -> Result<usize> {
    unsafe {
        let vlen = msgvec.len() as u32;
        let timeout_ptr = match timeout {
            Some(t) => t as *mut Timespec,
            None => std::ptr::null_mut(),
        };

        let result = sys::recvmmsg(
            sock.as_raw(),
            msgvec.as_mut_ptr(),
            vlen,
            flags,
            timeout_ptr,
        );

        if result >= 0 {
            Ok(result as usize)
        } else {
            Err(xlasterror(sock))
        }
    }
}

#[inline(always)]
pub fn vecrecv<IpvXInbox>(sock: Socket, inbox: &mut IpvXInbox, flags: i32) -> Result<usize> 
where IpvXInbox: IpBucket {
    #[cfg(unix)] {
        unsafe {
            let result = sys::recvmmsg(sock.as_raw(), inbox.raw_msgs_ptr(), inbox.capacity() as u32, flags, std::ptr::null_mut());
            if result >= 0 {
                inbox.set_size(result as usize);
                Ok(result as usize)
            } else {
                Err(xlasterror(sock))
            }
        }
    }
    #[cfg(windows)] {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "vecrecv is not supported on Windows yet",
        ))
    }
}

#[inline(always)]
pub fn xrecvfrom_v4(sock: Socket, buf: &mut [u8], data_len: &mut usize, flags: i32) -> Result<SocketAddrSrcV4> {
    let mut addr_buf = MaybeUninit::<SocketAddrSrcV4>::uninit();
    let addrlen: i32 = std::mem::size_of::<SocketAddrSrcV4>() as std::os::raw::c_int;
    unsafe {
        let result = sys::recvfrom(
            sock.as_raw(),
            buf.as_mut_ptr() as *mut _,
            buf.len() as i32,
            flags,
            addr_buf.as_mut_ptr() as *mut _,
            (&addrlen as *const i32) as *mut _,
        );
        *data_len = result as usize;

        if result >= 0 {
            Ok(addr_buf.assume_init())
        } else {
            Err(xlasterror(sock))
        }
    }
}

pub fn xrecvfrom_v6(sock: Socket, buf: &mut [u8], data_len: &mut usize, flags: i32) -> Result<SocketAddrSrcV6> {
    let mut addr_buf = MaybeUninit::<SocketAddrSrcV6>::uninit();
    let addrlen: i32 = std::mem::size_of::<SocketAddrSrcV6>() as std::os::raw::c_int;
    unsafe {
        let result = sys::recvfrom(
            sock.as_raw(),
            buf.as_mut_ptr() as *mut _,
            buf.len() as i32,
            flags,
            addr_buf.as_mut_ptr() as *mut _,
            (&addrlen as *const i32) as *mut _,
        );
        *data_len = result as usize;
        if result >= 0 {
            Ok(addr_buf.assume_init())
        } else {
            Err(xlasterror(sock))
        }
    }
}


#[inline(always)]
pub fn popmsg(sock: Socket, buf: &mut [u8], data_len: &mut usize, flags: i32) -> Result<SocketAddrSrc> {
    let mut addr_buf = MaybeUninit::<SockAddrBuffer>::uninit();
    let addrlen: i32 = std::mem::size_of::<SocketAddrSrc>() as std::os::raw::c_int;
    unsafe {
        let result = sys::recvfrom(
            sock.as_raw(),
            buf.as_mut_ptr() as *mut _,
            buf.len() as i32,
            flags,
            addr_buf.as_mut_ptr() as *mut _,
            (&addrlen as *const i32) as *mut _,
        );
        *data_len = result as usize;
        if result >= 0 {
            let sockaddr = addr_buf.assume_init();
            if (sockaddr.family as i32) == AF_INET || (sockaddr.family as i32) == AF_INET6 {
                Ok(SocketAddrSrc::V4(*( &sockaddr as *const SockAddrBuffer as *const SocketAddrSrcV4 )))
            } else if (sockaddr.family as i32) == AF_INET6 {
                Ok(SocketAddrSrc::V6(*( &sockaddr as *const SockAddrBuffer as *const SocketAddrSrcV6 )))
            } else {
                Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Unsupported address family"))
            }
        } else {
            Err(xlasterror(sock))
        }
    }
}

#[inline(always)]
pub fn xclose(sock: Socket) -> Result<()> {
    #[cfg(windows)]
    let result = unsafe { sys::closesocket(sock.as_raw()) };
    #[cfg(unix)]
    let result = unsafe { sys::close(sock.as_raw()) };
    if result == 0 { Ok(()) } else { Err(std::io::Error::last_os_error()) }
}

#[inline(always)]
pub fn xgetpeername<A: SocketAddressBuffer>(sock: Socket, addr_buf: &mut A) -> Result<()> {
    let addrlen: i32 = addr_buf.len() as std::os::raw::c_int;
    unsafe {
        let result = sys::getpeername(
            sock.as_raw(),
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