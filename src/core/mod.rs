use std::any::TypeId;
use std::{net::ToSocketAddrs, ops::Deref};
use std::io::Result;

mod sys;
pub mod utils;
pub mod sockopts;
pub mod sockdomains;

use sys::*;
pub use utils::*;
pub use sockopts::*;
pub use sockdomains::*;
pub use sys::{SockAddrV4Buffer, SockAddrV6Buffer, SockAddrBuffer, ToIpv4Addr, SocketAddrV4IntoSockAddrV4Buffer, SocketAddrV6IntoSockAddrV6Buffer};

#[cfg(unix)]
pub type SocketRaw = i32;
#[cfg(windows)]
pub type SocketRaw = usize;

#[derive(Copy, Clone)]
#[repr(C)]
pub struct Socket(SocketRaw);

impl Socket {
    #[inline(always)]
    #[allow(unused_variables)]
    pub fn new<AF: AddressFamily, ST: SocketType, P: Protocol>(af: AF, st: ST, protocol: P) -> Result<Socket>
    where
        (AF, ST, P): ValidSocket,
    {
        xsocket(AF::DOMAIN, ST::TYPE, P::PROTOCOL)
    }

    #[inline(always)]
    pub fn raw_new(af: i32, socket_type: i32, protocol: i32) -> Result<Socket> {
        xsocket(af, socket_type, protocol)
    }

    #[inline(always)]
    pub fn bind<A: ToSocketAddrs>(self, addr: A) -> Result<()> {
        xbind(self, addr)
    }

    #[inline(always)]
    pub fn connect<A: ToSocketAddrs>(self, addr: A) -> Result<()> {
        xconnect(self, addr)
    }

    #[inline(always)]
    pub fn listen(self, backlog: i32) -> Result<()> {
        xlisten(self, backlog)
    }

    #[inline(always)]
    pub fn accept(self) -> Result<Socket> {
        xaccept(self)
    }

    #[inline(always)]
    pub fn send(self, buf: &[u8], flags: i32) -> Result<usize> {
        xsend(self, buf, flags)
    }

    #[inline(always)]
    pub fn recv(self, buf: &mut [u8], flags: i32) -> Result<usize> {
        xrecv(self, buf, flags)
    }

    #[inline(always)]
    pub fn send_to<A: SockAddrBuffer>(self, buf: &[u8], addr: &A, flags: i32) -> Result<usize> {
        xsendto(self, buf, flags, addr)
    }

    #[inline(always)]
    pub fn recv_from<A: SockAddrBuffer>(self, data_buf: &mut [u8], addr_buf: &mut A, flags: i32) -> Result<usize> {
        xrecvfrom(self, data_buf, addr_buf, flags)
    }

    #[inline(always)]
    pub fn peer_name<A: SockAddrBuffer>(self, addr_buf: &mut A) -> Result<()> {
        xgetpeername(self, addr_buf)
    }

    #[inline(always)]
    pub fn close(self) -> Result<()> {
        xclose(self)
    }
    
    #[inline(always)]
    #[allow(unused_variables)]
    pub fn set_socket_option<O: SocketOption>(&self, option: O, value: O::ValueType) -> Result<()> 
    where 
        O::ValueType: 'static
    {
        if TypeId::of::<O::ValueType>() == TypeId::of::<std::time::Duration>() {
            let duration = unsafe { &*( &value as *const _ as *const std::time::Duration) };
            let timeval = sys::TimeVal::from_duration(*duration);
            &timeval as *const _ as *const _;
            xsetsockopt(*self, O::level(), O::name(), &timeval, O::len())
        } else {
            &value as *const O::ValueType as *const _;
            xsetsockopt(*self, O::level(), O::name(), &value, O::len())
        }
    }
}

impl Deref for Socket {
    type Target = SocketRaw;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
