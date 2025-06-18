use std::{mem::MaybeUninit, net::ToSocketAddrs};
use super::{sys::SockAddrIn6, *};

#[cfg(unix)]
pub type SocketRaw = i32;
#[cfg(windows)]
pub type SocketRaw = usize;


#[derive(Copy, Clone)]
#[repr(C, packed)]
pub struct Socket(SocketRaw);

impl <'a>Socket {
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
    pub fn send_to<A: SocketAddressBuffer>(self, buf: &[u8], addr: &A, flags: i32) -> Result<usize> {
        xsendto(self, buf, flags, addr)
    }

    #[inline(always)]
    pub fn sendmmsg<A: SocketAddressBuffer>(self, bufs: &[(&[u8], &A)], flags: i32) -> Result<usize> {
        xsendmmsg(self, bufs, flags)
    }

    #[inline(always)]
    pub fn popmsgv4(self, data_buf: &mut [u8], data_len: &mut usize, flags: i32) -> Result<SocketAddrSrcV4> {
        xrecvfrom_v4(self, data_buf, data_len, flags)
    }
    
    pub fn popmsgv6(self, data_buf: &mut [u8], data_len: &mut usize, flags: i32) -> Result<SocketAddrSrcV6> {
        xrecvfrom_v6(self, data_buf, data_len, flags)
    }
    
    #[inline(always)]
    pub fn popmsg(self, data_buf: &mut [u8], data_len: &mut usize, flags: i32) -> Result<SocketAddrSrc> {
        popmsg(self, data_buf, data_len, flags)
    }

    #[inline(always)]
    pub fn vecrecv<IpvXInbox>(self, inbox: &mut IpvXInbox, flags: i32) -> Result<usize>
    where IpvXInbox: IpBucket {
        vecrecv(self, inbox, flags)
    }

    #[inline(always)]
    pub fn recv_from_v4(self, data_buf: &mut [u8], data_len: &mut usize, flags: i32) -> Result<SocketAddrSrcV4> {
        xrecvfrom_v4(self, data_buf, data_len, flags)
    }

    #[inline(always)]
    pub fn recv_from_v6(self, data_buf: &mut [u8], data_len: &mut usize, flags: i32) -> Result<SocketAddrSrcV6> {
        xrecvfrom_v6(self, data_buf, data_len, flags)
    }

    #[inline(always)]
    pub fn peer_name_v4(self) -> Result<SockAddrIn> {
    let mut addr_buf = MaybeUninit::<SockAddrIn>::uninit();
        xgetpeername(self, &mut addr_buf).unwrap();
        Ok(unsafe { addr_buf.assume_init() })

    }
    
    #[inline(always)]
    pub fn peer_name_v6(self) -> Result<SockAddrIn6> {
        let mut addr_buf = MaybeUninit::<SockAddrIn6>::uninit();
        xgetpeername(self, &mut addr_buf).unwrap();
        Ok(unsafe { addr_buf.assume_init() })
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

    #[inline(always)]
    pub fn as_raw(&self) -> SocketRaw {
        self.0
    }
}