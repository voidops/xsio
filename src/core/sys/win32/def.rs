use std::ffi::c_int;

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
pub const IPPROTO_QUIC: c_int = 261;

pub const TCP_NODELAY: c_int = 0x0001;

pub const SHUT_RD: c_int = 0;
pub const SHUT_WR: c_int = 1;

pub const SYS_SENDMMSG: usize = 307;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SockLen {
    pub len: c_int,
}

#[repr(C)]
pub struct SockAddr {
    pub sa_family: u16,
    pub sa_data: [i8; 14],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct InAddr {
    pub s_addr: [u8; 4]
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct In6Addr {
    pub s6_addr: [u8; 16],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SockAddrIn {
    pub sin_family: u16,
    pub sin_port: u16,
    pub sin_addr: InAddr,
    pub sin_zero: [u8; 8],
}

#[repr(C)]
#[derive(Clone, Copy)]
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

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Iovec {
    pub iov_base: *mut u8,
    pub iov_len: usize 
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Msghdr {
    pub msg_name: *mut u8,
    pub msg_namelen: u32,
    pub msg_iov: *mut Iovec,
    pub msg_iovlen: usize,
    pub msg_control: *mut u8,
    pub msg_controllen: usize,
    pub msg_flags: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Mmsghdr {
    pub msg_hdr: Msghdr, pub msg_len: u32
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Timespec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
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
    
    pub fn RIOReceive(socket: usize, buf: *mut u8, len: usize, flags: c_int, bytes_received: *mut usize) -> c_int;
}
extern "C" {
    //pub fn syscall(num: usize, ...) -> isize;
}