use std::os::raw::{c_int, c_long, c_uint, c_void};

pub const AF_UNIX: c_int = 1;
pub const AF_INET: c_int = 2;
pub const AF_INET6: c_int = 10;
pub const AF_PACKET: c_int = 17;
pub const AF_XDP: c_int = 44;

pub const ETH_P_IP: u16 = 0x0800;

pub const SOCK_STREAM: c_int = 1;
pub const SOCK_DGRAM: c_int = 2;
pub const SOCK_RAW: c_int = 3;
pub const SOCK_SEQPACKET: c_int = 5;

pub const SOL_SOCKET: c_int = 1;
pub const SOL_XDP: c_int = 283;

pub const SO_REUSEADDR: c_int = 2;
pub const SO_RCVBUF: c_int = 8;
pub const SO_SNDBUF: c_int = 7;
pub const SO_RCVTIMEO: c_int = 20;
pub const SO_SNDTIMEO: c_int = 21;

pub const XDP_MMAP_OFFSETS: c_int = 1;
pub const XDP_RX_RING: c_int = 2;
pub const XDP_TX_RING: c_int = 3;
pub const XDP_UMEM_REG: c_int = 4;
pub const XDP_UMEM_FILL_RING: c_int = 5;
pub const XDP_UMEM_COMPLETION_RING: c_int = 6;
pub const XDP_STATISTICS: c_int = 7;
pub const XDP_OPTIONS: c_int = 8;

pub const XDP_SHARED_UMEM: u16 = 1 << 0;
pub const XDP_COPY: u16 = 1 << 1;
pub const XDP_ZEROCOPY: u16 = 1 << 2;
pub const XDP_USE_NEED_WAKEUP: u16 = 1 << 3;

pub const XDP_FLAGS_UPDATE_IF_NOEXIST: u32 = 1 << 0;
pub const XDP_FLAGS_SKB_MODE: u32 = 1 << 1;
pub const XDP_FLAGS_DRV_MODE: u32 = 1 << 2;
pub const XDP_FLAGS_HW_MODE: u32 = 1 << 3;
pub const XDP_FLAGS_REPLACE: u32 = 1 << 4;

pub const IPPROTO_HOPOPTS: c_int = 0;
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
pub const IPPROTO_IPV6: c_int = 41;
pub const IPPROTO_ROUTING: c_int = 43;
pub const IPPROTO_FRAGMENT: c_int = 44;
pub const IPPROTO_ESP: c_int = 50;
pub const IPPROTO_AH: c_int = 51;
pub const IPPROTO_ICMPV6: c_int = 58;
pub const IPPROTO_NONE: c_int = 59;
pub const IPPROTO_DSTOPTS: c_int = 60;
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

pub const TCP_NODELAY: c_int = 1;

pub const F_GETFL: c_int = 3;
pub const O_NONBLOCK: c_int = 0o4000;

pub const SHUT_RD: c_int = 0;
pub const SHUT_WR: c_int = 1;

pub const SYS_SENDMMSG: usize = 307;

pub const PROT_READ: c_int = 0x1;
pub const PROT_WRITE: c_int = 0x2;

pub const MAP_SHARED: c_int = 0x01;
pub const MAP_PRIVATE: c_int = 0x02;
pub const MAP_ANONYMOUS: c_int = 0x20;
pub const MAP_FAILED: *mut c_void = -1isize as *mut c_void;

pub const POLLIN: i16 = 0x001;
pub const POLLOUT: i16 = 0x004;
pub const POLLERR: i16 = 0x008;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SockLen(c_int);

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SockAddr {
    pub sa_family: u16,
    pub sa_data: [u8; 14],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct InAddr {
    pub s_addr: u32,
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
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SockAddrXdp {
    pub sxdp_family: u16,
    pub sxdp_flags: u16,
    pub sxdp_ifindex: u32,
    pub sxdp_queue_id: u32,
    pub sxdp_shared_umem_fd: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct XdpUmemReg {
    pub addr: u64,
    pub len: u64,
    pub chunk_size: u32,
    pub headroom: u32,
    pub flags: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct XdpDesc {
    pub addr: u64,
    pub len: u32,
    pub options: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct XdpRingOffset {
    pub producer: u64,
    pub consumer: u64,
    pub desc: u64,
    pub flags: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct XdpMmapOffsets {
    pub rx: XdpRingOffset,
    pub tx: XdpRingOffset,
    pub fr: XdpRingOffset,
    pub cr: XdpRingOffset,
}

#[repr(C)]
#[derive(Clone, Copy)]
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
    pub msg_hdr: Msghdr,
    pub msg_len: u32
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Timespec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PollFd {
    pub fd: c_int,
    pub events: i16,
    pub revents: i16,
}

#[repr(C)]
#[derive(Clone, Copy)]
#[allow(unused)]
struct EthHdr {
    dest: [u8; 6],
    src: [u8; 6],
    ethertype: u16,
}

pub type NfdsT = u64;

extern "C" {
    pub fn syscall(number: c_long, ...) -> c_long;
    pub fn sysconf(name: c_int) -> c_long;

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
    pub fn recvmmsg(sockfd: c_int, msgvec: *mut Mmsghdr, vlen: c_uint, flags: c_int, timeout: *mut Timespec) -> c_int;
    pub fn sendmmsg(sockfd: c_int, msgvec: *mut Mmsghdr, vlen: c_uint, flags: c_int) -> c_int;

    pub fn mmap(addr: *mut c_void, length: usize, prot: c_int, flags: c_int, fd: c_int, offset: i64) -> *mut c_void;
    pub fn munmap(addr: *mut c_void, length: usize) -> c_int;
    pub fn poll(fds: *mut PollFd, nfds: NfdsT, timeout: c_int) -> c_int;

    pub fn posix_memalign(aligned_ptr: *mut *mut c_void, alignment: usize, size: usize) -> c_int;

    pub fn rdtsc() -> u64;

    pub fn if_nametoindex(ifname: *const u8) -> u32;
    pub fn if_indextoname(ifindex: u32, ifname: *mut u8) -> *mut u8;

    pub fn getpagesize() -> c_int;
}