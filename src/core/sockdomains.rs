use super::sys;

pub trait AddressFamily {
    const DOMAIN: i32;
}

pub trait SocketType {
    const TYPE: i32;
}

pub struct AfInet;
pub struct AfInet6;
pub struct AfUnix;
#[cfg(not(windows))]
pub struct Packet;

impl AddressFamily for AfInet {
    const DOMAIN: i32 = sys::AF_INET;
}

impl AddressFamily for AfInet6 {
    const DOMAIN: i32 = sys::AF_INET6;
}

impl AddressFamily for AfUnix {
    const DOMAIN: i32 = sys::AF_UNIX;
}

#[cfg(not(windows))]
impl AddressFamily for Packet {
    const DOMAIN: i32 = sys::AF_PACKET;
}

pub struct SockStream;
pub struct SockDgram;
pub struct SockRaw;
pub struct SeqPacket;

impl SocketType for SockStream {
    const TYPE: i32 = sys::SOCK_STREAM;
}

impl SocketType for SockDgram {
    const TYPE: i32 = sys::SOCK_DGRAM;
}

impl SocketType for SockRaw {
    const TYPE: i32 = sys::SOCK_RAW;
}

impl SocketType for SeqPacket {
    const TYPE: i32 = sys::SOCK_SEQPACKET;
}

pub trait Protocol {
    const PROTOCOL: i32;
}

pub struct IpProtoTcp;
pub struct IpProtoUdp;
pub struct IpProtoIcmp;
pub struct IpProtoSctp;

impl Protocol for IpProtoTcp {
    const PROTOCOL: i32 = sys::IPPROTO_TCP;
}

impl Protocol for IpProtoUdp {
    const PROTOCOL: i32 = sys::IPPROTO_UDP;
}

impl Protocol for IpProtoIcmp {
    const PROTOCOL: i32 = sys::IPPROTO_ICMP;
}

impl Protocol for IpProtoSctp {
    const PROTOCOL: i32 = sys::IPPROTO_SCTP;
}

pub trait ValidSocket {}

impl ValidSocket for (AfInet, SockStream, IpProtoTcp) {}
impl ValidSocket for (AfInet, SockStream, IpProtoSctp) {}
impl ValidSocket for (AfInet, SockDgram, IpProtoUdp) {}
impl ValidSocket for (AfInet, SockRaw) {}
impl ValidSocket for (AfInet, SockRaw, IpProtoIcmp) {}

impl ValidSocket for (AfInet6, SockStream) {}
impl ValidSocket for (AfInet6, SockDgram) {}
impl ValidSocket for (AfInet6, SockRaw) {}

impl ValidSocket for (AfUnix, SockStream) {}
impl ValidSocket for (AfUnix, SockDgram) {}
impl ValidSocket for (AfUnix, SeqPacket) {}

#[cfg(not(windows))]
impl ValidSocket for (Packet, SockRaw) {}
#[cfg(not(windows))]
impl ValidSocket for (Packet, SockDgram) {}