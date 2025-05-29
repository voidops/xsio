use super::sys;

const C_INT_SIZE: i32 = std::mem::size_of::<std::os::raw::c_int>() as i32;

pub trait SocketOption {
    type ValueType;

    fn level() -> i32;
    fn name() -> i32;
    fn len() -> i32 {
        C_INT_SIZE
    }
}

macro_rules! socket_option {
    ($name:ident, $value_type:ty, $level:expr, $name_value:expr) => {
        #[derive(Debug)]
        pub struct $name;

        impl SocketOption for $name {
            type ValueType = $value_type;

            fn level() -> i32 {
                $level
            }

            fn name() -> i32 {
                $name_value
            }
        }
    };

    ($name:ident, $value_type:ty, $level:expr, $name_value:expr, $len:expr) => {
        #[derive(Debug)]
        pub struct $name;

        impl SocketOption for $name {
            type ValueType = $value_type;

            fn level() -> i32 {
                $level
            }

            fn name() -> i32 {
                $name_value
            }

            fn len() -> i32 {
                $len
            }
        }
    };
}

socket_option!(SoReuseAddr, bool, sys::SOL_SOCKET, sys::SO_REUSEADDR);
socket_option!(SoRecvBufSize, i32, sys::SOL_SOCKET, sys::SO_RCVBUF);
socket_option!(SoSendBufSize, i32, sys::SOL_SOCKET, sys::SO_SNDBUF);
socket_option!(SoRecvTimeout, std::time::Duration, sys::SOL_SOCKET, sys::SO_RCVTIMEO, std::mem::size_of::<sys::TimeVal>() as i32);
socket_option!(SoSendTimeout, std::time::Duration, sys::SOL_SOCKET, sys::SO_SNDTIMEO, std::mem::size_of::<sys::TimeVal>() as i32);
socket_option!(TcpNoDelay, bool, sys::IPPROTO_TCP, sys::TCP_NODELAY);

#[derive(Debug)]
pub enum SocketOptions {
    ReuseAddr(SoReuseAddr),
    RecvBufSize(SoRecvBufSize),
    SendBufSize(SoSendBufSize),
    RecvTimeout(SoRecvTimeout),
    SendTimeout(SoSendTimeout),
}

#[derive(Debug)]
pub enum TcpOptions {
    NoDelay(TcpNoDelay),
}