use std::{sync::{atomic::Ordering, mpsc::Sender}, time::Duration};

use crate::*;

impl XUdpServerWorker {
    pub(crate) fn begin_ipv4_popmany_loop(&mut self, handler: &mut Box<dyn FnMut(&SocketAddrSrcV4, &[u8]) + Send + 'static>) -> std::io::Result<()> {
        let mut bucket = Ipv4Bucket::new(self.drain_capacity, self.msg_len);
        let socket = Socket::new(AfInet, SockDgram, IpProtoUdp).unwrap();
        socket.set_socket_option(SoRecvBufSize, self.kernel_socket_capacity)?;
        socket.set_socket_option(SoRecvTimeout, Duration::from_millis(500))?;
        socket.set_socket_option(SoReuseAddr, true)?;
        socket.bind(&self.address)?;
        if self.debug_mode {
            println!("[XUdpServerWorker] Starting IPv4 drain worker on {}", self.address);
        }
        let bucket_ref = &mut bucket;
        self.make_ready();
        while self.running.load(Ordering::Relaxed) {
            match socket.vecrecv(bucket_ref, 0) {
                Ok(count) => {
                    for i in 0..count {
                        let (addr, buf) = unsafe { bucket_ref.unsafe_peek(i) };
                        handler(addr, buf);
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => {
                    continue;
                }
                Err(e) => {
                    dprintln!(self, "Error receiving data: {e}");
                    break;
                }
            }
        }
        Ok(())
    }

    pub(crate) fn begin_ipv6_popmany_loop(&mut self, handler: &mut Box<dyn FnMut(&SocketAddrSrcV6, &[u8]) + Send + 'static>) -> std::io::Result<()> {
        let mut bucket = Ipv6Bucket::new(self.drain_capacity, self.msg_len);
        let socket = Socket::new(AfInet6, SockDgram, IpProtoUdp).unwrap();
        socket.set_socket_option(SoRecvBufSize, self.kernel_socket_capacity)?;
        socket.set_socket_option(SoRecvTimeout, Duration::from_millis(500))?;
        socket.set_socket_option(SoReuseAddr, true)?;
        socket.bind(&self.address)?;
        let bucket_ref = &mut bucket;
        self.make_ready();
        while self.running.load(Ordering::Relaxed) {
            match socket.vecrecv(bucket_ref, 0) {
                Ok(count) => {
                    for i in 0..count {
                        let (addr, buf) = unsafe { bucket_ref.unsafe_peek(i) };
                        handler(addr, buf);
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => {
                    continue;
                }
                Err(e) => {
                    dprintln!(self, "Error receiving data: {e}");
                    break;
                }
            }
        }
        Ok(())
    }
}