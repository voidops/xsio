use std::{sync::atomic::Ordering, time::Duration};

use crate::*;

impl XUdpServerWorker {
    pub(crate) fn begin_ipv4_pop_loop(&mut self, handler: &mut Box<dyn FnMut(&SocketAddrSrcV4, &[u8]) + Send + 'static>) -> std::io::Result<()> {
        let socket = Socket::new(AfInet, SockDgram, IpProtoUdp).unwrap();
        socket.set_socket_option(SoRecvBufSize, self.kernel_socket_capacity)?;
        socket.set_socket_option(SoRecvTimeout, Duration::from_millis(500))?;
        socket.set_socket_option(SoReuseAddr, true)?;
        socket.bind(&self.address)?;
        let mut data = [0u8; 1024];
        let mut data_len = 0;
        dprintln!(self, "[XUdpServerWorker] Starting IPv4 pop worker on {}", self.address);
        let mut c = 0;
        self.make_ready();
        while self.running.load(Ordering::Relaxed) {
            match socket.popmsgv4(&mut data, &mut data_len, 0) {
                Ok(addr) => {
                    handler(&addr, &data[..data_len]);
                    c += 1;
                    if c % 100_000 == 0 {
                        // Atomically commit the processed packets count
                        self.processed_counter.fetch_add(c, Ordering::Relaxed);
                        c = 0;
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

    pub(crate) fn begin_ipv6_pop_loop(&mut self, handler: &mut Box<dyn FnMut(&SocketAddrSrcV6, &[u8]) + Send + 'static>) -> std::io::Result<()> {
        let mut data = vec![0u8; self.msg_len];
        let mut data_len = 0;
        let socket = Socket::new(AfInet6, SockDgram, IpProtoUdp).unwrap();
        socket.set_socket_option(SoRecvBufSize, self.kernel_socket_capacity)?;
        socket.set_socket_option(SoRecvTimeout, Duration::from_millis(500))?;
        socket.set_socket_option(SoReuseAddr, true)?;
        socket.bind(&self.address)?;
        let data_ref = &mut data;
        self.make_ready();
        while self.running.load(Ordering::Relaxed) {
            match socket.popmsgv6(data_ref, &mut data_len, 0) {
                Ok(addr) => {
                    handler(&addr, &data_ref[..data_len]);
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