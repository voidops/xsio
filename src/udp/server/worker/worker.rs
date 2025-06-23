use std::{net::SocketAddr, sync::{atomic::{AtomicBool, AtomicU64, Ordering}, mpsc::Sender, Arc}, time::Duration};

use crate::*;

#[macro_export]
macro_rules! dprintln {
    ($self:expr, $fmt:literal $(, $args:expr)* $(,)?) => {
        if $self.debug_mode {
            println!($fmt $(, $args)*);
        }
    };
}

pub struct XUdpServerWorker {
    pub(crate) number: usize,
    pub(crate) name: String,
    pub(crate) address: SocketAddr,
    pub(crate) running: Arc<AtomicBool>,
    pub(crate) ipv4_handler: Option<Box<dyn FnMut(&SocketAddrSrcV4, &[u8]) + Send>>,
    pub(crate) ipv6_handler: Option<Box<dyn FnMut(&SocketAddrSrcV6, &[u8]) + Send>>,
    pub(crate) drain_capacity: usize,
    pub(crate) frame_count: usize,
    pub(crate) frame_size: usize,
    pub(crate) msg_len: usize,
    pub(crate) kernel_socket_capacity: usize,
    pub(crate) debug_mode: bool,
    pub(crate) kernel_mode: bool,
    pub(crate) processed_counter: Arc<AtomicU64>,
    pub(crate) ready_tx: Sender<()>,
}

impl XUdpServerWorker {
    pub fn new(number: usize, name: String, address: SocketAddr, ready_tx: Sender<()>) -> Self {
        Self {
            number,
            name,
            address,
            running: Arc::new(AtomicBool::new(false)),
            ipv4_handler: None,
            ipv6_handler: None,
            drain_capacity: 1,
            frame_count: 1024,
            frame_size: 2048,
            msg_len: 2048,
            kernel_socket_capacity: 1024 * 1024,
            debug_mode: false,
            kernel_mode: false,
            processed_counter: Arc::new(AtomicU64::new(0)),
            ready_tx,
        }
    }

    pub fn set_socket_capacity(&mut self, size: usize) {
        if size > 0 {
            self.kernel_socket_capacity = size;
        } else {
            panic!("Receive buffer size must be greater than zero");
        }
    }

    pub fn set_max_frames(&mut self, max: usize) -> &mut Self {
        if max > 0 {
            self.frame_count = max;
        } else {
            panic!("Max frame count must be greater than zero");
        }
        self
    }

    pub fn set_frame_size(&mut self, size: usize) -> &mut Self {
        if size > 0 {
            self.frame_size = size;
        } else {
            panic!("Frame size must be greater than zero");
        }
        self
    }

    pub fn set_drain_capacity(&mut self, max: usize) -> &mut Self {
        self.drain_capacity = max;
        self
    }
    
    pub fn set_msg_len(&mut self, max: usize) -> &mut Self {
        self.msg_len = max;
        self
    }

    pub fn on_ipv4<F>(&mut self, h: F)
    where
        F: FnMut(&SocketAddrSrcV4, &[u8]) + Send + 'static,
    {
        if !self.address.is_ipv4() {
            panic!("Cannot set IPv4 handler on non-IPv4 address");
        }

        self.ipv4_handler = Some(Box::new(h));
    }

    pub fn on_ipv6<F>(&mut self, h: F)
    where
        F: FnMut(&SocketAddrSrcV6, &[u8]) + Send + 'static
    {
        if !self.address.is_ipv6() {
            panic!("Cannot set IPv6 handler on non-IPv6 address");
        }
        self.ipv6_handler = Some(Box::new(h));
    }

    pub(crate) fn make_ready(&mut self) {
        self.ready_tx.send(()).expect("Failed to send ready signal");
        while !self.running.load(Ordering::Acquire) {
            std::thread::yield_now();
        }
    }
    
    pub(crate) fn run(&mut self) -> std::io::Result<()> {
        if self.address.is_ipv4() {
            let mut handler = self.ipv4_handler.take().expect("No IPv4 handler set for XUdpServerWorker");
            if self.kernel_mode {
                self.begin_raw_queue_poll_loop(&mut handler)
            } else if self.drain_capacity > 1 {
                self.begin_ipv4_popmany_loop(&mut handler)
            } else {
                self.begin_ipv4_pop_loop(&mut handler)
            }
        } else if self.address.is_ipv6() {
            let mut handler = self.ipv6_handler.take().expect("No IPv6 handler set for XUdpServerWorker");
            if self.drain_capacity > 1 {
                self.begin_ipv6_popmany_loop(&mut handler)
            } else {
                self.begin_ipv6_pop_loop(&mut handler)
            }
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Unsupported address type",
            ))
        }
    }
}