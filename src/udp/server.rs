use std::{
    ffi::CString, net::SocketAddr, os::raw::{c_int, c_void}, sync::{atomic::{AtomicBool, AtomicUsize, Ordering}, Arc}, time::Duration
};

use crate::*;
use super::flood::UdpFloodTest;

// a macro to eprintln! if debug_mode is true
#[macro_export]
macro_rules! dprintln {
    ($self:expr, $fmt:literal $(, $args:expr)* $(,)?) => {
        if $self.debug_mode {
            println!($fmt $(, $args)*);
        }
    };
}

static XDP_OBJ: &[u8] = include_bytes!("xdp/build/xdp.o");

pub struct XUdpServerWorker {
    number: usize,
    name: String,
    address: SocketAddr,
    running: Arc<AtomicBool>,
    ipv4_handler: Option<Box<dyn FnMut(&SocketAddrSrcV4, &[u8]) + Send>>,
    ipv6_handler: Option<Box<dyn FnMut(&SocketAddrSrcV6, &[u8]) + Send>>,
    drain_capacity: usize,
    frame_count: usize,
    frame_size: usize,
    msg_len: usize,
    kernel_socket_capacity: usize,
    debug_mode: bool,
    ipv4_invoke_fn: Option<fn(&mut Self) -> std::io::Result<()>>,
    ipv6_invoke_fn: Option<fn(&mut Self) -> std::io::Result<()>>
}

impl XUdpServerWorker {
    pub fn new(number: usize, name: String, address: SocketAddr) -> Self {
        Self {
            number,
            name,
            address,
            running: Arc::new(AtomicBool::new(false)),
            ipv4_handler: None,
            ipv6_handler: None,
            drain_capacity: 8,
            frame_count: 1024,
            frame_size: 2048,
            msg_len: 2048,
            kernel_socket_capacity: 1024 * 1024,
            debug_mode: false,
            ipv4_invoke_fn: None,
            ipv6_invoke_fn: None,
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
        self.ipv4_invoke_fn = if self.drain_capacity > 1 {
            Some(Self::begin_ipv4_drain_next)
        } else {
            Some(Self::begin_ipv4_pop_next)
        };
    }

    pub fn on_ipv6(&mut self, h: Box<dyn FnMut(&SocketAddrSrcV6, &[u8]) + Send>) {
        if !self.address.is_ipv6() {
            panic!("Cannot set IPv6 handler on non-IPv6 address");
        }
        self.ipv6_handler = Some(h);
        self.ipv6_invoke_fn = if self.drain_capacity > 1 {
            Some(Self::begin_ipv6_drain_next)
        } else {
            Some(Self::begin_ipv6_pop_next)
        };
    }

    fn begin_ipv4_pop_next(&mut self) -> std::io::Result<()> {
        let handler = self.ipv4_handler.as_mut().expect("No IPv4 handler set for XUdpServerWorker");
        let socket = Socket::new(AfInet, SockDgram, IpProtoUdp).unwrap();
        socket.set_socket_option(SoRecvBufSize, self.kernel_socket_capacity)?;
        socket.set_socket_option(SoRecvTimeout, Duration::from_millis(500))?;
        socket.set_socket_option(SoReuseAddr, true)?;
        socket.bind(&self.address)?;
        let mut data = [0u8; 1024];
        let mut data_len = 0;
        dprintln!(self, "[XUdpServerWorker] Starting IPv4 pop worker on {}", self.address);
        while self.running.load(Ordering::Relaxed) {
            match socket.popmsgv4(&mut data, &mut data_len, 0) {
                Ok(addr) => {
                    handler(&addr, &data[..data_len]);
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

    fn begin_ipv4_drain_next(&mut self) -> std::io::Result<()> {
        let handler = self.ipv4_handler.as_mut().expect("No IPv4 handler set for XUdpServerWorker");
        #[cfg(windows)]
        {
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
        }
        // Attempting to use XDP for IPv4 UDP...
        #[cfg(unix)]
        {
            let sock = Socket::new(AfXdp, SockRaw, NoProtocol).unwrap();
            dprintln!(self, "[{} INFO] Socket file descriptor: {}", self.name, sock.as_raw());
            let umem_len: u64 = self.frame_count as u64 * self.frame_size as u64;
            let umem_ptr = unsafe {
                mmap(std::ptr::null_mut(), umem_len as usize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)
            };
            if umem_ptr == MAP_FAILED {
                return Err(std::io::Error::last_os_error());
            }
            dprintln!(self, "[{} INFO] XDP UMEM allocated at: {:p} with length: {}", self.name, umem_ptr, umem_len);
            let umem = unsafe { std::slice::from_raw_parts_mut(umem_ptr as *mut u8, umem_len as usize) };
            let reg = XdpUmemReg {
                addr: umem_ptr as u64,
                len: umem_len,
                chunk_size: self.frame_size as u32,
                headroom: 0,
                flags: 0,
            };
            let r = unsafe {
                setsockopt(
                    sock.as_raw(),
                    SOL_XDP,
                    XDP_UMEM_REG,
                    &reg as *const _ as *const c_void,
                    size_of::<XdpUmemReg>() as c_int,
                )
            };
            if r < 0 {
                dprintln!(self, "[{} ERROR] Failed to register XDP UMEM: {}", self.name, std::io::Error::last_os_error());
                return Err(std::io::Error::last_os_error());
            }
            let desc_cnt: u32 = self.frame_count as u32;
            unsafe {
                setsockopt(sock.as_raw(), SOL_XDP, XDP_RX_RING,  &desc_cnt as *const _ as *const c_void, size_of::<u32>() as c_int);
                setsockopt(sock.as_raw(), SOL_XDP, XDP_UMEM_FILL_RING,  &desc_cnt as *const _ as *const c_void, size_of::<u32>() as c_int);
                setsockopt(sock.as_raw(), SOL_XDP, XDP_TX_RING,  &desc_cnt as *const _ as *const c_void, size_of::<u32>() as c_int);
                setsockopt(sock.as_raw(), SOL_XDP, XDP_UMEM_COMPLETION_RING,  &desc_cnt as *const _ as *const c_void, size_of::<u32>() as c_int);
            }
            let mut offs = XdpMmapOffsets::default();
            let mut optlen = size_of::<XdpMmapOffsets>() as c_int;
            let r = unsafe {
                getsockopt(
                    sock.as_raw(),
                    SOL_XDP,
                    XDP_MMAP_OFFSETS,
                    &mut offs as *mut _ as *mut c_void,
                    &mut optlen,
                )
            };
            if r < 0 {
                dprintln!(self, "[{} ERROR] Failed to get XDP mmap offsets: {}", self.name, std::io::Error::last_os_error());
                return Err(std::io::Error::last_os_error());
            }
            dprintln!(self, "[{} INFO] XDP mmap offsets: {:?}", self.name, offs);
            let page_size = unsafe { getpagesize() } as u64;
            let offset = offs.rx.desc & !(page_size - 1); // round down to page boundary
            let delta = offs.rx.desc - offset;
            let map_len = delta + (desc_cnt as u64 * std::mem::size_of::<XdpDesc>() as u64);
            let rx_raw = unsafe {
                mmap(
                    std::ptr::null_mut(),
                    map_len as usize,
                    PROT_READ | PROT_WRITE,
                    MAP_SHARED,
                    sock.as_raw(),
                    offset as i64,
                )
            };
            if rx_raw == MAP_FAILED {
                return Err(std::io::Error::last_os_error());
            }

            let rx_ring = unsafe { (rx_raw as *mut u8).add(delta as usize) as *mut XdpDesc };
            if rx_ring == MAP_FAILED as *mut XdpDesc {
                dprintln!(self, "[{} INFO] Failed to mmap RX ring: {:p}", self.name, rx_ring);
                return Err(std::io::Error::last_os_error());
            }
            dprintln!(self, "[{} INFO] RX ring mmaped at: {:p}", self.name, rx_ring);

            let raw_ptr = unsafe {
                mmap(
                    std::ptr::null_mut(),
                    map_len as usize,
                    PROT_READ | PROT_WRITE,
                    MAP_SHARED,
                    sock.as_raw(),
                    offset as i64,
                )
            };

            if raw_ptr == MAP_FAILED {
                panic!(
                    "[{} ERROR] mmap fill ring failed: {}",
                    self.name,
                    std::io::Error::last_os_error()
                );
            }

            let fill_ring = unsafe { (raw_ptr as *mut u8).add(delta as usize) as *mut u64 };
            let tx_ring = unsafe {
                mmap(
                    std::ptr::null_mut(),
                    (offs.tx.desc + (desc_cnt as u64) * size_of::<XdpDesc>() as u64) as usize,
                    PROT_READ | PROT_WRITE,
                    MAP_SHARED,
                    sock.as_raw(),
                    offs.tx.desc as i64,
                ) as *mut XdpDesc
            };
            /*
            let completion_ring = unsafe {
                mmap(
                    std::ptr::null_mut(),
                    (offs.cr.desc + (desc_cnt as u64) * size_of::<u64>() as u64) as usize,
                    PROT_READ | PROT_WRITE,
                    MAP_SHARED,
                    sock.as_raw(),
                    offs.cr.desc as i64,
                ) as *mut u64
            };
            */
            let iface = std::env::var("XDP_IFACE").unwrap_or_else(|_| {
                use std::process::Command;
                let output = Command::new("sh")
                    .arg("-c")
                    .arg("ip route get 1 | awk '{print $5; exit}'")
                    .output()
                    .expect("Failed to query default interface");
                String::from_utf8_lossy(&output.stdout).trim().to_string()
            });
            let c_iface = std::ffi::CString::new(iface.clone()).expect("CString failed");
            let ifindex = unsafe { if_nametoindex(c_iface.as_ptr() as _) };
            if ifindex == 0 {
                dprintln!(self, "[{} ERROR] Interface '{}' not found or has no index", self.name, iface);
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid interface index"));
            }
            let saddr = SockAddrXdp {
                sxdp_family: AF_XDP as u16,
                sxdp_flags: 0,
                sxdp_ifindex: ifindex,
                sxdp_queue_id: 0,
                sxdp_shared_umem_fd: 0,
            };
            let ret = unsafe { bind(sock.as_raw(), &saddr as *const _ as *const SockAddr, size_of::<SockAddrXdp>() as c_int) };
            if ret < 0 {
                dprintln!(self, "[{} Error] While attempting to bind to interface: {} (index: {}): {}", self.name, iface, ifindex, std::io::Error::last_os_error());
                return Err(std::io::Error::last_os_error());
            }
            dprintln!(self, "[{} INFO] Bound to interface: {} (index: {})", self.name, iface, ifindex);
            let attr = bpf_attr {
                prog_load: unsafe { std::mem::zeroed() },
            };
            /*
            let elf = Elf::load_from_bytes(XDP_OBJ).expect("Failed to load XDP ELF object");
            println!("All sections: {:?}", elf.sections);
            let text_section = elf.get_section_data_by_name("xdp_sock").expect("Failed to find .text section in XDP ELF object");
            dprintln!(self, "[{} INFO] XDP ELF text section found at offset: {:?}", self.name, text_section);
            let license = CString::new("GPL").unwrap();
            attr.prog_load.prog_type = BPF_PROG_TYPE_XDP;
            attr.prog_load.insn_cnt = (text_section.len() / std::mem::size_of::<BpfInsn>()) as u32;
            attr.prog_load.insns =  text_section.as_ptr() as u64;
            attr.prog_load.license = license.as_ptr() as u64;
            let mut log_buf = vec![0u8; 65536];
            attr.prog_load.log_level = 1;
            attr.prog_load.log_buf = log_buf.as_mut_ptr() as u64;
            attr.prog_load.log_size = log_buf.len() as u32;
            let prog_fd = unsafe {
                bpf(BPF_PROG_LOAD, &mut attr, std::mem::size_of::<bpf_attr>() as u32)
            };
            if prog_fd < 0 {
                dprintln!(self, "[{} Error] Loading XSIO's BPF Program failed.\nBPF log dump:\n------------\n{}------------", self.name, String::from_utf8_lossy(&log_buf));
                return Err(std::io::Error::last_os_error());
            }*/
            let prog_fd = load_xdp(XDP_OBJ, ".maps").expect("Failed to load XDP program from embedded object");
            dprintln!(self, "[{} INFO] BPF program loaded with fd: {}", self.name, prog_fd);
            let attach_ret = unsafe {
                bpf_set_link_xdp_fd(ifindex, prog_fd.as_raw_fd(), XDP_FLAGS_SKB_MODE | XDP_FLAGS_UPDATE_IF_NOEXIST)
            };
            if attach_ret < 0 {
                dprintln!(self, "[{} Error] Failed to attach XDP program to interface {}: {}", self.name, iface, std::io::Error::last_os_error());
                return Err(std::io::Error::last_os_error());
            }
            dprintln!(self, "[{} INFO] XDP program loaded with fd: {}", self.name, prog_fd);
            for i in 0..desc_cnt {
                unsafe { std::ptr::write(fill_ring.add(i as usize), (i as u64) * self.frame_size as u64) }; // addr = i*chunk
            }

            let mut pfd = PollFd { fd: sock.as_raw(), events: POLLIN, revents: 0 };

            dprintln!(self, "[XUdpServerWorker] IPv4 XDP drain running on eth0 q0");

            while self.running.load(Ordering::Relaxed) {
                let poll_res = unsafe { poll(&mut pfd, 1, 500) };
                if poll_res < 0 {
                    dprintln!(self, "Error polling socket: {}", std::io::Error::last_os_error());
                    break;
                }
                println!("[{}]", poll_res);
                if pfd.revents & POLLIN != 0 {
                    for i in 0..desc_cnt {
                        let desc = unsafe { rx_ring.add(i as usize).as_mut().unwrap() };
                        if desc.len == 0 {
                            continue; // No data
                        }
                        let addr = SocketAddrSrcV4::from_raw_parts(desc.addr);
                        let data = unsafe { std::slice::from_raw_parts(umem.as_ptr().add(desc.addr as usize), desc.len as usize) };
                        handler(&addr, data);
                        desc.len = 0; // Mark as processed
                    }
                }
            }
        }
        Ok(())
    }

    fn begin_ipv6_pop_next(&mut self) -> std::io::Result<()> {
        let handler = self.ipv6_handler.as_mut().expect("No IPv6 handler set for XUdpServerWorker");
        let mut data = vec![0u8; self.msg_len];
        let mut data_len = 0;
        let socket = Socket::new(AfInet6, SockDgram, IpProtoUdp).unwrap();
        socket.set_socket_option(SoRecvBufSize, self.kernel_socket_capacity)?;
        socket.set_socket_option(SoRecvTimeout, Duration::from_millis(500))?;
        socket.set_socket_option(SoReuseAddr, true)?;
        socket.bind(&self.address)?;
        let data_ref = &mut data;
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

    fn begin_ipv6_drain_next(&mut self) -> std::io::Result<()> {
        let handler = self.ipv6_handler.as_mut().expect("No IPv6 handler set for XUdpServerWorker");
        let mut bucket = Ipv6Bucket::new(self.drain_capacity, self.msg_len);
        let socket = Socket::new(AfInet6, SockDgram, IpProtoUdp).unwrap();
        socket.set_socket_option(SoRecvBufSize, self.kernel_socket_capacity)?;
        socket.set_socket_option(SoRecvTimeout, Duration::from_millis(500))?;
        socket.set_socket_option(SoReuseAddr, true)?;
        socket.bind(&self.address)?;
        let bucket_ref = &mut bucket;
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

    fn begin(&mut self) -> std::io::Result<()> {
        if self.address.is_ipv4() {
            (self.ipv4_invoke_fn.expect("ipv4 handler invoke fn not set"))(self)
        } else if self.address.is_ipv6() {
            (self.ipv6_invoke_fn.expect("ipv6 handler invoke fn not set"))(self)
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Unsupported address type",
            ))
        }
    }

}
pub struct XUdpServer {
    running: Arc<AtomicBool>,
    address: SocketAddr,
    threads: Vec<std::thread::JoinHandle<()>>,
    worker_setup_handler: Option<Box<dyn FnMut(&mut XUdpServerWorker) + Send + 'static>>,
    debug_mode: bool,
    flood_counter: Arc<AtomicUsize>,
}

impl XUdpServer {
    pub fn new(address: SocketAddr) -> Self {
        Self {
            running: Arc::new(AtomicBool::new(false)),
            address,
            threads: Vec::new(),
            worker_setup_handler: None,
            debug_mode: false,
            flood_counter: Arc::new(AtomicUsize::new(0)),
        }
    }
    
    pub fn set_address(&mut self, address: SocketAddr) {
        self.address = address;
    }

    pub fn get_address(&self) -> SocketAddr {
        self.address
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }


    pub fn worker<WorkerSetupHandler>(&mut self, handler: WorkerSetupHandler) -> std::io::Result<()>
    where
        WorkerSetupHandler: FnMut(&mut XUdpServerWorker) + Send + 'static,{
        if self.running.load(Ordering::Relaxed) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Cannot set handler while server is running",
            ));
        }
        self.worker_setup_handler = Some(Box::new(handler));
        Ok(())
    }

    pub fn stop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
    }
    
    pub fn debug(&mut self, debug: bool) {
        self.debug_mode = debug;
    }

    pub fn start(&mut self, num_workers: usize) -> std::io::Result<()> {
        if self.worker_setup_handler.is_none() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "No worker handler set",
            ));
        }
        dprintln!(self, "[XUdpServer] Starting at {}", self.address);

        self.running.store(true, Ordering::Relaxed);

        for _ in 0..num_workers {
            let address = self.address;
            let running = self.running.clone();
            let mut thread_handler = self.worker_setup_handler.take();
            let len = self.threads.len();
            let debug_mode = self.debug_mode;
            let name = format!("XUdpServer->XUdpServerWorker-{}", len);
            let thread = std::thread::Builder::new()
                .name(name)
                .spawn(move || {
                    let name = format!("XUdpServer->XUdpServerWorker-{}", len);
                    let mut worker = XUdpServerWorker::new(len, name.clone(), address);
                    if let Some(handler) = thread_handler.as_mut() {
                        handler(&mut worker);
                    }
                    worker.running = running;
                    worker.debug_mode = debug_mode;
                    if let Err(e) = worker.begin() {
                        worker.running.store(false, Ordering::Relaxed);
                        panic!("[{name} LAST ERROR] {e}");
                    }
                })?;
            self.threads.push(thread);
        }

        Ok(())
    }

    pub fn wait(&mut self, interval: Option<Duration>) {
        let iv = interval.unwrap_or(Duration::from_millis(10));
        while self.running.load(Ordering::Relaxed) {
            std::thread::sleep(iv);
        }
    }

    pub fn worker_count(&self) -> usize {
        self.threads.len()
    }

    pub fn floodtest(&self, local_port: u16) -> UdpFloodTest {
        UdpFloodTest::new(&self, self.address.ip(), local_port)
    }

    pub fn flood_counter(&self) -> usize {
        self.flood_counter.load(Ordering::Relaxed)
    }
}
