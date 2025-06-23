use crate::*;

static XDP_OBJ: &[u8] = include_bytes!("xdp/build/xdp.o");


impl XUdpServerWorker {

    pub(crate) fn begin_raw_queue_poll_loop(&mut self, handler: &mut Box<dyn FnMut(&SocketAddrSrcV4, &[u8]) + Send + 'static>) -> std::io::Result<()> {
        #[cfg(not(unix))]
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "Kernel support is currently only supported on Unix systems (XDP mode)",
            ));
        }
        // Attempting to use XDP for IPv4 UDP...
        #[cfg(unix)]
        {
            use std::{os::raw::c_int, sync::atomic::Ordering};


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
                use std::os::raw::{c_int, c_void};

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
                use std::os::raw::{c_int, c_void};

                setsockopt(sock.as_raw(), SOL_XDP, XDP_RX_RING,  &desc_cnt as *const _ as *const c_void, size_of::<u32>() as c_int);
                setsockopt(sock.as_raw(), SOL_XDP, XDP_UMEM_FILL_RING,  &desc_cnt as *const _ as *const c_void, size_of::<u32>() as c_int);
                setsockopt(sock.as_raw(), SOL_XDP, XDP_TX_RING,  &desc_cnt as *const _ as *const c_void, size_of::<u32>() as c_int);
                setsockopt(sock.as_raw(), SOL_XDP, XDP_UMEM_COMPLETION_RING,  &desc_cnt as *const _ as *const c_void, size_of::<u32>() as c_int);
            }
            let mut offs = XdpMmapOffsets::default();
            let mut optlen = size_of::<XdpMmapOffsets>() as c_int;
            let r = unsafe {
                use std::os::raw::c_void;

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
            self.make_ready();
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
}