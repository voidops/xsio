 
use crate::{Iovec, Mmsghdr, Msghdr, SocketAddrSrcV4, SocketAddrSrcV6};
use std::fmt::Debug;
use std::mem::MaybeUninit;
use std::ptr;

/// Common trait (unchanged)
///
pub trait IpBucket {
    fn capacity(&self) -> usize;
    fn size(&self) -> usize;
    fn raw_msgs_ptr(&mut self) -> *mut Mmsghdr;
    fn set_size(&mut self, size: usize);
    unsafe fn unsafe_set_size(&mut self, size: usize);
}

/* ============================ IPv4 =================================== */

#[derive(Clone)]
pub struct Ipv4Bucket {
    capacity: usize,
    msg_len: usize,
    size: usize,

    bufs: Box<[Vec<u8>]>,          // one Vec<u8> per message
    iovecs: Box<[Iovec]>,
    hdrs:   Box<[Msghdr]>,
    msgs:   Box<[Mmsghdr]>,
    addrs:  Box<[SocketAddrSrcV4]>,
}

impl Ipv4Bucket {
    pub fn new(capacity: usize, buffer_size: usize) -> Self {
        // main data blocks
        let mut bufs: Vec<Vec<u8>> = (0..capacity)
            .map(|_| vec![0u8; buffer_size])
            .collect();
        #[allow(invalid_value)]
        let mut iovecs = vec![unsafe { MaybeUninit::<Iovec>::uninit().assume_init() }; capacity];
        #[allow(invalid_value)]
        let mut hdrs = vec![unsafe { MaybeUninit::<Msghdr>::uninit().assume_init() }; capacity];
        #[allow(invalid_value)]
        let mut msgs = vec![unsafe { MaybeUninit::<Mmsghdr>::uninit().assume_init() }; capacity];
        #[allow(invalid_value)]
        let mut addrs = vec![unsafe { MaybeUninit::<SocketAddrSrcV4>::uninit().assume_init() }; capacity];

        // tie everything together
        for i in 0..capacity {
            iovecs[i].iov_base = bufs[i].as_mut_ptr();
            iovecs[i].iov_len  = buffer_size;

            hdrs[i].msg_name       = &mut addrs[i] as *mut _ as *mut u8;
            hdrs[i].msg_namelen    = std::mem::size_of::<SocketAddrSrcV4>() as u32;
            hdrs[i].msg_iov        = &mut iovecs[i];
            hdrs[i].msg_iovlen     = 1;
            hdrs[i].msg_control    = ptr::null_mut();
            hdrs[i].msg_controllen = 0;
            hdrs[i].msg_flags      = 0;

            msgs[i].msg_hdr = hdrs[i];
            msgs[i].msg_len = 0;
        }

        Self {
            capacity,
            msg_len: buffer_size,
            size: 0,
            bufs: bufs.into_boxed_slice(),
            iovecs: iovecs.into_boxed_slice(),
            hdrs: hdrs.into_boxed_slice(),
            msgs: msgs.into_boxed_slice(),
            addrs: addrs.into_boxed_slice(),
        }
    }

    #[inline(always)]
    pub fn peek(&self, index: usize) -> Option<(&SocketAddrSrcV4, &[u8])> {
        (index < self.size).then(|| {
            let addr = &self.addrs[index];
            let len  = self.msgs[index].msg_len as usize;
            (addr, &self.bufs[index][..len])
        })
    }

    #[inline(always)]
    pub unsafe fn unsafe_peek(&self, index: usize) -> (&SocketAddrSrcV4, &[u8]) {
        let addr = &self.addrs[index];
        let len  = self.msgs[index].msg_len as usize;
        (addr, &self.bufs[index][..len])
    }

    #[inline(always)]
    #[allow(invalid_value)]
    pub fn set_capacity(&mut self, capacity: usize) {
        self.capacity = capacity;
        self.bufs = (0..capacity)
            .map(|_| vec![0u8; self.msg_len])
            .collect::<Vec<_>>()
            .into_boxed_slice();
        self.iovecs = (0..capacity)
            .map(|_| unsafe { MaybeUninit::<Iovec>::uninit().assume_init() })
            .collect::<Vec<_>>()
            .into_boxed_slice();
        self.hdrs = (0..capacity)
            .map(|_| unsafe { MaybeUninit::<Msghdr>::uninit().assume_init() })
            .collect::<Vec<_>>()
            .into_boxed_slice();
        self.msgs = (0..capacity)
            .map(|_| unsafe { MaybeUninit::<Mmsghdr>::uninit().assume_init() })
            .collect::<Vec<_>>()
            .into_boxed_slice();
        self.addrs = (0..capacity)
            .map(|_| unsafe { MaybeUninit::<SocketAddrSrcV4>::uninit().assume_init() })
            .collect::<Vec<_>>()
            .into_boxed_slice();
    }

    #[inline(always)]
    pub fn set_msg_len(&mut self, len: usize) {
        self.msg_len = len;
        for i in 0..self.size {
            self.msgs[i].msg_len = self.msg_len as u32;
        }
    }

    #[inline(always)]
    pub fn size(&self) -> usize {
        self.size
    }
}

impl IpBucket for Ipv4Bucket {
    fn capacity(&self) -> usize { self.capacity }
    fn size(&self) -> usize { self.size }

    #[inline(always)]
    fn raw_msgs_ptr(&mut self) -> *mut Mmsghdr { self.msgs.as_mut_ptr() }

    #[inline(always)]
    fn set_size(&mut self, s: usize) {
        assert!(s <= self.capacity, "size exceeds capacity");
        self.size = s;
    }

    #[inline(always)]
    unsafe fn unsafe_set_size(&mut self, s: usize) { self.size = s; }
}

impl Debug for Ipv4Bucket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ipv4Bucket")
            .field("capacity", &self.capacity)
            .field("buf_len", &self.msg_len)
            .field("size", &self.size)
            .finish()
    }
}

/* ============================ IPv6 =================================== */
pub struct Ipv6Bucket {
    capacity: usize,
    buf_len: usize,
    size: usize,

    bufs:  Box<[Vec<u8>]>,
    iovecs: Box<[Iovec]>,
    hdrs:   Box<[Msghdr]>,
    msgs:   Box<[Mmsghdr]>,
    addrs:  Box<[SocketAddrSrcV6]>,
}

impl Ipv6Bucket {
    #[allow(invalid_value)]
    pub fn new(capacity: usize, buffer_size: usize) -> Self {
        let mut bufs: Vec<Vec<u8>> = (0..capacity)
            .map(|_| vec![0u8; buffer_size])
            .collect();
        let mut iovecs = vec![unsafe { MaybeUninit::<Iovec>::uninit().assume_init() }; capacity];
        let mut hdrs   = vec![unsafe { MaybeUninit::<Msghdr>::uninit().assume_init() }; capacity];
        let mut msgs   = vec![unsafe { MaybeUninit::<Mmsghdr>::uninit().assume_init() }; capacity];
        let mut addrs  = vec![unsafe { MaybeUninit::<SocketAddrSrcV6>::uninit().assume_init() }; capacity];

        for i in 0..capacity {
            iovecs[i].iov_base = bufs[i].as_mut_ptr();
            iovecs[i].iov_len  = buffer_size;

            hdrs[i].msg_name       = &mut addrs[i] as *mut _ as *mut u8;
            hdrs[i].msg_namelen    = std::mem::size_of::<SocketAddrSrcV6>() as u32;
            hdrs[i].msg_iov        = &mut iovecs[i];
            hdrs[i].msg_iovlen     = 1;
            hdrs[i].msg_control    = ptr::null_mut();
            hdrs[i].msg_controllen = 0;
            hdrs[i].msg_flags      = 0;

            msgs[i].msg_hdr = hdrs[i];
            msgs[i].msg_len = 0;
        }

        Self {
            capacity,
            buf_len: buffer_size,
            size: 0,
            bufs: bufs.into_boxed_slice(),
            iovecs: iovecs.into_boxed_slice(),
            hdrs: hdrs.into_boxed_slice(),
            msgs: msgs.into_boxed_slice(),
            addrs: addrs.into_boxed_slice(),
        }
    }

    #[inline(always)]
    pub fn peek(&self, index: usize) -> Option<(&SocketAddrSrcV6, &[u8])> {
        (index < self.size).then(|| {
            let addr = &self.addrs[index];
            let len  = self.msgs[index].msg_len as usize;
            (addr, &self.bufs[index][..len])
        })
    }

    #[inline(always)]
    pub unsafe fn unsafe_peek(&self, index: usize) -> (&SocketAddrSrcV6, &[u8]) {
        let addr = &self.addrs[index];
        let len  = self.msgs[index].msg_len as usize;
        (addr, &self.bufs[index][..len])
    }

    #[inline(always)]
    #[allow(invalid_value)]
    pub fn set_capacity(&mut self, capacity: usize) {
        self.capacity = capacity;
        self.bufs = (0..capacity)
            .map(|_| vec![0u8; self.buf_len])
            .collect::<Vec<_>>()
            .into_boxed_slice();
        self.iovecs = (0..capacity)
            .map(|_| unsafe { MaybeUninit::<Iovec>::uninit().assume_init() })
            .collect::<Vec<_>>()
            .into_boxed_slice();
        self.hdrs = (0..capacity)
            .map(|_| unsafe { MaybeUninit::<Msghdr>::uninit().assume_init() })
            .collect::<Vec<_>>()
            .into_boxed_slice();
        self.msgs = (0..capacity)
            .map(|_| unsafe { MaybeUninit::<Mmsghdr>::uninit().assume_init() })
            .collect::<Vec<_>>()
            .into_boxed_slice();
        self.addrs = (0..capacity)
            .map(|_| unsafe { MaybeUninit::<SocketAddrSrcV6>::uninit().assume_init() })
            .collect::<Vec<_>>()
            .into_boxed_slice();
    }

    #[inline(always)]
    pub fn size(&self) -> usize {
        self.size
    }
}

impl IpBucket for Ipv6Bucket {
    fn capacity(&self) -> usize { self.capacity }
    fn size(&self) -> usize { self.size }

    #[inline(always)]
    fn raw_msgs_ptr(&mut self) -> *mut Mmsghdr { self.msgs.as_mut_ptr() }

    #[inline(always)]
    fn set_size(&mut self, s: usize) {
        assert!(s <= self.capacity, "size exceeds capacity");
        self.size = s;
    }

    #[inline(always)]
    unsafe fn unsafe_set_size(&mut self, s: usize) { self.size = s; }
}
