use std::os::raw::{c_char, c_int, c_long, c_uint, c_ulonglong};


pub const SYS_BPF: c_long = 321;
pub const BPF_SET_LINK_XDP_FD: c_int = 50;

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct BpfCmd(pub c_int);

pub const BPF_MAP_CREATE:   BpfCmd = BpfCmd(0);
pub const BPF_MAP_LOOKUP_ELEM: BpfCmd = BpfCmd(1);
pub const BPF_MAP_UPDATE_ELEM: BpfCmd = BpfCmd(2);
pub const BPF_MAP_DELETE_ELEM: BpfCmd = BpfCmd(3);
pub const BPF_MAP_GET_NEXT_KEY: BpfCmd = BpfCmd(4);
pub const BPF_PROG_LOAD: BpfCmd = BpfCmd(5);
pub const BPF_OBJ_PIN: BpfCmd = BpfCmd(6);
pub const BPF_OBJ_GET: BpfCmd = BpfCmd(7);
pub const BPF_PROG_ATTACH: BpfCmd = BpfCmd(8);
pub const BPF_PROG_DETACH: BpfCmd = BpfCmd(9);
pub const BPF_PROG_TEST_RUN: BpfCmd = BpfCmd(10);
pub const BPF_PROG_RUN: BpfCmd = BpfCmd(10);
pub const BPF_PROG_GET_NEXT_ID: BpfCmd = BpfCmd(11);
pub const BPF_MAP_GET_NEXT_ID: BpfCmd = BpfCmd(12);
pub const BPF_PROG_GET_FD_BY_ID: BpfCmd = BpfCmd(13);
pub const BPF_MAP_GET_FD_BY_ID: BpfCmd = BpfCmd(14);
pub const BPF_OBJ_GET_INFO_BY_FD: BpfCmd = BpfCmd(15);
pub const BPF_PROG_QUERY: BpfCmd = BpfCmd(16);
pub const BPF_RAW_TRACEPOINT_OPEN: BpfCmd = BpfCmd(17);
pub const BPF_BTF_LOAD: BpfCmd = BpfCmd(18);
pub const BPF_BTF_GET_FD_BY_ID: BpfCmd = BpfCmd(19);
pub const BPF_TASK_FD_QUERY: BpfCmd = BpfCmd(20);
pub const BPF_MAP_LOOKUP_AND_DELETE_ELEM: BpfCmd = BpfCmd(21);
pub const BPF_MAP_FREEZE: BpfCmd = BpfCmd(22);
pub const BPF_BTF_GET_NEXT_ID: BpfCmd = BpfCmd(23);
pub const BPF_MAP_LOOKUP_BATCH: BpfCmd = BpfCmd(24);
pub const BPF_MAP_LOOKUP_AND_DELETE_BATCH: BpfCmd = BpfCmd(25);
pub const BPF_MAP_UPDATE_BATCH: BpfCmd = BpfCmd(26);
pub const BPF_MAP_DELETE_BATCH: BpfCmd = BpfCmd(27);
pub const BPF_LINK_CREATE: BpfCmd = BpfCmd(28);
pub const BPF_LINK_UPDATE: BpfCmd = BpfCmd(29);
pub const BPF_LINK_GET_FD_BY_ID: BpfCmd = BpfCmd(30);
pub const BPF_LINK_GET_NEXT_ID: BpfCmd = BpfCmd(31);
pub const BPF_ENABLE_STATS: BpfCmd = BpfCmd(32);
pub const BPF_ITER_CREATE: BpfCmd = BpfCmd(33);
pub const BPF_LINK_DETACH: BpfCmd = BpfCmd(34);
pub const BPF_PROG_BIND_MAP: BpfCmd = BpfCmd(35);
pub const BPF_TOKEN_CREATE: BpfCmd = BpfCmd(36);
pub const __MAX_BPF_CMD: BpfCmd = BpfCmd(37);

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct BpfProgType(pub u32);

pub const BPF_PROG_TYPE_UNSPEC: BpfProgType = BpfProgType(0);
pub const BPF_PROG_TYPE_SOCKET_FILTER: BpfProgType = BpfProgType(1);
pub const BPF_PROG_TYPE_KPROBE: BpfProgType = BpfProgType(2);
pub const BPF_PROG_TYPE_SCHED_CLS: BpfProgType = BpfProgType(3);
pub const BPF_PROG_TYPE_SCHED_ACT: BpfProgType = BpfProgType(4);
pub const BPF_PROG_TYPE_TRACEPOINT: BpfProgType = BpfProgType(5);
pub const BPF_PROG_TYPE_XDP: BpfProgType = BpfProgType(6);
pub const BPF_PROG_TYPE_PERF_EVENT: BpfProgType = BpfProgType(7);
pub const BPF_PROG_TYPE_CGROUP_SKB: BpfProgType = BpfProgType(8);
pub const BPF_PROG_TYPE_CGROUP_SOCK: BpfProgType = BpfProgType(9);
pub const BPF_PROG_TYPE_LWT_IN: BpfProgType = BpfProgType(10);
pub const BPF_PROG_TYPE_LWT_OUT: BpfProgType = BpfProgType(11);
pub const BPF_PROG_TYPE_LWT_XMIT: BpfProgType = BpfProgType(12);
pub const BPF_PROG_TYPE_SOCK_OPS: BpfProgType = BpfProgType(13);
pub const BPF_PROG_TYPE_SK_SKB: BpfProgType = BpfProgType(14);
pub const BPF_PROG_TYPE_CGROUP_DEVICE: BpfProgType = BpfProgType(15);
pub const BPF_PROG_TYPE_SK_MSG: BpfProgType = BpfProgType(16);
pub const BPF_PROG_TYPE_RAW_TRACEPOINT: BpfProgType = BpfProgType(17);
pub const BPF_PROG_TYPE_CGROUP_SOCK_ADDR: BpfProgType = BpfProgType(18);
pub const BPF_PROG_TYPE_LWT_SEG6LOCAL: BpfProgType = BpfProgType(19);
pub const BPF_PROG_TYPE_LIRC_MODE2: BpfProgType = BpfProgType(20);
pub const BPF_PROG_TYPE_SK_REUSEPORT: BpfProgType = BpfProgType(21);
pub const BPF_PROG_TYPE_FLOW_DISSECTOR: BpfProgType = BpfProgType(22);
pub const BPF_PROG_TYPE_CGROUP_SYSCTL: BpfProgType = BpfProgType(23);
pub const BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE: BpfProgType = BpfProgType(24);
pub const BPF_PROG_TYPE_CGROUP_SOCKOPT: BpfProgType = BpfProgType(25);
pub const BPF_PROG_TYPE_TRACING: BpfProgType = BpfProgType(26);
pub const BPF_PROG_TYPE_STRUCT_OPS: BpfProgType = BpfProgType(27);
pub const BPF_PROG_TYPE_EXT: BpfProgType = BpfProgType(28);
pub const BPF_PROG_TYPE_LSM: BpfProgType = BpfProgType(29);
pub const BPF_PROG_TYPE_SK_LOOKUP: BpfProgType = BpfProgType(30);
pub const BPF_PROG_TYPE_SYSCALL: BpfProgType = BpfProgType(31); // a program that can execute syscalls
pub const BPF_PROG_TYPE_NETFILTER: BpfProgType = BpfProgType(32);
pub const __MAX_BPF_PROG_TYPE: BpfProgType = BpfProgType(33);

pub const BPF_OBJ_NAME_LEN: usize = 16;

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct BpfAttachType(pub u32);
pub const BPF_CGROUP_INET_INGRESS: BpfAttachType = BpfAttachType(0);
pub const BPF_CGROUP_INET_EGRESS: BpfAttachType = BpfAttachType(1);
pub const BPF_CGROUP_INET_SOCK_CREATE: BpfAttachType = BpfAttachType(2);
pub const BPF_CGROUP_SOCK_OPS: BpfAttachType = BpfAttachType(3);
pub const BPF_SK_SKB_STREAM_PARSER: BpfAttachType = BpfAttachType(4);
pub const BPF_SK_SKB_STREAM_VERDICT: BpfAttachType = BpfAttachType(5);
pub const BPF_CGROUP_DEVICE: BpfAttachType = BpfAttachType(6);
pub const BPF_SK_MSG_VERDICT: BpfAttachType = BpfAttachType(7);
pub const BPF_CGROUP_INET4_BIND: BpfAttachType = BpfAttachType(8);
pub const BPF_CGROUP_INET6_BIND: BpfAttachType = BpfAttachType(9);
pub const BPF_CGROUP_INET4_CONNECT: BpfAttachType = BpfAttachType(10);
pub const BPF_CGROUP_INET6_CONNECT: BpfAttachType = BpfAttachType(11);
pub const BPF_CGROUP_INET4_POST_BIND: BpfAttachType = BpfAttachType(12);
pub const BPF_CGROUP_INET6_POST_BIND: BpfAttachType = BpfAttachType(13);
pub const BPF_CGROUP_UDP4_SENDMSG: BpfAttachType = BpfAttachType(14);
pub const BPF_CGROUP_UDP6_SENDMSG: BpfAttachType = BpfAttachType(15);
pub const BPF_LIRC_MODE2: BpfAttachType = BpfAttachType(16);
pub const BPF_FLOW_DISSECTOR: BpfAttachType = BpfAttachType(17);
pub const BPF_CGROUP_SYSCTL: BpfAttachType = BpfAttachType(18);
pub const BPF_CGROUP_UDP4_RECVMSG: BpfAttachType = BpfAttachType(19);
pub const BPF_CGROUP_UDP6_RECVMSG: BpfAttachType = BpfAttachType(20);
pub const BPF_CGROUP_GETSOCKOPT: BpfAttachType = BpfAttachType(21);
pub const BPF_CGROUP_SETSOCKOPT: BpfAttachType = BpfAttachType(22);
pub const BPF_TRACE_RAW_TP: BpfAttachType = BpfAttachType(23);
pub const BPF_TRACE_FENTRY: BpfAttachType = BpfAttachType(24);
pub const BPF_TRACE_FEXIT: BpfAttachType = BpfAttachType(25);
pub const BPF_MODIFY_RETURN: BpfAttachType = BpfAttachType(26);
pub const BPF_LSM_MAC: BpfAttachType = BpfAttachType(27);
pub const BPF_TRACE_ITER: BpfAttachType = BpfAttachType(28);
pub const BPF_CGROUP_INET4_GETPEERNAME: BpfAttachType = BpfAttachType(29);
pub const BPF_CGROUP_INET6_GETPEERNAME: BpfAttachType = BpfAttachType(30);
pub const BPF_CGROUP_INET4_GETSOCKNAME: BpfAttachType = BpfAttachType(31);
pub const BPF_CGROUP_INET6_GETSOCKNAME: BpfAttachType = BpfAttachType(32);
pub const BPF_XDP_DEVMAP: BpfAttachType = BpfAttachType(33);
pub const BPF_CGROUP_INET_SOCK_RELEASE: BpfAttachType = BpfAttachType(34);
pub const BPF_XDP_CPUMAP: BpfAttachType = BpfAttachType(35);
pub const BPF_SK_LOOKUP: BpfAttachType = BpfAttachType(36);
pub const BPF_XDP: BpfAttachType = BpfAttachType(37);
pub const BPF_SK_SKB_VERDICT: BpfAttachType = BpfAttachType(38);
pub const BPF_SK_REUSEPORT_SELECT: BpfAttachType = BpfAttachType(39);
pub const BPF_SK_REUSEPORT_SELECT_OR_MIGRATE: BpfAttachType = BpfAttachType(40);
pub const BPF_PERF_EVENT: BpfAttachType = BpfAttachType(41);
pub const BPF_TRACE_KPROBE_MULTI: BpfAttachType = BpfAttachType(42);
pub const BPF_LSM_CGROUP: BpfAttachType = BpfAttachType(43);
pub const BPF_STRUCT_OPS: BpfAttachType = BpfAttachType(44);
pub const BPF_NETFILTER: BpfAttachType = BpfAttachType(45);
pub const BPF_TCX_INGRESS: BpfAttachType = BpfAttachType(46);
pub const BPF_TCX_EGRESS: BpfAttachType = BpfAttachType(47);
pub const BPF_TRACE_UPROBE_MULTI: BpfAttachType = BpfAttachType(48);
pub const BPF_CGROUP_UNIX_CONNECT: BpfAttachType = BpfAttachType(49);
pub const BPF_CGROUP_UNIX_SENDMSG: BpfAttachType = BpfAttachType(50);
pub const BPF_CGROUP_UNIX_RECVMSG: BpfAttachType = BpfAttachType(51);
pub const BPF_CGROUP_UNIX_GETPEERNAME: BpfAttachType = BpfAttachType(52);
pub const BPF_CGROUP_UNIX_GETSOCKNAME: BpfAttachType = BpfAttachType(53);
pub const BPF_NETKIT_PRIMARY: BpfAttachType = BpfAttachType(54);
pub const BPF_NETKIT_PEER: BpfAttachType = BpfAttachType(55);
pub const BPF_TRACE_KPROBE_SESSION: BpfAttachType = BpfAttachType(56);
pub const BPF_TRACE_UPROBE_SESSION: BpfAttachType = BpfAttachType(57);
pub const __MAX_BPF_ATTACH_TYPE: BpfAttachType = BpfAttachType(58);

#[repr(C)]
#[derive(Copy, Clone)]
pub union bpf_attr {
    pub link_create: BpfAttrLinkCreate,
    pub map_create: BpfAttrMapCreate,
    pub elem: BpfAttrElem,
    pub batch: BpfAttrBatch,
    pub prog_load: BpfAttrProgLoad,
    pub obj: BpfAttrObj,
}

#[repr(C)]
#[derive(Copy,Clone)]
pub struct BpfAttrLinkCreate {
    pub prog_fd: u32,
    pub attach_type: BpfAttachType,
    pub target_fd: u32,
    pub flags: u32,
    pub __reserved: u64,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct BpfAttrMapCreate {
    pub map_type:   c_uint,
    pub key_size:   c_uint,
    pub value_size: c_uint,
    pub max_entries:c_uint,
    pub map_flags:  c_uint,
    pub inner_map_fd: c_uint,
    pub numa_node:  c_uint,
    pub map_name:   [c_char; BPF_OBJ_NAME_LEN],
    pub map_ifindex:c_uint,
    pub btf_fd:     c_uint,
    pub btf_key_type_id:         c_uint,
    pub btf_value_type_id:       c_uint,
    pub btf_vmlinux_value_type_id: c_uint,
    pub map_extra:   c_ulonglong,
    pub value_type_btf_obj_fd: c_int,
    pub map_token_fd:         c_int,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct BpfAttrElem {
    pub map_fd:  c_uint,
    pub key:     c_ulonglong, // __aligned_u64
    pub _inner:  bpf_attr_elem_inner,
    pub flags:  c_ulonglong,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union bpf_attr_elem_inner {
    pub value:     c_ulonglong,
    pub next_key:  c_ulonglong,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct BpfAttrBatch {
    pub in_batch:  c_ulonglong,
    pub out_batch: c_ulonglong,
    pub keys:      c_ulonglong,
    pub values:    c_ulonglong,
    pub count:     c_uint,
    pub map_fd:    c_uint,
    pub elem_flags:c_ulonglong,
    pub flags:     c_ulonglong,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct BpfAttrProgLoad {
    pub prog_type: BpfProgType,
    pub insn_cnt:  c_uint,
    pub insns:     c_ulonglong,
    pub license:   c_ulonglong,
    pub log_level: c_uint,
    pub log_size:  c_uint,
    pub log_buf:   c_ulonglong,
    pub kern_version: c_uint,
    pub prog_flags:  c_uint,
    pub prog_name:   [c_char; BPF_OBJ_NAME_LEN],
    pub prog_ifindex:c_uint,
    pub expected_attach_type: c_uint,
    pub prog_btf_fd:          c_uint,
    pub func_info_rec_size:   c_uint,
    pub func_info:            c_ulonglong,
    pub func_info_cnt:        c_uint,
    pub line_info_rec_size:   c_uint,
    pub line_info:            c_ulonglong,
    pub line_info_cnt:        c_uint,
    pub attach_btf_id:        c_uint,
    pub _attach:               bpf_attr_prog_load_attach,
    pub core_relo_cnt:        c_uint,
    pub fd_array:             c_ulonglong,
    pub core_relos:           c_ulonglong,
    pub core_relo_rec_size:   c_uint,
    pub log_true_size:        c_uint,
    pub prog_token_fd:        c_int,
    pub fd_array_cnt:         c_uint,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union bpf_attr_prog_load_attach {
    pub attach_prog_fd: c_uint,
    pub attach_btf_obj_fd: c_uint,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct BpfAttrObj {
    pub pathname: c_ulonglong,
    pub bpf_fd:   c_uint,
    pub file_flags: c_uint,
    pub path_fd:    c_int,
}
#[repr(C, packed)]
pub struct BpfInsn {
    pub code: u8, // opcode
    //pub dst_reg: u4, // dest register (4 bits)
    //pub src_reg: u4, // source register (4 bits)
    pub regs: u8, // registers (Rust does not support setting bitfields to separte the dst and src registers)
    pub off: i16, // signed offset
    pub imm: i32, // signed immediate constant
}
#[repr(C)]
pub struct BpfSetLinkXdpFd {
    pub ifindex: u32,
    pub fd: u32,
    pub flags: u32,
    pub expected_fd: u32, // set to 0 unless replacing
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BpfMapDef {
    pub type_: u32,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
    pub map_flags: u32,
}

pub unsafe fn bpf(cmd: BpfCmd, attr: *const bpf_attr, size: u32) -> i32 {
    //syscall(SYS_BPF as usize, cmd, attr, size) as i32
    -1
}
pub unsafe fn bpf_set_link_xdp_fd(ifindex: u32, fd: i32, flags: u32) -> i32 {
    bpf(
        BPF_PROG_ATTACH,
        &bpf_attr {
            link_create: BpfAttrLinkCreate {
                prog_fd: fd as u32,
                attach_type: BPF_XDP,
                target_fd: ifindex,
                flags,
                __reserved: 0,
            },
        },
        std::mem::size_of::<BpfAttrLinkCreate>() as u32,
    )
}