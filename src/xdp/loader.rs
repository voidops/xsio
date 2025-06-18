use std::{collections::HashMap, ffi::CString, io::{Error, ErrorKind, Result}, mem::zeroed, os::fd::RawFd};

use crate::{bpf, bpf_attr, BpfInsn, BpfMapDef, Elf, Elf64Rel, Elf64Sym, BPF_MAP_CREATE, BPF_PROG_LOAD, BPF_PROG_TYPE_XDP};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XdpFd(pub i32);

impl XdpFd {
    pub fn new(fd: i32) -> Self {
        XdpFd(fd)
    }

    pub fn as_raw_fd(&self) -> i32 {
        self.0
    }
}

impl std::fmt::Display for XdpFd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "XdpFd({})", self.0)
    }
}

pub fn load_xdp(elf_data: &[u8], maps_section_name: &str) -> Result<XdpFd> {
    let elf = Elf::load_from_bytes(elf_data).expect("Failed to load XDP ELF object");
    let strtab = elf.get_strtab_header()
        .ok_or_else(|| Error::new(ErrorKind::NotFound, "String table section not found in ELF."))?;
    let strtab_data = &elf.data[strtab.sh_offset as usize .. strtab.sh_offset as usize + strtab.sh_size as usize];

    let xdp_section = elf.section_headers.iter()
        .find(|header| {
            header.sh_type == 1 && {
                let name_offset = header.sh_name as usize;
                name_offset < strtab_data.len() && {
                    let section_name = &strtab_data[name_offset..];
                    if let Some(end) = section_name.iter().position(|&c| c == 0) {
                        section_name[..end].starts_with(b"xdp")
                    } else { false }
                }
            }
        }).ok_or_else(|| Error::new(ErrorKind::NotFound, "XDP section not found in ELF."))?;

    let xdp_data = &elf.data[xdp_section.sh_offset as usize .. xdp_section.sh_offset as usize + xdp_section.sh_size as usize];

    let maps_section = elf.section_headers.iter().find(|header| {
        header.sh_type == 1 && {
            let name_offset = header.sh_name as usize;
            name_offset < strtab_data.len() && {
                let section_name = &strtab_data[name_offset..];
                if let Some(end) = section_name.iter().position(|&c| c == 0) {
                    &section_name[..end] == maps_section_name.as_bytes()
                } else { false }
            }
        }
    }).ok_or_else(|| Error::new(ErrorKind::NotFound, "No maps section found in ELF."))?;

    let maps_data = &elf.data[maps_section.sh_offset as usize .. maps_section.sh_offset as usize + maps_section.sh_size as usize];
    let map_cnt = maps_data.len() / std::mem::size_of::<BpfMapDef>();

    // Build offset->fd map for correct relocation
    let mut offset_to_fd = HashMap::new();
    for i in 0..map_cnt {
        let offset = i * std::mem::size_of::<BpfMapDef>();
        let def: BpfMapDef = unsafe {
            std::ptr::read_unaligned(
                maps_data[offset..].as_ptr() as *const BpfMapDef
            )
        };
        let fd = unsafe { create_map_fd(&def)? };
        offset_to_fd.insert(offset, fd);
    }

    let relocation_section = elf.section_headers.iter().find(|header| {
        header.sh_type == 9 && {
            let name_offset = header.sh_name as usize;
            name_offset < strtab_data.len() && {
                let section_name = &strtab_data[name_offset..];
                if let Some(end) = section_name.iter().position(|&c| c == 0) {
                    let name = &section_name[..end];
                    name.starts_with(b".relxdp")
                } else { false }
            }
        }
    }).ok_or_else(|| Error::new(ErrorKind::NotFound, "No relocation entries found in ELF."))?;

    let rel_data = &elf.data[relocation_section.sh_offset as usize .. relocation_section.sh_offset as usize + relocation_section.sh_size as usize];
    let rel_cnt = rel_data.len() / std::mem::size_of::<Elf64Rel>();

    let symtab_section = elf.section_headers.iter().find(|header| {
        header.sh_type == 2
    }).ok_or_else(|| Error::new(ErrorKind::NotFound, ".symtab not found in ELF."))?;
    let symtab_data = &elf.data[symtab_section.sh_offset as usize .. symtab_section.sh_offset as usize + symtab_section.sh_size as usize];
    let symtab_cnt = symtab_data.len() / std::mem::size_of::<Elf64Sym>();

    let mut code = xdp_data.to_vec();
    for i in 0..rel_cnt {
        let rel: Elf64Rel = unsafe { std::ptr::read_unaligned(&rel_data[i * std::mem::size_of::<Elf64Rel>()..] as *const _ as *const Elf64Rel) };
        let sym_idx = (rel.r_info >> 32) as usize;
        if sym_idx >= symtab_cnt { continue; }
        let sym: Elf64Sym = unsafe { std::ptr::read_unaligned(&symtab_data[sym_idx * std::mem::size_of::<Elf64Sym>()..] as *const _ as *const Elf64Sym) };
        let map_offset = sym.st_value as usize;
        let fd = match offset_to_fd.get(&map_offset) {
            Some(fd) => *fd,
            None => continue,
        };
        let insn_off = rel.r_offset as usize / std::mem::size_of::<BpfInsn>();
        let code_ptr = code.as_mut_ptr() as *mut BpfInsn;
        unsafe {
            let insn = code_ptr.add(insn_off);
            (*insn).imm = fd;
            (*insn.add(1)).imm = 0;
        }
    }

    let mut log_buf = vec![0u8; 65536];
    let license = CString::new("GPL").unwrap();
    let prog_fd = unsafe {
        bpf_prog_load(
            code.as_ptr() as *const BpfInsn,
            (code.len() / std::mem::size_of::<BpfInsn>()) as u32,
            license.as_ptr(),
            log_buf.as_mut_ptr(),
            log_buf.len()
        )
    };
    if prog_fd < 0 {
        let msg = String::from_utf8_lossy(&log_buf);
        return Err(Error::new(ErrorKind::Other, format!("BPF verifier: {msg}")));
    }
    Ok(XdpFd(prog_fd))
}


unsafe fn create_map_fd(def: &BpfMapDef) -> Result<RawFd> {
    let mut attr: bpf_attr = zeroed();
    {
        let map_create = &mut attr.map_create;
        map_create.map_type    = def.type_;
        map_create.key_size    = def.key_size;
        map_create.value_size  = def.value_size;
        map_create.max_entries = def.max_entries;
        map_create.map_flags   = def.map_flags;
    }
    let fd = bpf(BPF_MAP_CREATE, &attr, std::mem::size_of::<bpf_attr>() as u32);
    if fd < 0 {
        return Err(Error::last_os_error());
    }
    Ok(fd)
}

unsafe fn bpf_prog_load(
    insns: *const BpfInsn,
    insn_cnt: u32,
    license: *const i8,
    log_buf: *mut u8,
    log_size: usize,
) -> i32 {
    let mut attr: bpf_attr = std::mem::zeroed();
    {
        let prog_load = &mut attr.prog_load;
        prog_load.prog_type = BPF_PROG_TYPE_XDP;
        prog_load.insn_cnt = insn_cnt;
        prog_load.insns = insns as u64;
        prog_load.license = license as u64;
        prog_load.log_level = 1;
        prog_load.log_size = log_size as u32;
        prog_load.log_buf = log_buf as u64;
        // optionally: prog_load.kern_version, etc.
    }
    bpf(BPF_PROG_LOAD, &attr, std::mem::size_of::<bpf_attr>() as u32)
}