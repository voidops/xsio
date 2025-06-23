use std::fs::File;
use std::io::Read;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Elf64Header {
    pub e_ident: [u8; 16],
    pub e_type:    u16,
    pub e_machine: u16,
    pub e_version: u32,
    pub e_entry:   u64,
    pub e_phoff:   u64,
    pub e_shoff:   u64,
    pub e_flags:   u32,
    pub e_ehsize:  u16,
    pub e_phentsize: u16,
    pub e_phnum:     u16,
    pub e_shentsize: u16,
    pub e_shnum:     u16,
    pub e_shstrndx:  u16,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Elf64SectionHeader {
    pub sh_name:      u32,
    pub sh_type:      u32,
    pub sh_flags:     u64,
    pub sh_addr:      u64,
    pub sh_offset:    u64,
    pub sh_size:      u64,
    pub sh_link:      u32,
    pub sh_info:      u32,
    pub sh_addralign: u64,
    pub sh_entsize:   u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Elf64Rel {
    pub r_offset: u64,
    pub r_info: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Elf64Rela {
    pub r_offset: u64,
    pub r_info: u64,
    pub r_addend: i64,
}


#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Elf64Sym {
    pub st_name:  u32,
    pub st_info:  u8,
    pub st_other: u8,
    pub st_shndx: u16,
    pub st_value: u64,
    pub st_size:  u64,
}

pub struct Elf<'a> {
    pub data: &'a [u8],
    pub header: Elf64Header,
    pub section_headers: Vec<Elf64SectionHeader>,
}


impl<'a> Elf<'a> {
    pub fn load_from_file(path: &str) -> std::io::Result<Self> {
        let mut f = File::open(path)?;
        let mut buf = Vec::new();
        f.read_to_end(&mut buf)?;
        let data = buf.leak(); // leaks for 'static lifetime; ok for short-lived tool
        Elf::load_from_bytes(data)
    }

    pub fn load_from_bytes(data: &'a [u8]) -> std::io::Result<Self> {
        if data.len() < std::mem::size_of::<Elf64Header>() {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "file too small"));
        }

        let header: Elf64Header = unsafe { std::ptr::read_unaligned(data.as_ptr() as *const Elf64Header) };

        if &header.e_ident[0..4] != b"\x7FELF" {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "not an ELF file"));
        }
        if header.e_ident[4] != 2 {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "not 64-bit ELF"));
        }

        let shoff = header.e_shoff as usize;
        let shent = header.e_shentsize as usize;
        let shnum = header.e_shnum as usize;

        let end = shoff.checked_add(shent * shnum).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "overflow in section header math")
        })?;
        if end > data.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "section header table out of bounds",
            ));
        }

        let mut section_headers = Vec::with_capacity(shnum);
        for i in 0..shnum {
            let off = shoff + i * shent;
            let sh: Elf64SectionHeader =
                unsafe { std::ptr::read_unaligned(data[off..].as_ptr() as *const Elf64SectionHeader) };
            section_headers.push(sh);
        }

        Ok(Elf { data, header, section_headers })
    }

    pub fn get_strtab_header(&self) -> Option<&Elf64SectionHeader> {
        let strtab_index = self.header.e_shstrndx as usize;
        if strtab_index < self.section_headers.len() {
            return Some(&self.section_headers[strtab_index]);
        }
        None
    }

    pub fn get_strtab_data(&self) -> Option<&[u8]> {
        let strtab = &self.get_strtab_header()?;
        let start = strtab.sh_offset as usize;
        let end = start + strtab.sh_size as usize;
        if end <= self.data.len() {
            return Some(&self.data[start..end]);
        }
        None
    }

    pub fn get_section_header_by_name(&self, name: &str) -> Option<&Elf64SectionHeader> {
        let strtab = self.get_strtab_header()?;
        let strtab_data = &self.data[strtab.sh_offset as usize..strtab.sh_offset as usize + strtab.sh_size as usize];
        let name_b = name.as_bytes();
        for section in self.section_headers.iter() {
            let name_offset = section.sh_name as usize;
            if name_offset < strtab_data.len() {
                let section_name = &strtab_data[name_offset..];
                if let Some(end) = section_name.iter().position(|&c| c == 0) {
                    if &section_name[..end] == name_b {
                        return Some(section);
                    }
                }
            }
        }
        None
    }

    pub fn get_section_data_by_name(&self, name: &str) -> Option<&[u8]> {
        if let Some(section) = self.get_section_header_by_name(name) {
            let start = section.sh_offset as usize;
            let end = start + section.sh_size as usize;
            if end <= self.data.len() {
                return Some(&self.data[start..end]);
            }
        }
        None
    }
}