//! ELF / cubin reader and writer for SM120.
//!
//! Strategy: read original cubin, patch .text sections in place, write back.

use anyhow::{bail, Context, Result};
use object::read::elf::{ElfFile, FileHeader, SectionHeader as _};
use object::{elf, Endianness};

#[derive(Debug, Clone, Copy)]
pub struct SmVersion {
    pub sm: u32,
    pub compute: u32,
}

#[derive(Debug)]
pub struct CubinFile {
    pub bytes: Vec<u8>,
    pub sm: SmVersion,
    pub text_sections: Vec<(String, u64, u64)>,
}

impl CubinFile {
    pub fn load(path: &std::path::Path) -> Result<Self> {
        let bytes = std::fs::read(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        Self::from_bytes(bytes)
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        let elf: ElfFile<'_, elf::FileHeader64<Endianness>> =
            ElfFile::parse(bytes.as_slice()).context("failed to parse ELF")?;
        let endian = elf.endian();
        let header = elf.elf_header();
        let flags = header.e_flags.get(endian);
        let sm = parse_sm_version(flags);

        let mut text_sections = Vec::new();
        let sections = header.sections(endian, bytes.as_slice())?;
        for section in sections.iter() {
            let name = match sections.section_name(endian, section) {
                Ok(n) => n,
                Err(_) => continue,
            };
            let name_str = std::str::from_utf8(name).unwrap_or("");
            if (name_str.starts_with(".text.") || name_str == ".text")
                && section.sh_type(endian) == elf::SHT_PROGBITS
                && section.sh_size(endian) > 0
            {
                text_sections.push((
                    name_str.to_string(),
                    section.sh_offset(endian),
                    section.sh_size(endian),
                ));
            }
        }

        Ok(CubinFile { bytes, sm, text_sections })
    }

    pub fn text_bytes(&self, section_idx: usize) -> Result<&[u8]> {
        let (name, offset, size) = self.text_sections.get(section_idx)
            .context("text section index out of range")?;
        let start = *offset as usize;
        let end = start + *size as usize;
        if end > self.bytes.len() {
            bail!("text section {name} extends past end of file");
        }
        Ok(&self.bytes[start..end])
    }

    pub fn patch_text(&mut self, section_idx: usize, new_code: &[u8]) -> Result<()> {
        let (_name, offset, size) = self.text_sections.get(section_idx)
            .context("text section index out of range")?;
        let old_size = *size as usize;
        let start = *offset as usize;

        if new_code.len() == old_size {
            self.bytes[start..start + old_size].copy_from_slice(new_code);
        } else {
            // Splice: remove old text, insert new text
            let delta = new_code.len() as i64 - old_size as i64;
            let end = start + old_size;
            let mut result = Vec::with_capacity((self.bytes.len() as i64 + delta) as usize);
            result.extend_from_slice(&self.bytes[..start]);
            result.extend_from_slice(new_code);
            result.extend_from_slice(&self.bytes[end..]);
            self.bytes = result;

            // Fix all ELF offsets affected by the splice
            self.fix_elf_offsets(start, old_size, new_code.len())?;

            // Update cached offsets for text sections shifted by the splice
            for i in 0..self.text_sections.len() {
                if i != section_idx && (self.text_sections[i].1 as usize) > start {
                    self.text_sections[i].1 = (self.text_sections[i].1 as i64 + delta) as u64;
                }
            }
        }
        self.text_sections[section_idx].2 = new_code.len() as u64;
        Ok(())
    }

    /// After splicing text at `splice_point` from `old_size` to `new_size`,
    /// fix all ELF offsets: section headers, e_shoff, symbol sizes.
    fn fix_elf_offsets(&mut self, splice_point: usize, old_size: usize, new_size: usize) -> Result<()> {
        let delta = new_size as i64 - old_size as i64;
        if delta == 0 { return Ok(()); }

        // e_shoff (section header table offset)
        let e_shoff = u64::from_le_bytes(self.bytes[0x28..0x30].try_into().unwrap());
        if e_shoff as usize > splice_point {
            let new_shoff = (e_shoff as i64 + delta) as u64;
            self.bytes[0x28..0x30].copy_from_slice(&new_shoff.to_le_bytes());
        }
        let e_shoff = u64::from_le_bytes(self.bytes[0x28..0x30].try_into().unwrap()) as usize;
        let e_shnum = u16::from_le_bytes(self.bytes[0x3C..0x3E].try_into().unwrap()) as usize;

        // Fix program headers (e_phoff at ELF offset 0x20, phdrs are 56 bytes each)
        let e_phoff = u64::from_le_bytes(self.bytes[0x20..0x28].try_into().unwrap());
        if (e_phoff as usize) > splice_point {
            let new_phoff = (e_phoff as i64 + delta) as u64;
            self.bytes[0x20..0x28].copy_from_slice(&new_phoff.to_le_bytes());
        }
        let e_phoff = u64::from_le_bytes(self.bytes[0x20..0x28].try_into().unwrap()) as usize;
        let e_phnum = u16::from_le_bytes(self.bytes[0x38..0x3A].try_into().unwrap()) as usize;
        for p in 0..e_phnum {
            let ph = e_phoff + p * 56;
            if ph + 56 > self.bytes.len() { break; }
            let p_offset = u64::from_le_bytes(self.bytes[ph+8..ph+16].try_into().unwrap()) as usize;
            let p_filesz = u64::from_le_bytes(self.bytes[ph+0x20..ph+0x28].try_into().unwrap()) as usize;

            if p_offset <= splice_point && splice_point < p_offset.saturating_add(p_filesz) {
                let new_filesz = (p_filesz as i64 + delta) as u64;
                let p_memsz = u64::from_le_bytes(self.bytes[ph+0x28..ph+0x30].try_into().unwrap());
                let new_memsz = (p_memsz as i64 + delta) as u64;
                self.bytes[ph+0x20..ph+0x28].copy_from_slice(&new_filesz.to_le_bytes());
                self.bytes[ph+0x28..ph+0x30].copy_from_slice(&new_memsz.to_le_bytes());
            } else if p_offset > splice_point {
                let new_off = (p_offset as i64 + delta) as u64;
                self.bytes[ph+8..ph+16].copy_from_slice(&new_off.to_le_bytes());
            }
        }

        // Track which section index is the text section we spliced
        let mut text_sec_elf_idx = None;
        for s in 0..e_shnum {
            let sh = e_shoff + s * 64;
            if sh + 64 > self.bytes.len() { break; }
            let sh_offset = u64::from_le_bytes(self.bytes[sh+0x18..sh+0x20].try_into().unwrap()) as usize;
            let sh_size = u64::from_le_bytes(self.bytes[sh+0x20..sh+0x28].try_into().unwrap()) as usize;

            if sh_offset == splice_point && sh_size == old_size {
                // This is the spliced text section — update size
                self.bytes[sh+0x20..sh+0x28].copy_from_slice(&(new_size as u64).to_le_bytes());
                text_sec_elf_idx = Some(s);
            } else if sh_offset > splice_point {
                // Section after splice point — shift offset
                let new_off = (sh_offset as i64 + delta) as u64;
                self.bytes[sh+0x18..sh+0x20].copy_from_slice(&new_off.to_le_bytes());
            }
        }

        // Fix symbol table: update st_size for FUNC symbols in the text section
        if let Some(text_idx) = text_sec_elf_idx {
            // Find .symtab section (usually section 3)
            for s in 0..e_shnum {
                let sh = e_shoff + s * 64;
                if sh + 64 > self.bytes.len() { break; }
                let sh_type = u32::from_le_bytes(self.bytes[sh+4..sh+8].try_into().unwrap());
                if sh_type != 2 { continue; } // SHT_SYMTAB = 2
                let sym_off = u64::from_le_bytes(self.bytes[sh+0x18..sh+0x20].try_into().unwrap()) as usize;
                let sym_total = u64::from_le_bytes(self.bytes[sh+0x20..sh+0x28].try_into().unwrap()) as usize;
                for i in 0..(sym_total / 24) {
                    let so = sym_off + i * 24;
                    if so + 24 > self.bytes.len() { break; }
                    let st_shndx = u16::from_le_bytes(self.bytes[so+6..so+8].try_into().unwrap()) as usize;
                    let st_info = self.bytes[so + 4];
                    if st_shndx == text_idx && (st_info >> 4) >= 1 {
                        // Update symbol size (st_size at offset 16 in Elf64_Sym)
                        self.bytes[so+16..so+24].copy_from_slice(&(new_size as u64).to_le_bytes());
                    }
                }
                break;
            }
        }

        // Fix .debug_frame FDE addr_range: DWARF64 format
        // CIE: 0xFFFFFFFF(4) + length(8) + CIE_id=0xFF..FF(8) + ...
        // FDE: 0xFFFFFFFF(4) + length(8) + CIE_ptr(8) + init_loc(8) + addr_range(8)
        for s in 0..e_shnum {
            let sh = e_shoff + s * 64;
            if sh + 64 > self.bytes.len() { break; }
            // Find .debug_frame by name or by scanning for DWARF content
            let sh_offset = u64::from_le_bytes(self.bytes[sh+0x18..sh+0x20].try_into().unwrap()) as usize;
            let sh_size = u64::from_le_bytes(self.bytes[sh+0x20..sh+0x28].try_into().unwrap()) as usize;
            if sh_size < 48 || sh_offset + sh_size > self.bytes.len() { continue; }
            // Check for DWARF64 marker
            if u32::from_le_bytes(self.bytes[sh_offset..sh_offset+4].try_into().unwrap()) != 0xFFFFFFFF { continue; }
            // Scan for FDE entries and patch addr_range
            let mut pos = sh_offset;
            let end = sh_offset + sh_size;
            while pos + 36 <= end {
                let marker = u32::from_le_bytes(self.bytes[pos..pos+4].try_into().unwrap());
                if marker != 0xFFFFFFFF { break; }
                let length = u64::from_le_bytes(self.bytes[pos+4..pos+12].try_into().unwrap()) as usize;
                let cie_id = u64::from_le_bytes(self.bytes[pos+12..pos+20].try_into().unwrap());
                if cie_id != 0xFFFFFFFFFFFFFFFF && pos + 36 <= end {
                    // FDE: patch addr_range at pos+28 if it matches old_size
                    let addr_range = u64::from_le_bytes(self.bytes[pos+28..pos+36].try_into().unwrap()) as usize;
                    if addr_range == old_size {
                        self.bytes[pos+28..pos+36].copy_from_slice(&(new_size as u64).to_le_bytes());
                    }
                }
                pos += 12 + length;
            }
            break; // only one .debug_frame section
        }
        Ok(())
    }

    pub fn write(&self, path: &std::path::Path) -> Result<()> {
        std::fs::write(path, &self.bytes)
            .with_context(|| format!("failed to write {}", path.display()))
    }

    pub fn split_code128(code: u128) -> (u64, u64) {
        (code as u64, (code >> 64) as u64)
    }

    pub fn merge_code128(lo: u64, hi: u64) -> u128 {
        ((hi as u128) << 64) | (lo as u128)
    }

    /// Find a section by name, returning its index.
    pub fn find_section(&self, name: &str) -> Option<usize> {
        let shstrtab_idx = u16::from_le_bytes([self.bytes[0x3E], self.bytes[0x3F]]) as usize;
        let e_shoff = u64::from_le_bytes(self.bytes[0x28..0x30].try_into().ok()?) as usize;
        let e_shentsize = u16::from_le_bytes([self.bytes[0x3A], self.bytes[0x3B]]) as usize;
        let e_shnum = u16::from_le_bytes([self.bytes[0x3C], self.bytes[0x3D]]) as usize;
        let shstr_off_pos = e_shoff + shstrtab_idx * e_shentsize + 0x18;
        let shstr_off = u64::from_le_bytes(self.bytes[shstr_off_pos..shstr_off_pos+8].try_into().ok()?) as usize;
        let shstr_sz_pos = e_shoff + shstrtab_idx * e_shentsize + 0x20;
        let shstr_sz = u64::from_le_bytes(self.bytes[shstr_sz_pos..shstr_sz_pos+8].try_into().ok()?) as usize;
        for i in 0..e_shnum {
            let sh_name_off_pos = e_shoff + i * e_shentsize;
            let sh_name_off = u32::from_le_bytes(self.bytes[sh_name_off_pos..sh_name_off_pos+4].try_into().ok()?) as usize;
            if sh_name_off >= shstr_sz { continue; }
            let end = self.bytes[shstr_off + sh_name_off..shstr_off + shstr_sz]
                .iter().position(|&b| b == 0).unwrap_or(shstr_sz - sh_name_off);
            let sec_name = std::str::from_utf8(&self.bytes[shstr_off + sh_name_off..shstr_off + sh_name_off + end]).ok()?;
            if sec_name == name { return Some(i); }
        }
        None
    }

    /// Patch a section data in-place.
    pub fn patch_section(&mut self, sec_idx: usize, data: &[u8]) -> anyhow::Result<()> {
        let e_shoff = u64::from_le_bytes(self.bytes[0x28..0x30].try_into().unwrap()) as usize;
        let e_shentsize = u16::from_le_bytes([self.bytes[0x3A], self.bytes[0x3B]]) as usize;
        let sh_offset_pos = e_shoff + sec_idx * e_shentsize + 0x18;
        let sh_size_pos = e_shoff + sec_idx * e_shentsize + 0x20;
        let sec_offset = u64::from_le_bytes(self.bytes[sh_offset_pos..sh_offset_pos+8].try_into().unwrap()) as usize;
        let sec_size = u64::from_le_bytes(self.bytes[sh_size_pos..sh_size_pos+8].try_into().unwrap()) as usize;
        if data.len() > sec_size {
            anyhow::bail!("mercury stub ({} bytes) > section ({} bytes)", data.len(), sec_size);
        }
        self.bytes[sec_offset..sec_offset + data.len()].copy_from_slice(data);
        for b in &mut self.bytes[sec_offset + data.len()..sec_offset + sec_size] { *b = 0; }
        Ok(())
    }
}

fn parse_sm_version(flags: u32) -> SmVersion {
    let sm_field = flags & 0xFF;
    if sm_field < 10 {
        SmVersion { sm: (flags >> 8) & 0xFFF, compute: (flags >> 20) & 0xFFF }
    } else {
        SmVersion { sm: sm_field, compute: (flags >> 16) & 0xFF }
    }
}
