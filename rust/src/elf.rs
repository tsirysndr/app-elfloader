// SPDX-License-Identifier: BSD-3-Clause
//! A bounds-checked ELF64 reader.
//!
//! This replaces libelf/gelf. The motivation is not tidiness: the C loader
//! reached into `Elf`'s private `e_rawfile` to read `PT_INTERP`, which is only
//! populated for `elf_memory()` images and is a dangling read for the
//! `elf_open(fd)` path it was used from. Owning the parse also means every
//! field that later becomes an address or a length gets range-checked in one
//! place, against the actual file size.
//!
//! Only the pieces a program loader needs are parsed: the executable header
//! and the program headers. Sections are irrelevant to loading.

use crate::err::{Error, Result};
use alloc::vec::Vec;

pub const EI_NIDENT: usize = 16;
pub const EHDR_SIZE: usize = 64;
pub const PHDR_SIZE: usize = 56;

pub const ELFMAG: [u8; 4] = [0x7f, b'E', b'L', b'F'];

pub const EI_CLASS: usize = 4;
pub const EI_DATA: usize = 5;
pub const EI_VERSION: usize = 6;
pub const EI_OSABI: usize = 7;
pub const EI_ABIVERSION: usize = 8;

pub const ELFCLASS64: u8 = 2;
pub const ELFDATA2LSB: u8 = 1;
pub const EV_CURRENT: u8 = 1;

pub const ELFOSABI_NONE: u8 = 0;
pub const ELFOSABI_GNU: u8 = 3; // a.k.a. ELFOSABI_LINUX
pub const ELFOSABI_ARM_AEABI: u8 = 64;

pub const ET_EXEC: u16 = 2;
pub const ET_DYN: u16 = 3;

pub const EM_X86_64: u16 = 62;
pub const EM_AARCH64: u16 = 183;

pub const PN_XNUM: u16 = 0xffff;

pub const PT_NULL: u32 = 0;
pub const PT_LOAD: u32 = 1;
pub const PT_DYNAMIC: u32 = 2;
pub const PT_INTERP: u32 = 3;
pub const PT_NOTE: u32 = 4;
pub const PT_PHDR: u32 = 6;
pub const PT_TLS: u32 = 7;
pub const PT_GNU_EH_FRAME: u32 = 0x6474_e550;
pub const PT_GNU_STACK: u32 = 0x6474_e551;
pub const PT_GNU_RELRO: u32 = 0x6474_e552;
pub const PT_GNU_PROPERTY: u32 = 0x6474_e553;

pub const PF_X: u32 = 1;
pub const PF_W: u32 = 2;
pub const PF_R: u32 = 4;

/// The machine this loader can start.
pub const EM_NATIVE: u16 = if cfg!(target_arch = "aarch64") {
    EM_AARCH64
} else {
    EM_X86_64
};

/// Longest `PT_INTERP` path accepted. Linux caps this at PATH_MAX; we are
/// stricter because an oversized value is far more likely to be a corrupt
/// header than a real path.
pub const INTERP_MAX: u64 = 4096;

/// Largest `e_phnum` accepted. Real toolchains emit tens; thousands means the
/// header is junk and we would otherwise allocate on its say-so.
pub const PHNUM_MAX: u16 = 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ehdr {
    pub ident: [u8; EI_NIDENT],
    pub e_type: u16,
    pub e_machine: u16,
    pub e_version: u32,
    pub e_entry: u64,
    pub e_phoff: u64,
    pub e_shoff: u64,
    pub e_flags: u32,
    pub e_ehsize: u16,
    pub e_phentsize: u16,
    pub e_phnum: u16,
    pub e_shentsize: u16,
    pub e_shnum: u16,
    pub e_shstrndx: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Phdr {
    pub p_type: u32,
    pub p_flags: u32,
    pub p_offset: u64,
    pub p_vaddr: u64,
    pub p_paddr: u64,
    pub p_filesz: u64,
    pub p_memsz: u64,
    pub p_align: u64,
}

impl Phdr {
    pub fn is_read(&self) -> bool {
        self.p_flags & PF_R != 0
    }
    pub fn is_write(&self) -> bool {
        self.p_flags & PF_W != 0
    }
    pub fn is_exec(&self) -> bool {
        self.p_flags & PF_X != 0
    }

    /// `RWX` string for log lines.
    pub fn flag_str(&self) -> [u8; 3] {
        [
            if self.is_read() { b'r' } else { b'-' },
            if self.is_write() { b'w' } else { b'-' },
            if self.is_exec() { b'x' } else { b'-' },
        ]
    }
}

fn u16le(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}

fn u32le(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

fn u64le(b: &[u8], off: usize) -> u64 {
    let mut v = [0u8; 8];
    v.copy_from_slice(&b[off..off + 8]);
    u64::from_le_bytes(v)
}

/// Random-access byte source for an ELF image: a file descriptor, or a region
/// of memory (the initrd case). Kept as a trait so the parser can be exercised
/// on the host against a plain `Vec<u8>`.
pub trait ImageSource {
    /// Fill `buf` entirely from `off`. Short reads are an error: for a program
    /// header table or a segment, a short read means a truncated image.
    fn read_exact_at(&self, off: u64, buf: &mut [u8]) -> Result<()>;

    /// Total size, when known. `None` means the loader cannot pre-validate
    /// offsets against the end of the image and will rely on read failures.
    fn size(&self) -> Option<u64>;
}

impl ImageSource for &[u8] {
    fn read_exact_at(&self, off: u64, buf: &mut [u8]) -> Result<()> {
        let off: usize = off.try_into().map_err(|_| Error::ENOEXEC)?;
        let end = off.checked_add(buf.len()).ok_or(Error::ENOEXEC)?;
        if end > self.len() {
            return Err(Error::ENOEXEC);
        }
        buf.copy_from_slice(&self[off..end]);
        Ok(())
    }

    fn size(&self) -> Option<u64> {
        Some(self.len() as u64)
    }
}

impl Ehdr {
    pub fn parse(raw: &[u8]) -> Result<Ehdr> {
        if raw.len() < EHDR_SIZE {
            return Err(Error::ENOEXEC);
        }
        let mut ident = [0u8; EI_NIDENT];
        ident.copy_from_slice(&raw[..EI_NIDENT]);
        Ok(Ehdr {
            ident,
            e_type: u16le(raw, 16),
            e_machine: u16le(raw, 18),
            e_version: u32le(raw, 20),
            e_entry: u64le(raw, 24),
            e_phoff: u64le(raw, 32),
            e_shoff: u64le(raw, 40),
            e_flags: u32le(raw, 48),
            e_ehsize: u16le(raw, 52),
            e_phentsize: u16le(raw, 54),
            e_phnum: u16le(raw, 56),
            e_shentsize: u16le(raw, 58),
            e_shnum: u16le(raw, 60),
            e_shstrndx: u16le(raw, 62),
        })
    }
}

impl Phdr {
    pub fn parse(raw: &[u8]) -> Result<Phdr> {
        if raw.len() < PHDR_SIZE {
            return Err(Error::ENOEXEC);
        }
        Ok(Phdr {
            p_type: u32le(raw, 0),
            p_flags: u32le(raw, 4),
            p_offset: u64le(raw, 8),
            p_vaddr: u64le(raw, 16),
            p_paddr: u64le(raw, 24),
            p_filesz: u64le(raw, 32),
            p_memsz: u64le(raw, 40),
            p_align: u64le(raw, 48),
        })
    }
}

/// Why an image was rejected. Distinguishing these matters: `libukbinfmt`
/// treats `ENOEXEC` as "not mine, try the next loader" and anything else as a
/// hard failure, so "this is not an ELF" and "this is an ELF I cannot load"
/// must not collapse into the same code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reject {
    /// Not an ELF64 little-endian image at all.
    NotElf,
    /// A valid ELF this loader will not run (wrong machine, wrong type, ...).
    Unsupported(&'static str),
    /// Structurally broken: offsets past the end, overlapping segments, ...
    Malformed(&'static str),
}

impl From<Reject> for Error {
    fn from(r: Reject) -> Error {
        match r {
            Reject::NotElf | Reject::Malformed(_) => Error::ENOEXEC,
            Reject::Unsupported(_) => Error::ENOTSUP,
        }
    }
}

impl Reject {
    pub fn as_str(self) -> &'static str {
        match self {
            Reject::NotElf => "not an ELF64 little-endian image",
            Reject::Unsupported(s) | Reject::Malformed(s) => s,
        }
    }
}

/// A parsed and validated program image: the executable header plus every
/// program header, with the loader-relevant ones already picked out.
#[derive(Clone, Debug)]
pub struct Image {
    pub ehdr: Ehdr,
    pub phdrs: Vec<Phdr>,
    /// Indices into `phdrs` of the `PT_LOAD` entries, in ascending `p_vaddr`.
    pub loads: Vec<usize>,
    pub interp: Option<Phdr>,
    pub phdr_seg: Option<Phdr>,
    pub tls: Option<Phdr>,
    pub relro: Option<Phdr>,
    /// `true` when a `PT_GNU_STACK` asks for an executable stack. Recorded so
    /// the decision to refuse is explicit rather than accidental.
    pub exec_stack: bool,
}

impl Image {
    pub fn is_pie(&self) -> bool {
        self.ehdr.e_type == ET_DYN
    }

    pub fn needs_interp(&self) -> bool {
        self.interp.is_some()
    }

    /// Read and validate the headers of `src`.
    ///
    /// `page_size` is needed here rather than later because the `p_vaddr ==
    /// p_offset (mod page_size)` congruence is what makes a file-backed
    /// mapping of a segment possible at all; a violation has to be caught
    /// before anything is mapped.
    pub fn parse<S: ImageSource + ?Sized>(
        src: &S,
        page_size: u64,
    ) -> core::result::Result<Image, Reject> {
        debug_assert!(page_size.is_power_of_two());

        let mut raw = [0u8; EHDR_SIZE];
        src.read_exact_at(0, &mut raw).map_err(|_| Reject::NotElf)?;
        let ehdr = Ehdr::parse(&raw).map_err(|_| Reject::NotElf)?;

        // --- identification. Anything failing here is "not for me". ---
        if ehdr.ident[..4] != ELFMAG
            || ehdr.ident[EI_CLASS] != ELFCLASS64
            || ehdr.ident[EI_DATA] != ELFDATA2LSB
            || ehdr.ident[EI_VERSION] != EV_CURRENT
        {
            return Err(Reject::NotElf);
        }

        // Linux accepts ELFOSABI_NONE and ELFOSABI_GNU for its binaries; some
        // aarch64 toolchains still stamp ELFOSABI_ARM_AEABI, and rejecting
        // those loses nothing since the syscall ABI is what actually matters.
        match ehdr.ident[EI_OSABI] {
            ELFOSABI_NONE | ELFOSABI_GNU | ELFOSABI_ARM_AEABI => {}
            _ => return Err(Reject::Unsupported("unsupported ELF OS ABI")),
        }

        if ehdr.e_machine != EM_NATIVE {
            return Err(Reject::Unsupported("ELF machine type mismatch"));
        }

        // Unlike the C loader, ET_EXEC is accepted. A non-PIE simply loads at
        // its own p_vaddr with a zero bias; refusing it ruled out every
        // `-no-pie` build and every static non-PIE binary for no good reason.
        if ehdr.e_type != ET_DYN && ehdr.e_type != ET_EXEC {
            return Err(Reject::Unsupported("ELF is neither ET_DYN nor ET_EXEC"));
        }

        if ehdr.e_version != 1 {
            return Err(Reject::Malformed("unsupported ELF version"));
        }

        // --- program header table ---
        if ehdr.e_phnum == PN_XNUM {
            // The real count lives in section header 0's sh_info. No real
            // executable has >65534 program headers; say so instead of
            // pretending e_phnum is 0xffff.
            return Err(Reject::Unsupported("PN_XNUM program header count"));
        }
        if ehdr.e_phnum == 0 {
            return Err(Reject::Malformed("no program headers"));
        }
        if ehdr.e_phnum > PHNUM_MAX {
            return Err(Reject::Malformed("implausible program header count"));
        }
        if (ehdr.e_phentsize as usize) < PHDR_SIZE {
            return Err(Reject::Malformed("program header entry too small"));
        }

        let phnum = ehdr.e_phnum as u64;
        let phentsize = ehdr.e_phentsize as u64;
        let phtab_len = phnum
            .checked_mul(phentsize)
            .ok_or(Reject::Malformed("program header table overflows"))?;
        let phtab_end = ehdr
            .e_phoff
            .checked_add(phtab_len)
            .ok_or(Reject::Malformed("program header table overflows"))?;
        if let Some(size) = src.size() {
            if phtab_end > size {
                return Err(Reject::Malformed("program header table past end of file"));
            }
        }

        let mut phdrs = Vec::new();
        phdrs
            .try_reserve(ehdr.e_phnum as usize)
            .map_err(|_| Reject::Malformed("out of memory reading program headers"))?;
        let mut ent = [0u8; PHDR_SIZE];
        for i in 0..phnum {
            src.read_exact_at(ehdr.e_phoff + i * phentsize, &mut ent)
                .map_err(|_| Reject::Malformed("truncated program header table"))?;
            phdrs.push(Phdr::parse(&ent).map_err(|_| Reject::Malformed("bad program header"))?);
        }

        // --- classify and validate ---
        let mut loads: Vec<usize> = Vec::new();
        let mut interp = None;
        let mut phdr_seg = None;
        let mut tls = None;
        let mut relro = None;
        let mut exec_stack = false;

        for (i, ph) in phdrs.iter().enumerate() {
            match ph.p_type {
                PT_LOAD => {
                    validate_load(ph, page_size, src.size())?;
                    loads.push(i);
                }
                PT_INTERP => {
                    if interp.is_some() {
                        return Err(Reject::Unsupported("multiple PT_INTERP"));
                    }
                    if ph.p_filesz == 0 || ph.p_filesz > INTERP_MAX {
                        return Err(Reject::Malformed("implausible PT_INTERP length"));
                    }
                    if let Some(size) = src.size() {
                        let end = ph
                            .p_offset
                            .checked_add(ph.p_filesz)
                            .ok_or(Reject::Malformed("PT_INTERP overflows"))?;
                        if end > size {
                            return Err(Reject::Malformed("PT_INTERP past end of file"));
                        }
                    }
                    interp = Some(*ph);
                }
                PT_PHDR => phdr_seg = Some(*ph),
                PT_TLS => tls = Some(*ph),
                PT_GNU_RELRO => relro = Some(*ph),
                PT_GNU_STACK => exec_stack = ph.is_exec(),
                _ => {}
            }
        }

        if loads.is_empty() {
            return Err(Reject::Malformed("no PT_LOAD segments"));
        }

        // The ELF spec requires PT_LOAD entries in ascending p_vaddr, and
        // every loader (including Linux's) relies on it. Sort rather than
        // reject -- but still refuse overlaps, which are unloadable whatever
        // the order.
        loads.sort_by_key(|&i| phdrs[i].p_vaddr);
        for w in loads.windows(2) {
            let (a, b) = (&phdrs[w[0]], &phdrs[w[1]]);
            let a_end = align_up(a.p_vaddr + a.p_memsz, page_size)
                .ok_or(Reject::Malformed("segment end overflows"))?;
            if b.p_vaddr < a_end && align_down(b.p_vaddr, page_size) < align_down(a_end, page_size)
            {
                return Err(Reject::Malformed("overlapping PT_LOAD segments"));
            }
        }

        Ok(Image {
            ehdr,
            phdrs,
            loads,
            interp,
            phdr_seg,
            tls,
            relro,
            exec_stack,
        })
    }

    /// Read the `PT_INTERP` path, without its terminating NUL.
    pub fn interp_path<S: ImageSource + ?Sized>(&self, src: &S) -> Result<Vec<u8>> {
        let ph = self.interp.ok_or(Error::EINVAL)?;
        let len = ph.p_filesz as usize;
        let mut buf = Vec::new();
        buf.try_reserve(len).map_err(|_| Error::ENOMEM)?;
        buf.resize(len, 0);
        src.read_exact_at(ph.p_offset, &mut buf)?;

        // PT_INTERP is a NUL-terminated string by convention, but only by
        // convention: truncate at the first NUL, and refuse an unterminated
        // or empty one rather than inventing a terminator the way the C
        // loader did (it overwrote the last byte, silently corrupting a path
        // that happened not to be terminated).
        match buf.iter().position(|&b| b == 0) {
            Some(0) => Err(Error::ENOEXEC),
            Some(n) => {
                buf.truncate(n);
                Ok(buf)
            }
            None => Err(Error::ENOEXEC),
        }
    }

    /// Lowest and highest page-aligned virtual address the image occupies, as
    /// linked (before any load bias).
    pub fn va_span(&self, page_size: u64) -> Result<(u64, u64)> {
        let first = &self.phdrs[self.loads[0]];
        let last = &self.phdrs[*self.loads.last().unwrap()];
        let lo = align_down(first.p_vaddr, page_size);
        let hi = align_up(last.p_vaddr + last.p_memsz, page_size).ok_or(Error::ENOEXEC)?;
        Ok((lo, hi))
    }

    /// Strongest alignment any loadable segment asks for, floored at the page
    /// size. arm64 distro toolchains link with `-z max-page-size=0x10000`, so
    /// this is routinely 64 KiB even though the page size is 4 KiB.
    pub fn load_align(&self, page_size: u64) -> u64 {
        let mut a = page_size;
        for &i in &self.loads {
            let pa = self.phdrs[i].p_align;
            if pa > a && pa.is_power_of_two() {
                a = pa;
            }
        }
        a
    }
}

fn validate_load(
    ph: &Phdr,
    page_size: u64,
    file_size: Option<u64>,
) -> core::result::Result<(), Reject> {
    if ph.p_filesz > ph.p_memsz {
        return Err(Reject::Malformed("PT_LOAD filesz exceeds memsz"));
    }
    if ph.p_align != 0 && !ph.p_align.is_power_of_two() {
        return Err(Reject::Malformed("PT_LOAD alignment is not a power of two"));
    }
    if ph.p_align > page_size && !ph.p_align.is_power_of_two() {
        return Err(Reject::Malformed("PT_LOAD alignment is not a power of two"));
    }
    ph.p_vaddr
        .checked_add(ph.p_memsz)
        .ok_or(Reject::Malformed("PT_LOAD vaddr+memsz overflows"))?;
    let file_end = ph
        .p_offset
        .checked_add(ph.p_filesz)
        .ok_or(Reject::Malformed("PT_LOAD offset+filesz overflows"))?;
    if let Some(size) = file_size {
        if file_end > size {
            return Err(Reject::Malformed("PT_LOAD extends past end of file"));
        }
    }

    // The spec requires p_offset and p_vaddr to be congruent modulo p_align.
    // What a loader actually needs is congruence modulo the *page size*: that
    // is what lets one mmap() place file bytes at the right virtual offset.
    // The C loader never checked, and would silently map a segment shifted by
    // the difference.
    if ph.p_filesz != 0 && (ph.p_vaddr & (page_size - 1)) != (ph.p_offset & (page_size - 1)) {
        return Err(Reject::Malformed(
            "PT_LOAD vaddr and offset are not page-congruent",
        ));
    }
    Ok(())
}

pub fn align_down(v: u64, a: u64) -> u64 {
    debug_assert!(a.is_power_of_two());
    v & !(a - 1)
}

pub fn align_up(v: u64, a: u64) -> Option<u64> {
    debug_assert!(a.is_power_of_two());
    v.checked_add(a - 1).map(|x| x & !(a - 1))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;

    #[test]
    fn parses_a_minimal_pie() {
        let img = ElfBuilder::new().pie_two_segment().build();
        let e = Image::parse(&img.as_slice(), 4096).unwrap();
        assert!(e.is_pie());
        assert_eq!(e.loads.len(), 2);
        assert!(!e.needs_interp());
        assert_eq!(e.va_span(4096).unwrap().0, 0);
    }

    #[test]
    fn accepts_non_pie() {
        let img = ElfBuilder::new().non_pie().build();
        let e = Image::parse(&img.as_slice(), 4096).unwrap();
        assert!(!e.is_pie());
        assert_eq!(e.ehdr.e_type, ET_EXEC);
        // The whole point: the span starts at the link address, not at 0.
        assert_eq!(e.va_span(4096).unwrap().0, 0x400000);
    }

    #[test]
    fn accepts_glibc_style_64k_alignment() {
        let img = ElfBuilder::new().glibc_arm64_style().build();
        let e = Image::parse(&img.as_slice(), 4096).unwrap();
        assert_eq!(e.load_align(4096), 0x10000);
        assert!(e.needs_interp());
        assert_eq!(
            e.interp_path(&img.as_slice()).unwrap(),
            b"/lib/ld-linux-aarch64.so.1"
        );
    }

    #[test]
    fn rejects_non_elf() {
        assert_eq!(
            Image::parse(&b"#!/bin/sh\n".as_slice(), 4096).unwrap_err(),
            Reject::NotElf
        );
        assert_eq!(
            Image::parse(&[].as_slice(), 4096).unwrap_err(),
            Reject::NotElf
        );
    }

    #[test]
    fn rejects_wrong_machine() {
        let img = ElfBuilder::new().pie_two_segment().machine(0x1234).build();
        assert!(matches!(
            Image::parse(&img.as_slice(), 4096).unwrap_err(),
            Reject::Unsupported(_)
        ));
    }

    #[test]
    fn rejects_truncated_phdr_table() {
        let mut img = ElfBuilder::new().pie_two_segment().build();
        img.bytes.truncate(72); // ehdr plus a fragment of one phdr
        assert!(matches!(
            Image::parse(&img.as_slice(), 4096).unwrap_err(),
            Reject::Malformed(_)
        ));
    }

    #[test]
    fn rejects_segment_past_end_of_file() {
        let img = ElfBuilder::new()
            .pie_two_segment()
            .patch_phdr(0, |p| p.p_filesz = 1 << 40)
            .build();
        assert!(matches!(
            Image::parse(&img.as_slice(), 4096).unwrap_err(),
            Reject::Malformed(_)
        ));
    }

    #[test]
    fn rejects_vaddr_memsz_overflow() {
        let img = ElfBuilder::new()
            .pie_two_segment()
            .patch_phdr(0, |p| {
                p.p_vaddr = u64::MAX - 0xfff;
                p.p_memsz = 0x2000;
            })
            .build();
        assert!(matches!(
            Image::parse(&img.as_slice(), 4096).unwrap_err(),
            Reject::Malformed(_)
        ));
    }

    #[test]
    fn rejects_filesz_greater_than_memsz() {
        let img = ElfBuilder::new()
            .pie_two_segment()
            .patch_phdr(0, |p| p.p_memsz = 1)
            .build();
        assert!(matches!(
            Image::parse(&img.as_slice(), 4096).unwrap_err(),
            Reject::Malformed(_)
        ));
    }

    #[test]
    fn rejects_non_congruent_segment() {
        // A segment whose file offset and virtual address disagree below the
        // page size cannot be produced by one mmap. The C loader mapped it
        // anyway, shifted.
        let img = ElfBuilder::new()
            .pie_two_segment()
            .patch_phdr(0, |p| p.p_vaddr += 0x40)
            .build();
        assert!(matches!(
            Image::parse(&img.as_slice(), 4096).unwrap_err(),
            Reject::Malformed(_)
        ));
    }

    #[test]
    fn rejects_overlapping_segments() {
        let img = ElfBuilder::new()
            .pie_two_segment()
            .patch_phdr(1, |p| p.p_vaddr = 0)
            .build();
        assert!(matches!(
            Image::parse(&img.as_slice(), 4096).unwrap_err(),
            Reject::Malformed(_)
        ));
    }

    #[test]
    fn rejects_pn_xnum() {
        let img = ElfBuilder::new().pie_two_segment().phnum_xnum().build();
        assert!(matches!(
            Image::parse(&img.as_slice(), 4096).unwrap_err(),
            Reject::Unsupported(_)
        ));
    }

    #[test]
    fn rejects_unterminated_interp() {
        let img = ElfBuilder::new().interp_without_nul().build();
        let e = Image::parse(&img.as_slice(), 4096).unwrap();
        assert_eq!(e.interp_path(&img.as_slice()).unwrap_err(), Error::ENOEXEC);
    }

    #[test]
    fn segments_are_sorted_by_vaddr() {
        let img = ElfBuilder::new().pie_two_segment().reverse_phdrs().build();
        let e = Image::parse(&img.as_slice(), 4096).unwrap();
        let a = e.phdrs[e.loads[0]].p_vaddr;
        let b = e.phdrs[e.loads[1]].p_vaddr;
        assert!(a < b, "loads should be ascending, got {a:#x} then {b:#x}");
    }

    #[test]
    fn notices_executable_stack_request() {
        let img = ElfBuilder::new().pie_two_segment().exec_stack().build();
        let e = Image::parse(&img.as_slice(), 4096).unwrap();
        assert!(e.exec_stack);
    }
}
