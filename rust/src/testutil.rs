// SPDX-License-Identifier: BSD-3-Clause
//! Synthetic ELF images for the host test suite.
//!
//! The layouts here are traced from real binaries rather than invented:
//! `glibc_arm64_style` has the 64 KiB segment alignment, the inter-segment
//! gap and the `memsz > filesz` data segment of Debian's
//! `aarch64-linux-gnu/libc.so.6`, scaled down so the fixture stays small.
//! That combination -- 64 KiB alignment over a 4 KiB page -- is exactly what
//! the loader has to get right on arm64.

#![cfg(test)]

use crate::elf::*;
use alloc::vec;
use alloc::vec::Vec;

pub struct TestImage {
    pub bytes: Vec<u8>,
}

impl TestImage {
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }
}

type Patch = (usize, fn(&mut Phdr));

pub struct ElfBuilder {
    e_type: u16,
    e_machine: u16,
    e_entry: u64,
    phdrs: Vec<Phdr>,
    overlays: Vec<(u64, Vec<u8>)>,
    patches: Vec<Patch>,
    force_phnum: Option<u16>,
    reverse: bool,
}

fn load(flags: u32, off: u64, va: u64, filesz: u64, memsz: u64, align: u64) -> Phdr {
    Phdr {
        p_type: PT_LOAD,
        p_flags: flags,
        p_offset: off,
        p_vaddr: va,
        p_paddr: va,
        p_filesz: filesz,
        p_memsz: memsz,
        p_align: align,
    }
}

impl ElfBuilder {
    pub fn new() -> Self {
        ElfBuilder {
            e_type: ET_DYN,
            e_machine: EM_NATIVE,
            e_entry: 0x400,
            phdrs: Vec::new(),
            overlays: Vec::new(),
            patches: Vec::new(),
            force_phnum: None,
            reverse: false,
        }
    }

    // --- shapes ---------------------------------------------------------

    /// The simplest thing that loads: two page-aligned segments, no
    /// interpreter. Indices into `phdrs` coincide with the PT_LOAD order, so
    /// tests can use `patch_phdr(0)` / `patch_phdr(1)`.
    pub fn pie_two_segment(mut self) -> Self {
        self.phdrs = vec![
            load(PF_R | PF_X, 0x0, 0x0, 0x1000, 0x1000, 0x1000),
            load(PF_R | PF_W, 0x1000, 0x2000, 0x500, 0x1500, 0x1000),
        ];
        self
    }

    /// `-no-pie`: ET_EXEC linked at the traditional 0x400000.
    pub fn non_pie(mut self) -> Self {
        self.e_type = ET_EXEC;
        self.e_entry = 0x400500;
        self.phdrs = vec![
            load(PF_R | PF_X, 0x0, 0x400000, 0x1000, 0x1000, 0x1000),
            load(PF_R | PF_W, 0x1000, 0x402000, 0x500, 0x1500, 0x1000),
        ];
        self
    }

    /// A dynamically linked arm64 shared object, shaped like glibc's:
    /// 64 KiB `p_align`, a gap between the code and data segments, a data
    /// segment whose `memsz` exceeds `filesz` by whole pages, plus PT_PHDR,
    /// PT_INTERP, PT_TLS, PT_DYNAMIC and PT_GNU_RELRO.
    pub fn glibc_arm64_style(mut self) -> Self {
        const INTERP_OFF: u64 = 0x200;
        let interp = b"/lib/ld-linux-aarch64.so.1\0";
        self.e_entry = 0x7930;
        self.phdrs = vec![
            Phdr {
                p_type: PT_PHDR,
                p_flags: PF_R,
                p_offset: 0x40,
                p_vaddr: 0x40,
                p_paddr: 0x40,
                p_filesz: 7 * PHDR_SIZE as u64,
                p_memsz: 7 * PHDR_SIZE as u64,
                p_align: 8,
            },
            Phdr {
                p_type: PT_INTERP,
                p_flags: PF_R,
                p_offset: INTERP_OFF,
                p_vaddr: INTERP_OFF,
                p_paddr: INTERP_OFF,
                p_filesz: interp.len() as u64,
                p_memsz: interp.len() as u64,
                p_align: 1,
            },
            load(PF_R | PF_X, 0x0, 0x0, 0x1b89c, 0x1b89c, 0x10000),
            load(PF_R | PF_W, 0x1cdc0, 0x2cdc0, 0x4908, 0x112a0, 0x10000),
            Phdr {
                p_type: PT_DYNAMIC,
                p_flags: PF_R | PF_W,
                p_offset: 0x1fbb0,
                p_vaddr: 0x2fbb0,
                p_paddr: 0x2fbb0,
                p_filesz: 0x1b0,
                p_memsz: 0x1b0,
                p_align: 8,
            },
            Phdr {
                p_type: PT_TLS,
                p_flags: PF_R,
                p_offset: 0x1cdc0,
                p_vaddr: 0x2cdc0,
                p_paddr: 0x2cdc0,
                p_filesz: 0x10,
                p_memsz: 0x90,
                p_align: 0x10,
            },
            Phdr {
                p_type: PT_GNU_RELRO,
                p_flags: PF_R,
                p_offset: 0x1cdc0,
                p_vaddr: 0x2cdc0,
                p_paddr: 0x2cdc0,
                p_filesz: 0x3240,
                p_memsz: 0x3240,
                p_align: 1,
            },
        ];
        self.overlays.push((INTERP_OFF, interp.to_vec()));
        self
    }

    /// What a current toolchain emits with `-z separate-code`: four PT_LOADs,
    /// only one of them executable.
    pub fn four_segment_separate_code(mut self) -> Self {
        self.e_entry = 0x1100;
        self.phdrs = vec![
            load(PF_R, 0x0, 0x0, 0x1000, 0x1000, 0x1000),
            load(PF_R | PF_X, 0x1000, 0x1000, 0x2000, 0x2000, 0x1000),
            load(PF_R, 0x3000, 0x3000, 0x1000, 0x1000, 0x1000),
            load(PF_R | PF_W, 0x4000, 0x5000, 0x800, 0x2000, 0x1000),
        ];
        self
    }

    /// A data segment that does not start on a page boundary, but is
    /// congruent with its file offset -- legal, and the case where getting the
    /// mmap offset wrong shifts the whole segment.
    pub fn unaligned_second_segment(mut self) -> Self {
        self.phdrs = vec![
            load(PF_R | PF_X, 0x0, 0x0, 0x1000, 0x1000, 0x1000),
            load(PF_R | PF_W, 0x1234, 0x2234, 0x500, 0x900, 0x1000),
        ];
        self
    }

    /// PT_INTERP whose contents are not NUL-terminated.
    pub fn interp_without_nul(mut self) -> Self {
        const OFF: u64 = 0x200;
        let s = b"/lib/ld-musl-aarch64.so.1";
        self = self.pie_two_segment();
        self.phdrs.push(Phdr {
            p_type: PT_INTERP,
            p_flags: PF_R,
            p_offset: OFF,
            p_vaddr: OFF,
            p_paddr: OFF,
            p_filesz: s.len() as u64,
            p_memsz: s.len() as u64,
            p_align: 1,
        });
        self.overlays.push((OFF, s.to_vec()));
        self
    }

    // --- modifiers ------------------------------------------------------

    pub fn machine(mut self, m: u16) -> Self {
        self.e_machine = m;
        self
    }

    pub fn patch_phdr(mut self, idx: usize, f: fn(&mut Phdr)) -> Self {
        self.patches.push((idx, f));
        self
    }

    pub fn phnum_xnum(mut self) -> Self {
        self.force_phnum = Some(PN_XNUM);
        self
    }

    pub fn reverse_phdrs(mut self) -> Self {
        self.reverse = true;
        self
    }

    pub fn exec_stack(mut self) -> Self {
        self.phdrs.push(Phdr {
            p_type: PT_GNU_STACK,
            p_flags: PF_R | PF_W | PF_X,
            ..Phdr::default()
        });
        self
    }

    /// Drop PT_INTERP: a dynamic linker looks like this -- same 64 KiB
    /// alignment and inter-segment gap as the program it loads, but it asks
    /// for no interpreter of its own.
    pub fn no_interp(mut self) -> Self {
        self.phdrs.retain(|p| p.p_type != PT_INTERP);
        self
    }

    pub fn drop_pt_phdr(mut self) -> Self {
        self.phdrs.retain(|p| p.p_type != PT_PHDR);
        self
    }

    // --- serialisation --------------------------------------------------

    pub fn build(mut self) -> TestImage {
        for (idx, f) in core::mem::take(&mut self.patches) {
            f(&mut self.phdrs[idx]);
        }
        if self.reverse {
            self.phdrs.reverse();
        }

        let phoff = EHDR_SIZE as u64;
        let phnum = self.phdrs.len() as u64;
        let mut size = phoff + phnum * PHDR_SIZE as u64;
        for p in &self.phdrs {
            // Saturating: some fixtures deliberately set an absurd p_filesz to
            // exercise the "past end of file" rejection, and the file must not
            // grow to accommodate it.
            if p.p_filesz < (1 << 32) {
                size = size.max(p.p_offset.saturating_add(p.p_filesz));
            }
        }
        for (off, data) in &self.overlays {
            size = size.max(off + data.len() as u64);
        }
        let size = ((size + 0xfff) & !0xfff) as usize;

        // A recognisable, NUL-free-ish pattern so loader tests can assert that
        // file byte N really landed at the address it should have.
        let mut b: Vec<u8> = (0..size).map(|i| (i % 251) as u8 | 1).collect();

        b[0..4].copy_from_slice(&ELFMAG);
        b[EI_CLASS] = ELFCLASS64;
        b[EI_DATA] = ELFDATA2LSB;
        b[EI_VERSION] = EV_CURRENT;
        b[EI_OSABI] = ELFOSABI_NONE;
        b[EI_ABIVERSION] = 0;
        b[9..16].fill(0);

        put16(&mut b, 16, self.e_type);
        put16(&mut b, 18, self.e_machine);
        put32(&mut b, 20, 1);
        put64(&mut b, 24, self.e_entry);
        put64(&mut b, 32, phoff);
        put64(&mut b, 40, 0); // e_shoff
        put32(&mut b, 48, 0);
        put16(&mut b, 52, EHDR_SIZE as u16);
        put16(&mut b, 54, PHDR_SIZE as u16);
        put16(&mut b, 56, self.force_phnum.unwrap_or(phnum as u16));
        put16(&mut b, 58, 64);
        put16(&mut b, 60, 0);
        put16(&mut b, 62, 0);

        for (i, p) in self.phdrs.iter().enumerate() {
            let o = phoff as usize + i * PHDR_SIZE;
            put32(&mut b, o, p.p_type);
            put32(&mut b, o + 4, p.p_flags);
            put64(&mut b, o + 8, p.p_offset);
            put64(&mut b, o + 16, p.p_vaddr);
            put64(&mut b, o + 24, p.p_paddr);
            put64(&mut b, o + 32, p.p_filesz);
            put64(&mut b, o + 40, p.p_memsz);
            put64(&mut b, o + 48, p.p_align);
        }

        for (off, data) in &self.overlays {
            let o = *off as usize;
            b[o..o + data.len()].copy_from_slice(data);
        }

        TestImage { bytes: b }
    }
}

fn put16(b: &mut [u8], o: usize, v: u16) {
    b[o..o + 2].copy_from_slice(&v.to_le_bytes());
}
fn put32(b: &mut [u8], o: usize, v: u32) {
    b[o..o + 4].copy_from_slice(&v.to_le_bytes());
}
fn put64(b: &mut [u8], o: usize, v: u64) {
    b[o..o + 8].copy_from_slice(&v.to_le_bytes());
}

/// A model address space that behaves like Unikraft's.
///
/// The important fidelity detail is placement: `uk_vma_map()` picks the *first*
/// free range at or above a fixed base (`vmem_first_fit` in `lib/ukvmem`), so
/// any hole a loader leaves behind is a hole something else can be dropped
/// into. Tests use that to prove the image's range is never released.
pub mod vm {
    use super::TestImage;
    use crate::err::Result;
    use crate::layout::PROT_WRITE;
    use crate::loader::RW;
    use crate::loader::{MapSrc, Vm, Where};
    use alloc::collections::BTreeMap;
    use alloc::vec::Vec;
    use core::cell::RefCell;

    #[derive(Clone, Debug)]
    pub struct Region {
        len: u64,
        prot: u32,
        data: Vec<u8>,
        file: Option<(i32, u64)>,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum Op {
        Map { addr: u64, len: u64, prot: u32 },
        Unmap { addr: u64, len: u64 },
        Protect { addr: u64, len: u64, prot: u32 },
        Zero { addr: u64, len: u64 },
        Icache { addr: u64, len: u64 },
    }

    /// An address space that behaves like Unikraft's: `uk_vma_map()` with no
    /// address picks the *first* free range at or above a fixed base, so any
    /// hole the loader leaves is a hole something else can be put in.
    pub struct FakeVm {
        page: u64,
        can_map_files: bool,
        st: RefCell<State>,
    }

    pub struct State {
        base: u64,
        regions: BTreeMap<u64, Region>,
        log: Vec<Op>,
        heap: u64,
    }

    impl FakeVm {
        pub fn new() -> Self {
            FakeVm {
                page: 4096,
                can_map_files: true,
                st: RefCell::new(State {
                    base: 0x1000_0000,
                    regions: BTreeMap::new(),
                    log: Vec::new(),
                    heap: 0x8000_0000_0000,
                }),
            }
        }

        pub fn no_files(mut self) -> Self {
            self.can_map_files = false;
            self
        }

        pub fn ops(&self) -> Vec<Op> {
            self.st.borrow().log.clone()
        }

        /// Every mapped byte, for overlap assertions.
        pub fn regions(&self) -> Vec<(u64, u64, u32)> {
            self.st
                .borrow()
                .regions
                .iter()
                .map(|(&a, r)| (a, r.len, r.prot))
                .collect()
        }

        pub fn read(&self, addr: u64, len: usize) -> Vec<u8> {
            let st = self.st.borrow();
            let (&start, r) = st
                .regions
                .range(..=addr)
                .next_back()
                .expect("address is not mapped");
            assert!(
                addr + len as u64 <= start + r.len,
                "read {addr:#x}+{len:#x} crosses out of region {start:#x}+{:#x}",
                r.len
            );
            let o = (addr - start) as usize;
            r.data[o..o + len].to_vec()
        }

        pub fn prot_at(&self, addr: u64) -> u32 {
            let st = self.st.borrow();
            let (&start, r) = st.regions.range(..=addr).next_back().expect("unmapped");
            assert!(addr < start + r.len, "{addr:#x} is in a hole");
            r.prot
        }

        pub fn is_mapped(&self, addr: u64) -> bool {
            let st = self.st.borrow();
            match st.regions.range(..=addr).next_back() {
                Some((&start, r)) => addr < start + r.len,
                None => false,
            }
        }

        /// Carve `[addr, addr+len)` out of whatever occupies it.
        fn punch(st: &mut State, addr: u64, len: u64) {
            let end = addr + len;
            let hits: Vec<u64> = st
                .regions
                .range(..end)
                .filter(|(&s, r)| s + r.len > addr)
                .map(|(&s, _)| s)
                .collect();
            for s in hits {
                let r = st.regions.remove(&s).unwrap();
                let e = s + r.len;
                if s < addr {
                    let n = (addr - s) as usize;
                    st.regions.insert(
                        s,
                        Region {
                            len: addr - s,
                            prot: r.prot,
                            data: r.data[..n].to_vec(),
                            file: r.file,
                        },
                    );
                }
                if e > end {
                    let o = (end - s) as usize;
                    st.regions.insert(
                        end,
                        Region {
                            len: e - end,
                            prot: r.prot,
                            data: r.data[o..].to_vec(),
                            file: r.file.map(|(fd, off)| (fd, off + (end - s))),
                        },
                    );
                }
            }
        }

        fn first_fit(st: &State, len: u64) -> u64 {
            let mut cur = st.base;
            for (&s, r) in st.regions.iter() {
                if s + r.len <= cur {
                    continue;
                }
                if s >= cur + len {
                    return cur;
                }
                cur = s + r.len;
            }
            cur
        }

        /// What an unrelated `mmap(NULL, len)` would return right now.
        pub fn would_place(&self, len: u64) -> u64 {
            Self::first_fit(&self.st.borrow(), len)
        }
    }

    // File contents the fake serves for file-backed mappings.
    thread_local! {
        static FILES: RefCell<BTreeMap<i32, Vec<u8>>> = const { RefCell::new(BTreeMap::new()) };
    }

    impl Vm for FakeVm {
        fn page_size(&self) -> u64 {
            self.page
        }

        fn map(&self, at: Where, len: u64, prot: u32, src: MapSrc) -> Result<u64> {
            assert_eq!(len % self.page, 0, "map length {len:#x} is not page-aligned");
            let mut st = self.st.borrow_mut();
            let addr = match at {
                Where::Anywhere => FakeVm::first_fit(&st, len),
                Where::Hint(a) => {
                    let free = st
                        .regions
                        .range(..a + len)
                        .all(|(&s, r)| s + r.len <= a || s >= a + len);
                    if free {
                        a
                    } else {
                        FakeVm::first_fit(&st, len)
                    }
                }
                Where::Exact(a) => {
                    FakeVm::punch(&mut st, a, len);
                    a
                }
            };
            assert_eq!(addr % self.page, 0);

            let data = match src {
                MapSrc::Anon => alloc::vec![0u8; len as usize],
                MapSrc::File { fd, off } => FILES.with(|f| {
                    let f = f.borrow();
                    let file = f.get(&fd).expect("unknown fd");
                    let mut d = alloc::vec![0u8; len as usize];
                    let start = off as usize;
                    let n = core::cmp::min(len as usize, file.len().saturating_sub(start));
                    d[..n].copy_from_slice(&file[start..start + n]);
                    d
                }),
            };
            st.regions.insert(
                addr,
                Region {
                    len,
                    prot,
                    data,
                    file: match src {
                        MapSrc::Anon => None,
                        MapSrc::File { fd, off } => Some((fd, off)),
                    },
                },
            );
            st.log.push(Op::Map { addr, len, prot });
            Ok(addr)
        }

        fn unmap(&self, addr: u64, len: u64) -> Result<()> {
            let mut st = self.st.borrow_mut();
            FakeVm::punch(&mut st, addr, len);
            st.log.push(Op::Unmap { addr, len });
            Ok(())
        }

        fn protect(&self, addr: u64, len: u64, prot: u32) -> Result<()> {
            let mut st = self.st.borrow_mut();
            let end = addr + len;
            let hits: Vec<u64> = st
                .regions
                .range(..end)
                .filter(|(&s, r)| s + r.len > addr)
                .map(|(&s, _)| s)
                .collect();
            assert!(!hits.is_empty(), "protect on unmapped {addr:#x}+{len:#x}");
            for s in hits {
                st.regions.get_mut(&s).unwrap().prot = prot;
            }
            st.log.push(Op::Protect { addr, len, prot });
            Ok(())
        }

        fn write(&self, addr: u64, data: &[u8]) -> Result<()> {
            let mut st = self.st.borrow_mut();
            let (&start, r) = st
                .regions
                .range_mut(..=addr)
                .next_back()
                .expect("write to unmapped memory");
            assert!(
                addr + data.len() as u64 <= start + r.len,
                "write {addr:#x}+{:#x} runs past its region",
                data.len()
            );
            assert!(r.prot & PROT_WRITE != 0, "write to non-writable mapping");
            let o = (addr - start) as usize;
            r.data[o..o + data.len()].copy_from_slice(data);
            Ok(())
        }

        fn zero(&self, addr: u64, len: u64) -> Result<()> {
            {
                let mut st = self.st.borrow_mut();
                let (&start, r) = st
                    .regions
                    .range_mut(..=addr)
                    .next_back()
                    .expect("zero of unmapped memory");
                assert!(addr + len <= start + r.len, "zero runs past its region");
                assert!(r.prot & PROT_WRITE != 0, "zero of non-writable mapping");
                let o = (addr - start) as usize;
                r.data[o..o + len as usize].fill(0);
            }
            self.st.borrow_mut().log.push(Op::Zero { addr, len });
            Ok(())
        }

        fn icache_sync(&self, addr: u64, len: u64) {
            self.st.borrow_mut().log.push(Op::Icache { addr, len });
        }

        fn can_map_files(&self) -> bool {
            self.can_map_files
        }

        fn alloc_aligned(&self, align: u64, len: u64) -> Result<u64> {
            let mut st = self.st.borrow_mut();
            let addr = (st.heap + align - 1) & !(align - 1);
            st.heap = addr + len;
            st.regions.insert(
                addr,
                Region {
                    len,
                    prot: RW,
                    data: alloc::vec![0u8; len as usize],
                    file: None,
                },
            );
            st.log.push(Op::Map {
                addr,
                len,
                prot: RW,
            });
            Ok(addr)
        }

        fn free_aligned(&self, addr: u64, len: u64) {
            let mut st = self.st.borrow_mut();
            FakeVm::punch(&mut st, addr, len);
            st.log.push(Op::Unmap { addr, len });
        }
    }


    pub fn install(fd: i32, img: &TestImage) {
        FILES.with(|f| f.borrow_mut().insert(fd, img.bytes.clone()));
    }

    /// Which descriptor a given file body was installed under.
    pub fn find_fd(data: &[u8]) -> Option<i32> {
        FILES.with(|f| {
            f.borrow()
                .iter()
                .find(|(_, v)| v.as_slice() == data)
                .map(|(k, _)| *k)
        })
    }
}

// --- a stack to lay out, for the auxv tests ------------------------------

use crate::err::Result as UtilResult;
use crate::auxv::StackWriter;

/// A stack living in a `Vec`, at a plausible virtual address.
pub struct FakeStack {
    base: u64,
    mem: Vec<u8>,
    /// Lowest address ever written, to catch overruns that stay in range.
    pub low: u64,
}

impl FakeStack {
    pub fn new(base: u64, len: usize) -> Self {
        FakeStack {
            base,
            mem: alloc::vec![0xAA; len],
            low: base + len as u64,
        }
    }
    pub fn read(&self, addr: u64, n: usize) -> &[u8] {
        let o = (addr - self.base) as usize;
        &self.mem[o..o + n]
    }
    pub fn u64_at(&self, addr: u64) -> u64 {
        let mut b = [0u8; 8];
        b.copy_from_slice(self.read(addr, 8));
        u64::from_le_bytes(b)
    }
    pub fn cstr_at(&self, addr: u64) -> Vec<u8> {
        let o = (addr - self.base) as usize;
        let end = self.mem[o..].iter().position(|&b| b == 0).unwrap() + o;
        self.mem[o..end].to_vec()
    }
}

impl StackWriter for FakeStack {
    fn top(&self) -> u64 {
        self.base + self.mem.len() as u64
    }
    fn bottom(&self) -> u64 {
        self.base
    }
    fn write(&mut self, addr: u64, data: &[u8]) -> UtilResult<()> {
        assert!(addr >= self.bottom(), "write below the stack");
        assert!(
            addr + data.len() as u64 <= self.top(),
            "write above the stack"
        );
        self.low = self.low.min(addr);
        let o = (addr - self.base) as usize;
        self.mem[o..o + data.len()].copy_from_slice(data);
        Ok(())
    }
}


impl FakeStack {
    /// Look one auxiliary vector entry up in a stack that `build_stack` has
    /// already laid out, the way a libc start-up would.
    pub fn auxv_value(&self, sp: u64, key: u64) -> Option<u64> {
        let argc = self.u64_at(sp) as usize;
        let mut at = sp + 8 + (argc as u64 + 1) * 8;
        while self.u64_at(at) != 0 {
            at += 8;
        }
        at += 8;
        loop {
            let k = self.u64_at(at);
            let v = self.u64_at(at + 8);
            at += 16;
            if k == crate::auxv::AT_NULL {
                return None;
            }
            if k == key {
                return Some(v);
            }
        }
    }
}
