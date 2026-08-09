// SPDX-License-Identifier: BSD-3-Clause
//! Executing a [`LoadPlan`] against an address space.
//!
//! The address space is behind the [`Vm`] trait so the whole procedure can be
//! run on the host against a model that mimics Unikraft's allocator, including
//! its first-fit placement. That is what lets the test suite assert the
//! property this rewrite exists for: **the image's address range is never
//! unreserved, not even briefly**.

use crate::elf::{Image, ImageSource, ET_DYN};
use crate::err::{Error, Result};
use crate::layout::{self, LoadPlan, Placement, PROT_EXEC, PROT_NONE, PROT_READ, PROT_WRITE};
use crate::log;
use alloc::vec::Vec;

/// Where a mapping should go.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Where {
    /// The system picks. Never replaces anything.
    Anywhere,
    /// A preference. May come back somewhere else; the caller must check.
    Hint(u64),
    /// Exactly here, replacing whatever is in the way. Only ever used to fill
    /// in a range this loader already holds.
    Exact(u64),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MapSrc {
    Anon,
    File { fd: i32, off: u64 },
}

pub trait Vm {
    fn page_size(&self) -> u64;
    fn map(&self, at: Where, len: u64, prot: u32, src: MapSrc) -> Result<u64>;
    fn unmap(&self, addr: u64, len: u64) -> Result<()>;
    fn protect(&self, addr: u64, len: u64, prot: u32) -> Result<()>;
    fn write(&self, addr: u64, data: &[u8]) -> Result<()>;
    fn zero(&self, addr: u64, len: u64) -> Result<()>;
    /// Make writes at `addr..addr+len` visible to instruction fetch.
    fn icache_sync(&self, addr: u64, len: u64);
    /// Whether file-backed mappings are available (`CONFIG_LIBPOSIX_MMAP`).
    fn can_map_files(&self) -> bool;
    fn alloc_aligned(&self, align: u64, len: u64) -> Result<u64>;
    fn free_aligned(&self, addr: u64, len: u64);
}

/// A loaded image and the resources it owns.
#[derive(Debug)]
pub struct Loaded {
    pub plan: LoadPlan,
    /// `true` when the backing store is an `alloc_aligned` block rather than
    /// mappings, so `unload` knows which to release.
    allocated: bool,
}

impl Loaded {
    pub fn unload<V: Vm>(&self, vm: &V) {
        if self.allocated {
            vm.free_aligned(self.plan.reserve_addr, self.plan.reserve_len);
        } else if let Err(e) = vm.unmap(self.plan.reserve_addr, self.plan.reserve_len) {
            log::warn(format_args!(
                "failed to release image reservation {:#x}+{:#x}: {e}",
                self.plan.reserve_addr, self.plan.reserve_len
            ));
        }
    }
}

const COPY_CHUNK: usize = 64 * 1024;

/// Load `image` into `vm`.
///
/// `fd` is the descriptor the image came from, used for file-backed mappings.
/// Pass `None` for an in-memory image (the initrd case), which forces the copy
/// path.
pub fn load<S: ImageSource + ?Sized, V: Vm>(
    name: &str,
    image: &Image,
    src: &S,
    fd: Option<i32>,
    vm: &V,
) -> Result<Loaded> {
    let page = vm.page_size();
    let use_mmap = vm.can_map_files() && fd.is_some();

    if use_mmap {
        load_mapped(name, image, src, fd.unwrap(), vm, page)
    } else {
        load_copied(name, image, src, vm, page)
    }
}

/// The mmap path.
///
/// Order matters, and differs from the C loader in exactly one respect that
/// turns out to be the important one. The C loader sized a scratch mapping,
/// **munmap'd it**, and then mapped each segment into the address it had been
/// told. Between the unmap and the last segment map, and permanently in every
/// inter-segment gap, the range was free -- and Unikraft hands out addresses
/// first-fit from a fixed base, so an unrelated `mmap(NULL, ...)` could be
/// placed inside the program image. Here the reservation is taken once, as
/// `PROT_NONE`, and every segment is mapped *into* it with MAP_FIXED. The
/// reservation is released only by `unload`.
fn load_mapped<S: ImageSource + ?Sized, V: Vm>(
    name: &str,
    image: &Image,
    src: &S,
    fd: i32,
    vm: &V,
    page: u64,
) -> Result<Loaded> {
    let (va_lo, _) = image.va_span(page)?;
    let need = layout::reservation_len(image, page)?;

    let placement = if image.ehdr.e_type == ET_DYN {
        let raw = vm.map(Where::Anywhere, need, PROT_NONE, MapSrc::Anon)?;
        Placement::At(raw)
    } else {
        // Non-PIE: the image names its own address, so ask for exactly that
        // and refuse to continue if something is already there. Asking as a
        // hint rather than MAP_FIXED matters -- MAP_FIXED would silently
        // evict whatever was in the way.
        let span = image.va_span(page)?.1 - va_lo;
        let got = vm.map(Where::Hint(va_lo), span, PROT_NONE, MapSrc::Anon)?;
        if got != va_lo {
            log::err(format_args!(
                "{name}: cannot place non-PIE image at its link address {va_lo:#x} (got {got:#x})"
            ));
            let _ = vm.unmap(got, span);
            return Err(Error::ENOMEM);
        }
        Placement::Fixed
    };

    let plan = layout::plan(image, page, placement)?;
    let loaded = Loaded {
        plan,
        allocated: false,
    };

    if let Err(e) = fill_mapped(name, image, src, fd, vm, &loaded.plan) {
        loaded.unload(vm);
        return Err(e);
    }
    Ok(loaded)
}

fn fill_mapped<S: ImageSource + ?Sized, V: Vm>(
    name: &str,
    image: &Image,
    src: &S,
    fd: i32,
    vm: &V,
    plan: &LoadPlan,
) -> Result<()> {
    for seg in &plan.segments {
        let ph = &image.phdrs[seg.idx];
        let f = ph.flag_str();
        log::debug(format_args!(
            "{name}: segment {} {}{}{} -> {:#x}..{:#x} (file {:#x}+{:#x})",
            seg.idx,
            f[0] as char,
            f[1] as char,
            f[2] as char,
            seg.range().0,
            seg.range().1,
            ph.p_offset,
            ph.p_filesz
        ));

        if let Some(fm) = seg.file {
            // Map writable when the tail of the last page has to be cleared,
            // then narrow below. A read-only segment with a partial last page
            // otherwise exposes whatever bytes followed it in the file.
            let prot = if seg.needs_write_window {
                seg.prot | PROT_WRITE
            } else {
                seg.prot
            };
            let got = vm.map(
                Where::Exact(fm.addr),
                fm.len,
                prot,
                MapSrc::File { fd, off: fm.off },
            )?;
            debug_assert_eq!(got, fm.addr);
        }

        if let Some(z) = seg.zero {
            vm.zero(z.addr, z.len)?;
        }

        if let Some(a) = seg.anon {
            // Anonymous pages arrive zeroed, so `.bss` needs no explicit
            // clearing beyond the partial page handled above.
            let got = vm.map(Where::Exact(a.addr), a.len, seg.prot, MapSrc::Anon)?;
            debug_assert_eq!(got, a.addr);
        }

        if seg.needs_write_window {
            let (s, e) = seg.range();
            vm.protect(s, e - s, seg.prot)?;
        }
    }

    // The file-backed pages are populated on demand by the kernel, so any
    // instruction-cache maintenance for them belongs to the fault handler,
    // not here. Only bytes this loader wrote itself need syncing.
    for seg in &plan.segments {
        if image.phdrs[seg.idx].is_exec() {
            if let Some(z) = seg.zero {
                vm.icache_sync(z.addr, z.len);
            }
        }
    }

    let _ = src;
    Ok(())
}

/// The copy path: one aligned allocation, contents read in with `pread`.
///
/// Used when there is no `mmap` (`CONFIG_LIBPOSIX_MMAP=n`) and for in-memory
/// images from the initrd. Because the loader writes the instructions itself
/// here, it also has to make them visible to instruction fetch -- on arm64
/// that is not automatic, and nothing else in the system does it.
fn load_copied<S: ImageSource + ?Sized, V: Vm>(
    name: &str,
    image: &Image,
    src: &S,
    vm: &V,
    page: u64,
) -> Result<Loaded> {
    if image.ehdr.e_type != ET_DYN {
        // Without mmap there is no way to demand a particular address.
        log::err(format_args!(
            "{name}: non-PIE images need CONFIG_LIBPOSIX_MMAP to be placed at their link address"
        ));
        return Err(Error::ENOTSUP);
    }

    let need = layout::reservation_len(image, page)?;
    let align = layout::seg_align(image, page);
    let raw = vm.alloc_aligned(align, need)?;

    let plan = layout::plan(image, page, Placement::At(raw))?;
    let loaded = Loaded {
        plan,
        allocated: true,
    };

    if let Err(e) = fill_copied(name, image, src, vm, &loaded.plan) {
        loaded.unload(vm);
        return Err(e);
    }
    Ok(loaded)
}

fn fill_copied<S: ImageSource + ?Sized, V: Vm>(
    name: &str,
    image: &Image,
    src: &S,
    vm: &V,
    plan: &LoadPlan,
) -> Result<()> {
    let mut buf = Vec::new();
    buf.try_reserve(COPY_CHUNK).map_err(|_| Error::ENOMEM)?;
    buf.resize(COPY_CHUNK, 0);

    for seg in &plan.segments {
        let ph = &image.phdrs[seg.idx];
        let vaddr = ph.p_vaddr + plan.bias;

        let mut done: u64 = 0;
        while done < ph.p_filesz {
            let n = core::cmp::min(COPY_CHUNK as u64, ph.p_filesz - done) as usize;
            src.read_exact_at(ph.p_offset + done, &mut buf[..n])?;
            vm.write(vaddr + done, &buf[..n])?;
            done += n as u64;
        }

        // Everything from the end of file data to the end of the segment,
        // rounded out to the page. The C loader only did this when the
        // segment was writable.
        let mem_end = crate::elf::align_up(vaddr + ph.p_memsz, vm.page_size()).ok_or(Error::ENOMEM)?;
        let zstart = vaddr + ph.p_filesz;
        if mem_end > zstart {
            vm.zero(zstart, mem_end - zstart)?;
        }
    }

    for (addr, len) in plan.exec_ranges(image) {
        vm.icache_sync(addr, len);
    }

    for seg in &plan.segments {
        let (s, e) = seg.range();
        if let Err(err) = vm.protect(s, e - s, seg.prot) {
            // Not fatal: without CONFIG_LIBUKVMEM there is nothing to enforce
            // and the program still runs, just without W^X.
            log::warn(format_args!(
                "{name}: could not set protection on {s:#x}..{e:#x}: {err}"
            ));
        }
    }
    Ok(())
}

/// Protection the entry point must have, for a sanity check at start-up.
pub fn entry_is_executable(image: &Image, plan: &LoadPlan) -> bool {
    plan.segments.iter().any(|s| {
        let (a, b) = s.range();
        s.prot & PROT_EXEC != 0 && plan.entry >= a && plan.entry < b
    }) && !image.loads.is_empty()
}

/// Reject a request for an executable stack rather than silently ignoring it.
/// Unikraft's thread stacks are not executable and cannot be made so, and a
/// binary that genuinely needs one (a GCC nested-function trampoline, an old
/// JIT) would fail in a much more confusing way later.
pub fn check_stack_request(name: &str, image: &Image) -> Result<()> {
    if image.exec_stack {
        log::err(format_args!(
            "{name}: PT_GNU_STACK requests an executable stack, which is not supported"
        ));
        return Err(Error::ENOTSUP);
    }
    Ok(())
}

/// `PROT_READ | PROT_WRITE`, spelled out for the copy path.
pub const RW: u32 = PROT_READ | PROT_WRITE;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::vm::*;
    use crate::testutil::*;

    fn load_fixture(vm: &FakeVm, img: &TestImage, fd: i32) -> Loaded {
        install(fd, img);
        let e = Image::parse(&img.as_slice(), 4096).unwrap();
        load("test", &e, &img.as_slice(), Some(fd), vm).unwrap()
    }

    #[test]
    fn image_range_is_never_left_unreserved() {
        // The regression this rewrite is about. Replay the operation log and
        // check that after the very first map, every address inside the
        // image's span is continuously covered.
        let vm = FakeVm::new();
        let img = ElfBuilder::new().glibc_arm64_style().build();
        let l = load_fixture(&vm, &img, 3);

        let ops = vm.ops();
        assert!(matches!(ops[0], Op::Map { .. }), "reservation comes first");
        assert!(
            !ops.iter().any(|o| matches!(o, Op::Unmap { .. })),
            "nothing is unmapped during a successful load: {ops:#?}"
        );

        // And the whole span, holes included, is still covered afterwards.
        let mut a = l.plan.reserve_addr;
        while a < l.plan.reserve_addr + l.plan.reserve_len {
            assert!(vm.is_mapped(a), "{a:#x} is not mapped");
            a += 4096;
        }
    }

    #[test]
    fn a_later_anonymous_mapping_cannot_land_inside_the_image() {
        // With the C loader's unmap-then-map, the inter-segment gap of a
        // glibc-style image (64 KiB, from `-z max-page-size=0x10000`) was free
        // and first-fit would hand it straight back.
        let vm = FakeVm::new();
        let img = ElfBuilder::new().glibc_arm64_style().build();
        let l = load_fixture(&vm, &img, 3);

        let placed = vm.would_place(0x4000);
        assert!(
            placed >= l.plan.reserve_addr + l.plan.reserve_len,
            "a 16 KiB mapping would be placed at {placed:#x}, inside the image \
             {:#x}..{:#x}",
            l.plan.reserve_addr,
            l.plan.reserve_addr + l.plan.reserve_len
        );
    }

    #[test]
    fn segment_contents_land_at_the_right_addresses() {
        let vm = FakeVm::new();
        let img = ElfBuilder::new().unaligned_second_segment().build();
        let l = load_fixture(&vm, &img, 3);
        let e = Image::parse(&img.as_slice(), 4096).unwrap();

        for &i in &e.loads {
            let ph = &e.phdrs[i];
            let va = ph.p_vaddr + l.plan.bias;
            let n = core::cmp::min(ph.p_filesz, 256) as usize;
            let got = vm.read(va, n);
            let want = &img.bytes[ph.p_offset as usize..ph.p_offset as usize + n];
            assert_eq!(got, want, "segment {i} contents are shifted");

            // ...and the last byte of the segment too, which is where an
            // off-by-a-page in the offset calculation shows up.
            let last = (ph.p_filesz - 1) as usize;
            assert_eq!(
                vm.read(va + last as u64, 1)[0],
                img.bytes[ph.p_offset as usize + last]
            );
        }
    }

    #[test]
    fn bss_tail_is_zeroed_and_file_bytes_do_not_leak() {
        let vm = FakeVm::new();
        let img = ElfBuilder::new().glibc_arm64_style().build();
        let l = load_fixture(&vm, &img, 3);
        let e = Image::parse(&img.as_slice(), 4096).unwrap();

        let data = e
            .loads
            .iter()
            .map(|&i| &e.phdrs[i])
            .find(|p| p.is_write())
            .unwrap();
        let fend = data.p_vaddr + l.plan.bias + data.p_filesz;
        let mend = data.p_vaddr + l.plan.bias + data.p_memsz;

        // Byte just past filesz: in the file this is non-zero (the fixture
        // pattern sets bit 0), so a leak is detectable.
        assert_ne!(img.bytes[(data.p_offset + data.p_filesz) as usize], 0);
        assert_eq!(vm.read(fend, 1)[0], 0, "file bytes leaked past p_filesz");
        assert_eq!(vm.read(mend - 1, 1)[0], 0, "end of .bss is not zero");
    }

    #[test]
    fn final_protections_match_the_segment_flags() {
        let vm = FakeVm::new();
        let img = ElfBuilder::new().four_segment_separate_code().build();
        let l = load_fixture(&vm, &img, 3);
        let e = Image::parse(&img.as_slice(), 4096).unwrap();

        for &i in &e.loads {
            let ph = &e.phdrs[i];
            let va = ph.p_vaddr + l.plan.bias;
            let want = layout::prot_of(ph);
            assert_eq!(vm.prot_at(va), want, "segment {i} protection");
        }

        // No writable page is also executable, and vice versa.
        for (a, len, prot) in vm.regions() {
            assert!(
                prot & PROT_WRITE == 0 || prot & PROT_EXEC == 0,
                "{a:#x}+{len:#x} is both writable and executable ({prot:#x})"
            );
        }
    }

    #[test]
    fn gaps_between_segments_stay_inaccessible() {
        let vm = FakeVm::new();
        let img = ElfBuilder::new().glibc_arm64_style().build();
        let l = load_fixture(&vm, &img, 3);
        let e = Image::parse(&img.as_slice(), 4096).unwrap();

        // The 64 KiB hole between glibc's code and data segments.
        let code = e.loads.iter().map(|&i| &e.phdrs[i]).next().unwrap();
        let gap = crate::elf::align_up(code.p_vaddr + code.p_memsz, 4096).unwrap() + l.plan.bias;
        assert!(vm.is_mapped(gap));
        assert_eq!(vm.prot_at(gap), PROT_NONE, "the gap should be unreadable");
    }

    #[test]
    fn non_pie_loads_at_its_link_address() {
        let vm = FakeVm::new();
        let img = ElfBuilder::new().non_pie().build();
        let l = load_fixture(&vm, &img, 3);
        assert_eq!(l.plan.bias, 0);
        assert_eq!(l.plan.base, 0x400000);
        assert_eq!(l.plan.entry, 0x400500);
        assert_eq!(vm.read(0x400000, 4), crate::elf::ELFMAG);
    }

    #[test]
    fn read_only_segment_is_narrowed_after_zeroing() {
        let vm = FakeVm::new();
        let img = ElfBuilder::new()
            .pie_two_segment()
            .patch_phdr(0, |p| {
                p.p_flags = crate::elf::PF_R | crate::elf::PF_X;
                p.p_filesz = 0xf00;
                p.p_memsz = 0xf00;
            })
            .build();
        let l = load_fixture(&vm, &img, 3);
        let va = l.plan.base;
        // Written while writable, then narrowed: no W left, and the tail of
        // the page is clear.
        assert_eq!(vm.prot_at(va), PROT_READ | PROT_EXEC);
        assert_eq!(vm.read(va + 0xf00, 1)[0], 0);
        assert!(vm
            .ops()
            .iter()
            .any(|o| matches!(o, Op::Protect { prot, .. } if *prot == PROT_READ | PROT_EXEC)));
    }

    #[test]
    fn copy_path_loads_and_syncs_the_icache() {
        // No file mappings: the loader writes the bytes itself, so it owes
        // instruction-cache maintenance for the executable segments.
        let vm = FakeVm::new().no_files();
        let img = ElfBuilder::new().pie_two_segment().build();
        let e = Image::parse(&img.as_slice(), 4096).unwrap();
        let l = load("test", &e, &img.as_slice(), None, &vm).unwrap();

        assert_eq!(vm.read(l.plan.base, 4), crate::elf::ELFMAG);
        let syncs: Vec<_> = vm
            .ops()
            .into_iter()
            .filter(|o| matches!(o, Op::Icache { .. }))
            .collect();
        assert!(!syncs.is_empty(), "executable segment was not synced");
        match syncs[0] {
            Op::Icache { addr, len } => {
                assert!(addr <= l.plan.base);
                assert!(addr + len >= l.plan.base + 0x1000);
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn copy_path_refuses_non_pie() {
        let vm = FakeVm::new().no_files();
        let img = ElfBuilder::new().non_pie().build();
        let e = Image::parse(&img.as_slice(), 4096).unwrap();
        assert_eq!(
            load("test", &e, &img.as_slice(), None, &vm).unwrap_err(),
            Error::ENOTSUP
        );
    }

    #[test]
    fn unload_releases_the_whole_reservation() {
        let vm = FakeVm::new();
        let img = ElfBuilder::new().glibc_arm64_style().build();
        let l = load_fixture(&vm, &img, 3);
        let span = (l.plan.reserve_addr, l.plan.reserve_len);
        l.unload(&vm);
        for a in (span.0..span.0 + span.1).step_by(4096) {
            assert!(!vm.is_mapped(a), "{a:#x} survived unload");
        }
        // ...and the space is reusable.
        assert_eq!(vm.would_place(0x1000), 0x1000_0000);
    }

    #[test]
    fn two_images_do_not_overlap() {
        // Program then interpreter, the real sequence. Under the C loader the
        // second reservation could be placed in the first image's holes.
        let vm = FakeVm::new();
        let prog = ElfBuilder::new().glibc_arm64_style().build();
        let interp = ElfBuilder::new().glibc_arm64_style().build();
        let a = load_fixture(&vm, &prog, 3);
        let b = load_fixture(&vm, &interp, 4);

        let (a0, a1) = (a.plan.reserve_addr, a.plan.reserve_addr + a.plan.reserve_len);
        let (b0, b1) = (b.plan.reserve_addr, b.plan.reserve_addr + b.plan.reserve_len);
        assert!(a1 <= b0 || b1 <= a0, "images overlap: {a0:#x}..{a1:#x} and {b0:#x}..{b1:#x}");
    }

    #[test]
    fn a_failed_load_leaves_nothing_behind() {
        let vm = FakeVm::new();
        let img = ElfBuilder::new().glibc_arm64_style().build();
        let e = Image::parse(&img.as_slice(), 4096).unwrap();

        // Parse from the whole image but read contents from a truncated copy,
        // so the load fails partway through with the reservation already held.
        let short = img.bytes[..0x100].to_vec();
        assert!(load("test", &e, &short.as_slice(), None, &vm).is_err());

        // Whatever happened, no region may be left behind.
        assert!(
            vm.regions().is_empty(),
            "leaked mappings: {:#x?}",
            vm.regions()
        );
    }
}
