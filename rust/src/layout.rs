// SPDX-License-Identifier: BSD-3-Clause
//! Turning a parsed image into a concrete plan of mappings.
//!
//! This is deliberately a pure computation: given the headers, a page size and
//! a chosen base address, it produces the exact list of map/zero/protect
//! operations. Nothing here touches memory, so the interesting cases -- a
//! non-PIE at 0x400000, arm64's 64 KiB segment alignment against a 4 KiB page,
//! a `.bss` that spans whole pages, a zero-`p_filesz` segment -- are all
//! checked by `cargo test` on the host rather than by booting a unikernel.

use crate::elf::{align_down, align_up, Image, Phdr, ET_DYN};
use crate::err::{Error, Result};
use alloc::vec::Vec;

/// Protection bits, matching `ELFRS_PROT_*` in `glue/shim.h`.
pub const PROT_NONE: u32 = 0;
pub const PROT_READ: u32 = 1;
pub const PROT_WRITE: u32 = 2;
pub const PROT_EXEC: u32 = 4;

/// Upper bound on the alignment a segment may demand. 64 KiB is normal on
/// arm64; 2 MiB shows up with explicit huge-page linking. Beyond that, the
/// reservation slack would dwarf the image.
pub const MAX_SEG_ALIGN: u64 = 2 * 1024 * 1024;

/// Translate ELF segment flags into protection bits.
///
/// The C loader wrote `if (phdr->p_flags & PROT_EXEC)`, comparing segment
/// flags against an *mmap* constant: `PROT_EXEC` is 4, but `PF_X` is 1 and 4
/// is `PF_R`. Every readable segment therefore came out executable and no
/// segment's X bit was ever consulted. This is the one-line fix.
pub fn prot_of(ph: &Phdr) -> u32 {
    let mut p = PROT_NONE;
    if ph.is_read() {
        p |= PROT_READ;
    }
    if ph.is_write() {
        p |= PROT_WRITE;
    }
    if ph.is_exec() {
        p |= PROT_EXEC;
    }
    p
}

/// A file-backed piece of a segment. `addr` and `off` are both page-aligned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileMap {
    pub addr: u64,
    pub len: u64,
    pub off: u64,
}

/// An anonymous piece of a segment: whole pages of `.bss` past the end of the
/// file-backed part.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AnonMap {
    pub addr: u64,
    pub len: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SegmentPlan {
    /// Index into `Image::phdrs`.
    pub idx: usize,
    pub file: Option<FileMap>,
    /// Bytes to clear between the end of file data and the end of its last
    /// page. Without this the tail of the page holds whatever followed the
    /// segment in the file.
    pub zero: Option<AnonMap>,
    pub anon: Option<AnonMap>,
    /// Protection to apply once the contents are in place.
    pub prot: u32,
    /// Whether the file mapping has to be created writable so `zero` can be
    /// applied, and then narrowed. The C loader skipped zeroing entirely for
    /// non-writable segments, leaving stale file bytes visible.
    pub needs_write_window: bool,
}

impl SegmentPlan {
    /// Whole address range this segment occupies once mapped.
    pub fn range(&self) -> (u64, u64) {
        let start = self
            .file
            .map(|f| f.addr)
            .or_else(|| self.anon.map(|a| a.addr))
            .unwrap_or(0);
        let end = self
            .anon
            .map(|a| a.addr + a.len)
            .or_else(|| self.file.map(|f| f.addr + f.len))
            .unwrap_or(start);
        (start, end)
    }
}

/// Where the image goes, and what to do once it is there.
#[derive(Clone, Debug)]
pub struct LoadPlan {
    /// Added to every `p_vaddr`. Zero for `ET_EXEC`.
    pub bias: u64,
    /// Lowest address of the reservation, and its length. The reservation is
    /// held for the whole life of the image.
    pub reserve_addr: u64,
    pub reserve_len: u64,
    /// Lowest and highest address actually covered by segments.
    pub base: u64,
    pub end: u64,
    pub align: u64,
    pub segments: Vec<SegmentPlan>,
    pub entry: u64,
}

/// How the caller wants the image placed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Placement {
    /// Non-PIE: the image dictates its own address.
    Fixed,
    /// PIE: `base` was chosen by the system (already aligned to `align`).
    At(u64),
}

/// Size of the anonymous reservation a PIE needs so that an `align`-aligned
/// base can be carved out of it.
///
/// The reservation is *kept*, not unmapped and re-mapped. That difference is
/// the point: Unikraft's `uk_vma_map()` picks addresses first-fit from the
/// mapping base, so any window in which the range is free is a window in which
/// an unrelated `mmap(NULL, ...)` -- the interpreter's own reservation, a
/// thread stack, a malloc arena -- can be placed inside the image.
pub fn reservation_len(image: &Image, page_size: u64) -> Result<u64> {
    let (lo, hi) = image.va_span(page_size)?;
    let align = seg_align(image, page_size);
    hi.checked_sub(lo)
        .and_then(|span| span.checked_add(align - page_size))
        .ok_or(Error::ENOEXEC)
}

pub fn seg_align(image: &Image, page_size: u64) -> u64 {
    image.load_align(page_size).min(MAX_SEG_ALIGN).max(page_size)
}

/// Build the plan.
///
/// `raw_base` is the address returned for the reservation (unaligned, as the
/// system chose it) for `Placement::At`; the plan aligns up within it.
pub fn plan(image: &Image, page_size: u64, placement: Placement) -> Result<LoadPlan> {
    let (va_lo, va_hi) = image.va_span(page_size)?;
    let align = seg_align(image, page_size);
    let span = va_hi - va_lo;

    let (bias, reserve_addr, reserve_len) = match placement {
        Placement::Fixed => {
            if image.ehdr.e_type == ET_DYN {
                // A PIE can be placed anywhere; asking for Fixed means the
                // caller wants it at its link address, which is legal but
                // only makes sense for va_lo != 0.
            }
            (0u64, va_lo, span)
        }
        Placement::At(raw) => {
            let base = align_up(raw, align).ok_or(Error::ENOMEM)?;
            let bias = base
                .checked_sub(va_lo)
                .ok_or(Error::ENOMEM)?;
            (bias, raw, span + (align - page_size))
        }
    };

    let base = va_lo + bias;
    let end = va_hi + bias;

    let mut segments = Vec::new();
    segments
        .try_reserve(image.loads.len())
        .map_err(|_| Error::ENOMEM)?;

    for &i in &image.loads {
        let ph = &image.phdrs[i];
        let prot = prot_of(ph);
        let vaddr = ph.p_vaddr.checked_add(bias).ok_or(Error::ENOMEM)?;
        let mstart = align_down(vaddr, page_size);
        let fdelta = vaddr - mstart;

        let mem_end = align_up(vaddr + ph.p_memsz, page_size).ok_or(Error::ENOMEM)?;

        let (file, zero, file_end) = if ph.p_filesz > 0 {
            let fend = vaddr + ph.p_filesz;
            let fmap_end = align_up(fend, page_size).ok_or(Error::ENOMEM)?;
            let f = FileMap {
                addr: mstart,
                len: fmap_end - mstart,
                off: ph.p_offset - fdelta,
            };
            let z = if fmap_end > fend {
                Some(AnonMap {
                    addr: fend,
                    len: fmap_end - fend,
                })
            } else {
                None
            };
            (Some(f), z, fmap_end)
        } else {
            (None, None, mstart)
        };

        let anon = if mem_end > file_end {
            Some(AnonMap {
                addr: file_end,
                len: mem_end - file_end,
            })
        } else {
            None
        };

        let needs_write_window = zero.is_some() && (prot & PROT_WRITE) == 0;

        segments.push(SegmentPlan {
            idx: i,
            file,
            zero,
            anon,
            prot,
            needs_write_window,
        });
    }

    let entry = image.ehdr.e_entry.checked_add(bias).ok_or(Error::ENOMEM)?;

    Ok(LoadPlan {
        bias,
        reserve_addr,
        reserve_len,
        base,
        end,
        align,
        segments,
        entry,
    })
}

impl LoadPlan {
    /// Address at which the program header table is visible to the loaded
    /// program, for `AT_PHDR`.
    ///
    /// `PT_PHDR` is authoritative when present. Otherwise the table has to be
    /// found inside a `PT_LOAD`, which is what the C loader did -- but it
    /// asserted the result was non-zero rather than reporting the (real, if
    /// unusual) case of an image whose headers are not mapped at all.
    pub fn phdr_addr(&self, image: &Image) -> Option<u64> {
        if let Some(ph) = image.phdr_seg {
            // Trust PT_PHDR only if it actually falls inside a PT_LOAD;
            // a stale PT_PHDR from a stripped-down linker script does not.
            let addr = ph.p_vaddr.checked_add(self.bias)?;
            if self.covers(addr) {
                return Some(addr);
            }
        }
        let phoff = image.ehdr.e_phoff;
        for &i in &image.loads {
            let l = &image.phdrs[i];
            if phoff >= l.p_offset && phoff < l.p_offset.checked_add(l.p_filesz)? {
                return (phoff - l.p_offset)
                    .checked_add(l.p_vaddr)?
                    .checked_add(self.bias);
            }
        }
        None
    }

    fn covers(&self, addr: u64) -> bool {
        addr >= self.base && addr < self.end
    }

    /// Ranges that hold executable code, for instruction-cache maintenance.
    pub fn exec_ranges(&self, image: &Image) -> impl Iterator<Item = (u64, u64)> + '_ {
        let phdrs = image.phdrs.clone();
        self.segments
            .clone()
            .into_iter()
            .filter(move |s| phdrs[s.idx].is_exec())
            .map(|s| {
                let (a, b) = s.range();
                (a, b - a)
            })
            .collect::<Vec<_>>()
            .into_iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elf::{Image, PF_R, PF_W, PF_X};
    use crate::testutil::*;

    fn parse(img: &TestImage) -> Image {
        Image::parse(&img.as_slice(), 4096).unwrap()
    }

    #[test]
    fn prot_bits_follow_pf_flags_not_prot_constants() {
        let mut ph = Phdr::default();
        ph.p_flags = PF_R | PF_X;
        assert_eq!(prot_of(&ph), PROT_READ | PROT_EXEC);
        ph.p_flags = PF_R | PF_W;
        // The regression the C loader had: a RW data segment came out
        // executable because PF_R (4) happens to equal PROT_EXEC (4).
        assert_eq!(prot_of(&ph), PROT_READ | PROT_WRITE);
        assert_eq!(prot_of(&ph) & PROT_EXEC, 0);
        ph.p_flags = 0;
        assert_eq!(prot_of(&ph), PROT_NONE);
    }

    #[test]
    fn pie_is_biased_to_the_chosen_base() {
        let img = parse(&ElfBuilder::new().pie_two_segment().build());
        let p = plan(&img, 4096, Placement::At(0x1000_0000)).unwrap();
        assert_eq!(p.bias, 0x1000_0000);
        assert_eq!(p.base, 0x1000_0000);
        assert_eq!(p.entry, img.ehdr.e_entry + 0x1000_0000);
    }

    #[test]
    fn non_pie_keeps_its_link_address() {
        let img = parse(&ElfBuilder::new().non_pie().build());
        let p = plan(&img, 4096, Placement::Fixed).unwrap();
        assert_eq!(p.bias, 0);
        assert_eq!(p.base, 0x400000);
        assert_eq!(p.entry, img.ehdr.e_entry);
        // And, crucially, the reservation covers only the image -- not
        // everything from address zero. `valen = PAGE_ALIGN_UP(upperl)` in the
        // C loader ignored the lower bound, so a non-PIE would have reserved
        // its link address plus its size from zero.
        assert!(
            p.reserve_len < 0x400000,
            "reservation {:#x} should not span from zero",
            p.reserve_len
        );
    }

    #[test]
    fn reservation_absorbs_alignment_slack() {
        let img = parse(&ElfBuilder::new().glibc_arm64_style().build());
        let need = reservation_len(&img, 4096).unwrap();
        let (lo, hi) = img.va_span(4096).unwrap();
        assert_eq!(need, (hi - lo) + 0x10000 - 0x1000);

        // A base that is already 64K-aligned wastes nothing at the front, but
        // the reservation still runs to the end so nothing can be placed in
        // the tail.
        let p = plan(&img, 4096, Placement::At(0x2000_0000)).unwrap();
        assert_eq!(p.bias, 0x2000_0000);
        assert_eq!(p.reserve_addr, 0x2000_0000);
        assert_eq!(p.reserve_len, need);
        assert!(p.reserve_addr + p.reserve_len >= p.end);
    }

    #[test]
    fn unaligned_reservation_base_is_rounded_up() {
        let img = parse(&ElfBuilder::new().glibc_arm64_style().build());
        let p = plan(&img, 4096, Placement::At(0x2000_1000)).unwrap();
        assert_eq!(p.base, 0x2001_0000);
        assert_eq!(p.reserve_addr, 0x2000_1000);
        // The slack at the front stays reserved rather than being handed back.
        assert!(p.reserve_addr < p.base);
        assert!(p.reserve_addr + p.reserve_len >= p.end);
    }

    #[test]
    fn bss_is_split_into_a_zeroed_tail_and_anonymous_pages() {
        // filesz 0x4908, memsz 0x112a0 -- the shape of glibc's data segment.
        let img = parse(&ElfBuilder::new().glibc_arm64_style().build());
        let p = plan(&img, 4096, Placement::At(0x1000_0000)).unwrap();
        let data = p
            .segments
            .iter()
            .find(|s| img.phdrs[s.idx].is_write())
            .unwrap();

        let ph = &img.phdrs[data.idx];
        let vaddr = ph.p_vaddr + p.bias;
        let fend = vaddr + ph.p_filesz;

        let z = data.zero.expect("partial page past filesz must be cleared");
        assert_eq!(z.addr, fend);
        assert_eq!(z.addr + z.len, align_up(fend, 4096).unwrap());

        let a = data.anon.expect("whole bss pages must be anonymous");
        assert_eq!(a.addr, align_up(fend, 4096).unwrap());
        assert_eq!(a.addr + a.len, align_up(vaddr + ph.p_memsz, 4096).unwrap());

        // The file mapping stops at a page boundary and never covers bss.
        let f = data.file.unwrap();
        assert_eq!(f.addr % 4096, 0);
        assert_eq!(f.off % 4096, 0);
        assert_eq!(f.addr + f.len, align_up(fend, 4096).unwrap());
    }

    #[test]
    fn read_only_segment_with_bss_gets_a_write_window() {
        // Rare but legal, and the case the C loader silently skipped. The
        // segment has to end mid-page for there to be a tail worth clearing.
        let img = parse(
            &ElfBuilder::new()
                .pie_two_segment()
                .patch_phdr(0, |p| {
                    p.p_flags = PF_R | PF_X;
                    p.p_filesz = 0xf00;
                    p.p_memsz = 0x1100;
                })
                .build(),
        );
        let p = plan(&img, 4096, Placement::At(0x1000_0000)).unwrap();
        let s = &p.segments[0];
        assert!(s.zero.is_some());
        assert!(s.needs_write_window);
        assert_eq!(s.prot, PROT_READ | PROT_EXEC);
    }

    #[test]
    fn zero_filesz_segment_is_entirely_anonymous() {
        let img = parse(
            &ElfBuilder::new()
                .pie_two_segment()
                .patch_phdr(1, |p| {
                    p.p_filesz = 0;
                    p.p_memsz = 0x3000;
                })
                .build(),
        );
        let p = plan(&img, 4096, Placement::At(0x1000_0000)).unwrap();
        let s = p.segments.iter().find(|s| s.idx == 1).unwrap();
        assert!(s.file.is_none());
        assert!(s.zero.is_none());
        let a = s.anon.unwrap();
        assert_eq!(a.len, 0x3000);
    }

    #[test]
    fn file_mapping_offset_stays_congruent_for_unaligned_vaddr() {
        // A segment starting mid-page: the mapping has to begin at the page
        // below, with the file offset shifted by the same amount, or the
        // contents land at the wrong address.
        let img = parse(&ElfBuilder::new().unaligned_second_segment().build());
        let p = plan(&img, 4096, Placement::At(0x1000_0000)).unwrap();
        for s in &p.segments {
            if let Some(f) = s.file {
                let ph = &img.phdrs[s.idx];
                assert_eq!(f.addr % 4096, 0);
                assert_eq!(f.off % 4096, 0);
                // The byte at p_offset must land exactly at p_vaddr + bias.
                assert_eq!(f.addr + (ph.p_offset - f.off), ph.p_vaddr + p.bias);
            }
        }
    }

    #[test]
    fn segments_never_overlap_in_the_plan() {
        for img in [
            ElfBuilder::new().pie_two_segment().build(),
            ElfBuilder::new().glibc_arm64_style().build(),
            ElfBuilder::new().non_pie().build(),
            ElfBuilder::new().four_segment_separate_code().build(),
        ] {
            let e = parse(&img);
            let placement = if e.is_pie() {
                Placement::At(0x1000_0000)
            } else {
                Placement::Fixed
            };
            let p = plan(&e, 4096, placement).unwrap();
            let mut ranges: Vec<(u64, u64)> = p.segments.iter().map(|s| s.range()).collect();
            ranges.sort();
            for w in ranges.windows(2) {
                assert!(
                    w[0].1 <= w[1].0,
                    "segments overlap: {:#x?} then {:#x?}",
                    w[0],
                    w[1]
                );
            }
            // Everything the plan maps lies inside the reservation.
            for (a, b) in ranges {
                assert!(a >= p.reserve_addr, "{a:#x} below reservation");
                assert!(b <= p.reserve_addr + p.reserve_len, "{b:#x} past reservation");
            }
        }
    }

    #[test]
    fn phdr_addr_prefers_pt_phdr_then_falls_back() {
        let img = parse(&ElfBuilder::new().glibc_arm64_style().build());
        let p = plan(&img, 4096, Placement::At(0x1000_0000)).unwrap();
        let pt_phdr = img.phdr_seg.unwrap();
        assert_eq!(p.phdr_addr(&img), Some(pt_phdr.p_vaddr + p.bias));

        // Without PT_PHDR the table is located through the covering PT_LOAD,
        // and must come out at the same address.
        let img2 = parse(&ElfBuilder::new().glibc_arm64_style().drop_pt_phdr().build());
        let p2 = plan(&img2, 4096, Placement::At(0x1000_0000)).unwrap();
        assert_eq!(p2.phdr_addr(&img2), Some(img2.ehdr.e_phoff + p2.bias));
    }

    #[test]
    fn exec_ranges_cover_only_executable_segments() {
        let img = parse(&ElfBuilder::new().four_segment_separate_code().build());
        let p = plan(&img, 4096, Placement::At(0x1000_0000)).unwrap();
        let ranges: Vec<_> = p.exec_ranges(&img).collect();
        assert_eq!(ranges.len(), 1);
        let x = img
            .loads
            .iter()
            .map(|&i| &img.phdrs[i])
            .find(|ph| ph.is_exec())
            .unwrap();
        assert!(ranges[0].0 <= x.p_vaddr + p.bias);
        assert!(ranges[0].0 + ranges[0].1 >= x.p_vaddr + p.bias + x.p_memsz);
    }
}
