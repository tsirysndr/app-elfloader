# app-elfloader-rs

A Rust rewrite of Unikraft's [app-elfloader](https://github.com/unikraft/app-elfloader):
the unikernel that loads an unmodified Linux ELF executable, side-loads its
dynamic linker, and starts it.

It is a drop-in replacement. The Kconfig surface is deliberately identical, so
an existing Kraftfile or defconfig needs no changes — with one subtraction:
`lib-libelf` is no longer a dependency, because the loader parses ELF itself.

```sh
make test        # the loader's own tests, on your machine — no Unikraft needed
```

## Why

The C loader worked on x86_64 and did not work on arm64, and the reasons were
hard to see because almost everything it did was correct for the one case it
was exercised against: a position-independent, page-aligned, x86_64 binary. The
rewrite is about the cases that are *not* that — 64 KiB segment alignment over
a 4 KiB page, non-PIE, an image whose headers say something the file cannot
back up — and about making them checkable without booting a unikernel.

## What is different

Each of these is a behaviour change, not a translation. The tests named in the
right-hand column are the ones that pin it.

| | | |
|---|---|---|
| **The image's address range is never left unreserved.** The C loader sized a scratch mapping, `munmap`'d it, then mapped each segment into the address it had been handed. Unikraft's `uk_vma_map()` picks addresses *first-fit from a fixed base* (`vmem_first_fit`), so every moment the range was free — and every inter-segment gap, permanently — was an opportunity for an unrelated `mmap(NULL, …)` to be placed inside the program image. Here the reservation is taken once as `PROT_NONE` and each segment is mapped into it with `MAP_FIXED`. | `loader.rs` | `image_range_is_never_left_unreserved`, `a_later_anonymous_mapping_cannot_land_inside_the_image` |
| **Segment protections follow `PF_*`.** The C loader wrote `if (phdr->p_flags & PROT_EXEC)`, testing ELF segment flags against an *mmap* constant. `PROT_EXEC` is 4, but `PF_X` is 1 and 4 is `PF_R`, so every readable segment came out executable and no segment's X bit was ever consulted. | `layout.rs` | `prot_bits_follow_pf_flags_not_prot_constants`, `final_protections_match_the_segment_flags` |
| **Non-PIE (`ET_EXEC`) loads.** The C loader rejected anything that was not `ET_DYN`. It also computed the image length as `PAGE_ALIGN_UP(highest vaddr)`, ignoring the lowest — so a binary linked at `0x400000` would have reserved its link address *plus* its size, from zero. | `layout.rs` | `non_pie_keeps_its_link_address`, `non_pie_loads_at_its_link_address` |
| **`.bss` is cleared even in a read-only segment.** The C loader zeroed the tail of the last file page only when the segment was writable, leaving whatever followed the segment in the file visible to the program. Here the mapping is made writable for as long as the clearing takes and then narrowed. | `loader.rs` | `read_only_segment_is_narrowed_after_zeroing`, `bss_tail_is_zeroed_and_file_bytes_do_not_leak` |
| **`AT_BASE` is the interpreter's load bias**, not the address of its first mapped segment. Those coincide only while the first `PT_LOAD` has `p_vaddr == 0`, which every shipped dynamic linker does and nothing guarantees. | `program.rs` | `at_base_is_the_interpreter_bias_not_its_first_segment` |
| **`AT_RANDOM` points into the application's own stack.** The C loader pointed it at a local variable of its `main()`; in the binfmt path that function returned before the application ever read it, so glibc's stack canary and pointer-mangling key came out of a dead kernel stack frame. | `auxv.rs` | `at_random_points_at_sixteen_readable_bytes_on_the_stack` |
| **`AT_HWCAP` describes the machine.** The C loader passed 0. glibc and OpenSSL both dispatch on it, so zero means node uses the generic AES and SHA paths on a CPU that has the instructions. Now derived from `ID_AA64ISAR0_EL1`, and gated on `CONFIG_FPSIMD` — advertising SIMD features while FP/SIMD is trapped would turn a slow path into a crash. | `glue/shim.c` | — |
| **`AT_PAGESZ` is the real page size** rather than a hard-coded 4096, and `AT_PHDR` prefers `PT_PHDR` before falling back to the covering `PT_LOAD`. `AT_PHDR`/`PHENT`/`PHNUM` are omitted entirely when the headers are not mapped, instead of being reported as 0 — musl treats a present-but-null `AT_PHDR` as a valid pointer. | `auxv.rs`, `layout.rs` | `omits_phdr_entries_when_the_headers_are_not_mapped`, `phdr_addr_prefers_pt_phdr_then_falls_back` |
| **The stack cannot be overrun.** Every write is bounds-checked, and the size policy counts NUL terminators and the pointer arrays — the C version summed `strlen()` only, so a large number of short environment variables could pass the check and still not fit. | `auxv.rs` | `oversized_environment_is_rejected_not_overflowed`, `size_check_counts_terminators_and_pointers` |
| **Headers are validated against the file.** `p_offset + p_filesz` past the end, `p_filesz > p_memsz`, `p_vaddr + p_memsz` overflowing, overlapping `PT_LOAD`s, a `p_vaddr`/`p_offset` pair that is not page-congruent (which cannot be produced by one `mmap`, and which the C loader mapped anyway, shifted) — all rejected before anything is mapped. `PT_INTERP` is read through the normal file interface rather than through libelf's private `e_rawfile`, which is only populated for in-memory images and was a dangling read from the `elf_open(fd)` path. | `elf.rs` | 13 rejection tests |
| **arm64 instruction-cache maintenance.** Instruction and data caches are not coherent on arm64: code written through the data side is not visible to instruction fetch until it has been cleaned to the point of unification and the I-cache invalidated. The loader now does this for anything it writes itself. The demand-paging path needs the same thing one level down, in Unikraft — see below. | `glue/shim.c`, `loader.rs` | `copy_path_loads_and_syncs_the_icache` |
| **An executable-stack request is refused** rather than silently ignored. Unikraft's thread stacks are not executable and cannot be made so. | `loader.rs` | `an_executable_stack_request_is_refused` |
| **`CONFIG_APPELFLOADER_DEBUG` actually prints.** The kernel log level is a Kconfig `choice`, which a Kraftfile cannot set, so it sits at `KLVL_ERR` and filtered every message the option enabled. Loader messages are now forced through when the option is on. | `glue/shim.c` | — |

Two Unikraft-side fixes go with this; they live in bsdkrun's
`library/unikraft-base/patches/apply.sh` because they are not this repository's
to make:

* `invalidate_icache_range()` invalidated the I-cache *before* cleaning the
  D-cache for the same line, and strode by the I-cache line size while doing
  both. Both halves are wrong for publishing new code.
* `ukvmem` never did any I-cache maintenance when it populated a page, so
  demand-paged `.text` could be fetched stale from whatever previously occupied
  the physical frame. Linux does this in `set_pte_at()`.

## Layout

| | |
|---|---|
| `rust/src/elf.rs` | bounds-checked ELF64 header parsing |
| `rust/src/layout.rs` | headers → a concrete plan of mappings |
| `rust/src/loader.rs` | executes a plan against a `Vm` |
| `rust/src/auxv.rs` | builds the initial stack (argv/envp/auxv) |
| `rust/src/program.rs` | program + interpreter, and the auxv they imply |
| `rust/src/sys.rs` | the Unikraft implementations of those traits |
| `rust/src/app.rs` | the `main()` the unikernel boots into |
| `rust/src/binfmt.rs` | `libukbinfmt` registration, for `execve` |
| `glue/shim.c` | the only C: everything Unikraft exposes as a macro, a `static inline` or a struct layout |

The split is the point. Everything that decides *what* to map is pure and runs
under `cargo test` on a developer machine, against a model address space that
reproduces Unikraft's first-fit placement. The cases that are painful to reach
by booting a unikernel — a non-PIE at its link address, 64 KiB segment
alignment over a 4 KiB page, a truncated or hostile header, an interpreter with
a non-zero first `p_vaddr` — are covered there.

`glue/shim.c` exists so that no Rust code encodes a Unikraft struct offset. A
Unikraft API change is then a compile error in that file, at the line that uses
it, rather than a silently wrong offset at run time.

## Building

The Rust core is a `no_std` staticlib for `aarch64-unknown-none-softfloat` or
`x86_64-unknown-none` — bare-metal targets, because Unikraft compiles kernel
code without FP/SIMD (`-mgeneral-regs-only` on arm64, `-mno-sse` on x86_64) and
those targets match that ABI. `Makefile.uk` drives `cargo` and hands Unikraft
the archive through `ALIBS-y`; the crate has no dependencies, so the build is
offline.

You need `cargo` on the machine that runs the Unikraft build. `Makefile.uk`
fails with an install hint if it is missing.

## Status

**x86_64**: builds and boots.

**arm64**: builds and boots, and dynamically linked C and C++ programs run.

Getting there turned up two arm64 bugs in Unikraft, neither of them in the
loader — the C `app-elfloader` failed identically:

* **`struct stat` is the x86_64 layout on every architecture.** vfscore's
  `vn_stat()` does `memset(st, 0, sizeof(struct stat))` on the application's
  buffer, and Unikraft's definition is 144 bytes where arm64 uses 128, so every
  `stat()`/`fstat()` overwrote 16 bytes past the end of it. In musl's
  `load_library()` that is the saved frame pointer and return address, so any
  binary loading a second shared object returned to address 0.

* **The arm64 signal trampoline has never assembled** — it uses SP as an
  operand of `AND` — so `CONFIG_LIBPOSIX_PROCESS_SIGNAL` could not be enabled
  and no CPU fault reached the application as a signal.

Both fixes live in bsdkrun's `library/unikraft-base/patches/apply.sh`. node now
reaches OpenSSL's SM3 probe, which executes an undefined instruction on purpose
and expects `SIGILL`; that hits a third gap in the same arm64 signal path. See
`../bsdkrun/examples/unikraft-expressjs/repro/README.md`.
