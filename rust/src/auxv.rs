// SPDX-License-Identifier: BSD-3-Clause
//! Building the initial process stack: argv, envp and the auxiliary vector.
//!
//! Laid out the way Linux lays it out, because that is what every libc's
//! start-up code assumes:
//!
//! ```text
//!   high ┌───────────────────────────┐
//!        │ strings: platform, random,│
//!        │ execfn, envp[], argv[]    │
//!        ├───────────────────────────┤
//!        │ padding to 16 bytes       │
//!        ├───────────────────────────┤
//!        │ AT_NULL                   │
//!        │ auxv[n-1] … auxv[0]       │
//!        │ NULL                      │
//!        │ envp[m-1] … envp[0]       │
//!        │ NULL                      │
//!        │ argv[k-1] … argv[0]       │
//!    sp →│ argc                      │  (16-byte aligned)
//!   low  └───────────────────────────┘
//! ```
//!
//! Every write is bounds-checked against the bottom of the stack, so an
//! oversized environment fails with `E2BIG` instead of walking off the end.

use crate::err::{Error, Result};
use alloc::vec::Vec;

pub const AT_NULL: u64 = 0;
pub const AT_IGNORE: u64 = 1;
pub const AT_EXECFD: u64 = 2;
pub const AT_PHDR: u64 = 3;
pub const AT_PHENT: u64 = 4;
pub const AT_PHNUM: u64 = 5;
pub const AT_PAGESZ: u64 = 6;
pub const AT_BASE: u64 = 7;
pub const AT_FLAGS: u64 = 8;
pub const AT_ENTRY: u64 = 9;
pub const AT_NOTELF: u64 = 10;
pub const AT_UID: u64 = 11;
pub const AT_EUID: u64 = 12;
pub const AT_GID: u64 = 13;
pub const AT_EGID: u64 = 14;
pub const AT_PLATFORM: u64 = 15;
pub const AT_HWCAP: u64 = 16;
pub const AT_CLKTCK: u64 = 17;
pub const AT_SECURE: u64 = 23;
pub const AT_BASE_PLATFORM: u64 = 24;
pub const AT_RANDOM: u64 = 25;
pub const AT_HWCAP2: u64 = 26;
pub const AT_EXECFN: u64 = 31;
pub const AT_SYSINFO: u64 = 32;
pub const AT_SYSINFO_EHDR: u64 = 33;
pub const AT_MINSIGSTKSZ: u64 = 51;

/// POSIX's floor for the combined size of arguments and environment.
pub const ARG_MAX: usize = 4096 * 32;

pub const SP_ALIGN: u64 = 16;

/// Somewhere to put the stack. Abstracted so the layout can be built and
/// inspected on the host; on the unikernel it writes straight into the
/// application thread's stack.
pub trait StackWriter {
    /// One past the highest writable address.
    fn top(&self) -> u64;
    /// Lowest writable address.
    fn bottom(&self) -> u64;
    fn write(&mut self, addr: u64, data: &[u8]) -> Result<()>;
}

/// Everything that goes into the auxiliary vector.
#[derive(Clone, Debug)]
pub struct AuxvSpec<'a> {
    pub phdr: Option<u64>,
    pub phent: u64,
    pub phnum: u64,
    /// Load bias of the program interpreter, or 0 when there is none. This is
    /// a *bias*, not the address of the interpreter's first segment: the C
    /// loader passed `interp->start`, which happens to coincide only because
    /// every real dynamic linker has `p_vaddr == 0` on its first PT_LOAD.
    pub base: u64,
    pub entry: u64,
    pub pagesz: u64,
    pub uid: u64,
    pub gid: u64,
    pub hwcap: u64,
    pub hwcap2: u64,
    pub clktck: u64,
    pub secure: bool,
    /// 16 bytes of entropy. glibc takes the stack canary from the first 8 and
    /// the pointer-mangling key from the next 8.
    pub random: [u8; 16],
    pub platform: &'a [u8],
    pub execfn: &'a [u8],
    pub sysinfo_ehdr: Option<u64>,
    pub minsigstksz: Option<u64>,
}

impl Default for AuxvSpec<'_> {
    fn default() -> Self {
        AuxvSpec {
            phdr: None,
            phent: 0,
            phnum: 0,
            base: 0,
            entry: 0,
            pagesz: 4096,
            uid: 0,
            gid: 0,
            hwcap: 0,
            hwcap2: 0,
            clktck: 100,
            secure: false,
            random: [0; 16],
            platform: b"",
            execfn: b"",
            sysinfo_ehdr: None,
            minsigstksz: None,
        }
    }
}

/// The result of laying out a stack.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StackLayout {
    /// Value the entry point must be entered with.
    pub sp: u64,
    /// Address of the `argc` word, i.e. the same thing. Kept separate for
    /// readability at the call site.
    pub argc_at: u64,
    /// Lowest address written.
    pub low_water: u64,
}

/// Reject an argument/environment block that would eat the stack.
///
/// Linux's rule (see `execve(2)`) is a quarter of the stack, with a floor of
/// `ARG_MAX`. Unlike the C version this counts the NUL terminators and the
/// pointer arrays, which is what actually gets written.
pub fn check_arg_env_size(
    argv: &[&[u8]],
    envp: &[&[u8]],
    stack_size: u64,
) -> Result<usize> {
    let mut len: usize = 0;
    for s in argv.iter().chain(envp.iter()) {
        len = len
            .checked_add(s.len() + 1)
            .and_then(|l| l.checked_add(core::mem::size_of::<u64>()))
            .ok_or(Error::E2BIG)?;
    }
    let budget = core::cmp::max(ARG_MAX as u64, stack_size / 4);
    if len as u64 > budget {
        return Err(Error::E2BIG);
    }
    Ok(len)
}

fn align_down(v: u64, a: u64) -> u64 {
    v & !(a - 1)
}

struct Pusher<'w, W: StackWriter> {
    w: &'w mut W,
    sp: u64,
}

impl<W: StackWriter> Pusher<'_, W> {
    fn push_bytes(&mut self, data: &[u8]) -> Result<u64> {
        let n = data.len() as u64;
        self.sp = self.sp.checked_sub(n).ok_or(Error::E2BIG)?;
        if self.sp < self.w.bottom() {
            return Err(Error::E2BIG);
        }
        self.w.write(self.sp, data)?;
        Ok(self.sp)
    }

    /// Push a NUL-terminated copy of `s`, returning its address.
    fn push_cstr(&mut self, s: &[u8]) -> Result<u64> {
        self.push_bytes(&[0])?;
        if s.is_empty() {
            return Ok(self.sp);
        }
        self.push_bytes(s)
    }

    fn align(&mut self, a: u64) {
        self.sp = align_down(self.sp, a);
    }
}

/// Lay out the initial stack.
///
/// `argv` is the complete argument vector, `argv[0]` included.
pub fn build_stack<W: StackWriter>(
    w: &mut W,
    argv: &[&[u8]],
    envp: &[&[u8]],
    aux: &AuxvSpec<'_>,
) -> Result<StackLayout> {
    let stack_size = w.top() - w.bottom();
    check_arg_env_size(argv, envp, stack_size)?;

    let mut p = Pusher {
        sp: align_down(w.top(), SP_ALIGN),
        w,
    };

    // --- strings and other blobs, highest first ---

    let platform_at = if aux.platform.is_empty() {
        None
    } else {
        Some(p.push_cstr(aux.platform)?)
    };

    let execfn_at = Some(p.push_cstr(aux.execfn)?);

    // 16-byte aligned purely so the libc's 8-byte loads out of it are aligned;
    // Linux makes no such promise, but nothing depends on it being unaligned.
    p.align(SP_ALIGN);
    let random_at = p.push_bytes(&aux.random)?;

    let mut envp_at = Vec::new();
    envp_at.try_reserve(envp.len()).map_err(|_| Error::ENOMEM)?;
    for s in envp.iter().rev() {
        envp_at.push(p.push_cstr(s)?);
    }
    envp_at.reverse();

    let mut argv_at = Vec::new();
    argv_at.try_reserve(argv.len()).map_err(|_| Error::ENOMEM)?;
    for s in argv.iter().rev() {
        argv_at.push(p.push_cstr(s)?);
    }
    argv_at.reverse();

    // --- auxiliary vector ---

    let mut av: Vec<(u64, u64)> = Vec::new();
    let mut put = |k: u64, v: u64| av.push((k, v));

    if let Some(a) = aux.phdr {
        put(AT_PHDR, a);
        put(AT_PHENT, aux.phent);
        put(AT_PHNUM, aux.phnum);
    }
    put(AT_PAGESZ, aux.pagesz);
    put(AT_BASE, aux.base);
    put(AT_FLAGS, 0);
    put(AT_ENTRY, aux.entry);
    put(AT_UID, aux.uid);
    put(AT_EUID, aux.uid);
    put(AT_GID, aux.gid);
    put(AT_EGID, aux.gid);
    put(AT_SECURE, aux.secure as u64);
    put(AT_CLKTCK, aux.clktck);
    put(AT_HWCAP, aux.hwcap);
    put(AT_HWCAP2, aux.hwcap2);
    put(AT_RANDOM, random_at);
    if let Some(a) = platform_at {
        put(AT_PLATFORM, a);
    }
    if let Some(a) = execfn_at {
        put(AT_EXECFN, a);
    }
    if let Some(v) = aux.sysinfo_ehdr {
        put(AT_SYSINFO_EHDR, v);
    }
    if let Some(v) = aux.minsigstksz {
        put(AT_MINSIGSTKSZ, v);
    }
    put(AT_NULL, 0);

    // --- the pointer block, written low-to-high from the final sp ---

    let block = (1 + argv.len() + 1 + envp.len() + 1) * 8 + av.len() * 16;
    let sp = align_down(
        p.sp.checked_sub(block as u64).ok_or(Error::E2BIG)?,
        SP_ALIGN,
    );
    if sp < p.w.bottom() {
        return Err(Error::E2BIG);
    }

    let mut at = sp;
    let word = |w: &mut W, at: &mut u64, v: u64| -> Result<()> {
        w.write(*at, &v.to_le_bytes())?;
        *at += 8;
        Ok(())
    };

    word(p.w, &mut at, argv.len() as u64)?;
    for a in &argv_at {
        word(p.w, &mut at, *a)?;
    }
    word(p.w, &mut at, 0)?;
    for a in &envp_at {
        word(p.w, &mut at, *a)?;
    }
    word(p.w, &mut at, 0)?;
    for (k, v) in &av {
        word(p.w, &mut at, *k)?;
        word(p.w, &mut at, *v)?;
    }

    debug_assert_eq!(at, sp + block as u64);
    debug_assert_eq!(sp % SP_ALIGN, 0);

    Ok(StackLayout {
        sp,
        argc_at: sp,
        low_water: sp,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::FakeStack;

    /// Read back a laid-out stack the way a libc start-up would.
    struct Parsed {
        argv: Vec<Vec<u8>>,
        envp: Vec<Vec<u8>>,
        auxv: Vec<(u64, u64)>,
    }

    fn parse(s: &FakeStack, sp: u64) -> Parsed {
        let argc = s.u64_at(sp) as usize;
        let mut at = sp + 8;
        let mut argv = Vec::new();
        for _ in 0..argc {
            argv.push(s.cstr_at(s.u64_at(at)));
            at += 8;
        }
        assert_eq!(s.u64_at(at), 0, "argv is not NULL-terminated");
        at += 8;

        let mut envp = Vec::new();
        while s.u64_at(at) != 0 {
            envp.push(s.cstr_at(s.u64_at(at)));
            at += 8;
        }
        at += 8;

        let mut auxv = Vec::new();
        loop {
            let k = s.u64_at(at);
            let v = s.u64_at(at + 8);
            at += 16;
            if k == AT_NULL {
                break;
            }
            auxv.push((k, v));
        }
        Parsed { argv, envp, auxv }
    }

    fn get(p: &Parsed, key: u64) -> Option<u64> {
        p.auxv.iter().find(|(k, _)| *k == key).map(|(_, v)| *v)
    }

    fn spec() -> AuxvSpec<'static> {
        AuxvSpec {
            phdr: Some(0x1000_0040),
            phent: 56,
            phnum: 9,
            base: 0x2000_0000,
            entry: 0x1000_7930,
            pagesz: 4096,
            uid: 0,
            gid: 0,
            hwcap: 0x3,
            hwcap2: 0,
            clktck: 100,
            secure: false,
            random: *b"0123456789abcdef",
            platform: b"aarch64",
            execfn: b"/usr/bin/node",
            sysinfo_ehdr: None,
            minsigstksz: Some(6144),
            ..Default::default()
        }
    }

    #[test]
    fn round_trips_argv_envp_and_auxv() {
        let mut s = FakeStack::new(0x7000_0000, 64 * 1024);
        let argv: &[&[u8]] = &[b"/usr/bin/node", b"/usr/src/server.js"];
        let envp: &[&[u8]] = &[b"PATH=/usr/bin:/bin", b"HOME=/", b"PWD=/"];
        let l = build_stack(&mut s, argv, envp, &spec()).unwrap();

        let p = parse(&s, l.sp);
        assert_eq!(p.argv, alloc::vec![b"/usr/bin/node".to_vec(), b"/usr/src/server.js".to_vec()]);
        assert_eq!(
            p.envp,
            alloc::vec![
                b"PATH=/usr/bin:/bin".to_vec(),
                b"HOME=/".to_vec(),
                b"PWD=/".to_vec()
            ]
        );
        assert_eq!(get(&p, AT_PHDR), Some(0x1000_0040));
        assert_eq!(get(&p, AT_PHENT), Some(56));
        assert_eq!(get(&p, AT_PHNUM), Some(9));
        assert_eq!(get(&p, AT_BASE), Some(0x2000_0000));
        assert_eq!(get(&p, AT_ENTRY), Some(0x1000_7930));
        assert_eq!(get(&p, AT_PAGESZ), Some(4096));
        assert_eq!(get(&p, AT_CLKTCK), Some(100));
        assert_eq!(get(&p, AT_SECURE), Some(0));
        assert_eq!(get(&p, AT_MINSIGSTKSZ), Some(6144));
    }

    #[test]
    fn sp_is_sixteen_byte_aligned_for_every_shape() {
        // AAPCS64 and the x86-64 psABI both require it at the entry point, and
        // it is easy to get wrong by one pointer.
        for na in 0..8usize {
            for ne in 0..8usize {
                let mut s = FakeStack::new(0x7000_0000, 64 * 1024);
                let args: Vec<Vec<u8>> =
                    (0..na).map(|i| alloc::format!("arg{i}").into_bytes()).collect();
                let envs: Vec<Vec<u8>> =
                    (0..ne).map(|i| alloc::format!("E{i}=v").into_bytes()).collect();
                let argv: Vec<&[u8]> = args.iter().map(|v| v.as_slice()).collect();
                let envp: Vec<&[u8]> = envs.iter().map(|v| v.as_slice()).collect();
                let l = build_stack(&mut s, &argv, &envp, &spec()).unwrap();
                assert_eq!(l.sp % 16, 0, "argc={na} envc={ne} gave sp={:#x}", l.sp);
                assert_eq!(parse(&s, l.sp).argv.len(), na);
            }
        }
    }

    #[test]
    fn at_random_points_at_sixteen_readable_bytes_on_the_stack() {
        // The C loader pointed AT_RANDOM at a local of its own `main()`. In
        // the binfmt path that function returned before the application ever
        // read it, so the canary came from a dead stack frame.
        let mut s = FakeStack::new(0x7000_0000, 64 * 1024);
        let argv: &[&[u8]] = &[b"prog"];
        let l = build_stack(&mut s, argv, &[], &spec()).unwrap();
        let p = parse(&s, l.sp);
        let at = get(&p, AT_RANDOM).unwrap();
        assert!(at >= l.sp && at < s.top(), "AT_RANDOM is not on the stack");
        assert_eq!(s.read(at, 16), b"0123456789abcdef");
    }

    #[test]
    fn platform_and_execfn_are_copied_onto_the_stack() {
        let mut s = FakeStack::new(0x7000_0000, 64 * 1024);
        let argv: &[&[u8]] = &[b"prog"];
        let l = build_stack(&mut s, argv, &[], &spec()).unwrap();
        let p = parse(&s, l.sp);
        let plat = get(&p, AT_PLATFORM).unwrap();
        let execfn = get(&p, AT_EXECFN).unwrap();
        for a in [plat, execfn] {
            assert!(a >= l.sp && a < s.top(), "{a:#x} is not on the stack");
        }
        assert_eq!(s.cstr_at(plat), b"aarch64");
        assert_eq!(s.cstr_at(execfn), b"/usr/bin/node");
    }

    #[test]
    fn strings_are_nul_terminated_including_empty_ones() {
        let mut s = FakeStack::new(0x7000_0000, 64 * 1024);
        let argv: &[&[u8]] = &[b"prog", b"", b"x"];
        let envp: &[&[u8]] = &[b""];
        let l = build_stack(&mut s, argv, envp, &spec()).unwrap();
        let p = parse(&s, l.sp);
        assert_eq!(p.argv, alloc::vec![b"prog".to_vec(), Vec::new(), b"x".to_vec()]);
        assert_eq!(p.envp, alloc::vec![Vec::new()]);
    }

    #[test]
    fn no_auxv_entry_is_duplicated() {
        let mut s = FakeStack::new(0x7000_0000, 64 * 1024);
        let l = build_stack(&mut s, &[b"p"], &[], &spec()).unwrap();
        let p = parse(&s, l.sp);
        let mut keys: Vec<u64> = p.auxv.iter().map(|(k, _)| *k).collect();
        keys.sort();
        let n = keys.len();
        keys.dedup();
        assert_eq!(keys.len(), n, "duplicate auxv keys");
    }

    #[test]
    fn omits_phdr_entries_when_the_headers_are_not_mapped() {
        let mut s = FakeStack::new(0x7000_0000, 64 * 1024);
        let mut sp = spec();
        sp.phdr = None;
        let l = build_stack(&mut s, &[b"p"], &[], &sp).unwrap();
        let p = parse(&s, l.sp);
        // Better to say nothing than to claim AT_PHDR is 0: musl treats a
        // present-but-null AT_PHDR as a valid pointer.
        assert_eq!(get(&p, AT_PHDR), None);
        assert_eq!(get(&p, AT_PHENT), None);
        assert_eq!(get(&p, AT_PHNUM), None);
    }

    #[test]
    fn oversized_environment_is_rejected_not_overflowed() {
        let mut s = FakeStack::new(0x7000_0000, 16 * 1024);
        let big = alloc::vec![b'x'; 32 * 1024];
        let envs: Vec<&[u8]> = alloc::vec![big.as_slice()];
        assert_eq!(
            build_stack(&mut s, &[b"p"], &envs, &spec()).unwrap_err(),
            Error::E2BIG
        );
    }

    #[test]
    fn a_stack_that_is_merely_tight_still_fails_cleanly() {
        // Under the size check but too small once pointers and auxv are added.
        let mut s = FakeStack::new(0x7000_0000, 4096);
        let envs: Vec<Vec<u8>> = (0..200).map(|i| alloc::format!("VAR{i}=0123456789").into_bytes()).collect();
        let envp: Vec<&[u8]> = envs.iter().map(|v| v.as_slice()).collect();
        match build_stack(&mut s, &[b"p"], &envp, &spec()) {
            Err(Error::E2BIG) => {}
            Err(e) => panic!("unexpected error {e}"),
            Ok(_) => panic!("should not have fitted"),
        }
    }

    #[test]
    fn everything_written_stays_inside_the_stack() {
        let mut s = FakeStack::new(0x7000_0000, 64 * 1024);
        let argv: &[&[u8]] = &[b"/usr/bin/node", b"/usr/src/server.js"];
        let envp: &[&[u8]] = &[b"PATH=/usr/bin", b"HOME=/"];
        let l = build_stack(&mut s, argv, envp, &spec()).unwrap();
        assert!(s.low >= s.bottom());
        assert_eq!(s.low, l.sp, "sp should be the low-water mark");
    }

    #[test]
    fn size_check_counts_terminators_and_pointers() {
        // The C version summed strlen() only. A large number of very short
        // variables is where that diverges: the strings are a small fraction
        // of what actually gets written, because each one also costs a NUL and
        // an eight-byte pointer.
        const N: usize = 110_000;
        const STACK: u64 = 4 * 1024 * 1024; // budget = 1 MiB
        let many: Vec<Vec<u8>> = (0..N).map(|_| b"a".to_vec()).collect();
        let v: Vec<&[u8]> = many.iter().map(|s| s.as_slice()).collect();

        let strlen_only: usize = v.iter().map(|s| s.len()).sum();
        assert!(
            (strlen_only as u64) < STACK / 4,
            "the strlen-only sum must be under budget for this to prove anything"
        );
        assert_eq!(check_arg_env_size(&v, &[], STACK).unwrap_err(), Error::E2BIG);

        // The floor is ARG_MAX, so a small stack does not make the limit
        // absurdly tight -- that is the policy `execve(2)` describes.
        assert!(check_arg_env_size(&[b"prog"], &[b"HOME=/"], 8 * 1024).is_ok());
    }
}
