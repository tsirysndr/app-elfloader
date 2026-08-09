// SPDX-License-Identifier: BSD-3-Clause
//! The Unikraft side: FFI declarations for `glue/shim.c`, and the
//! implementations of [`Vm`](crate::loader::Vm),
//! [`ImageSource`](crate::elf::ImageSource) and
//! [`StackWriter`](crate::auxv::StackWriter) that sit on top of them.
//!
//! Nothing in here is compiled under `cargo test`.

use crate::auxv::StackWriter;
use crate::elf::ImageSource;
use crate::err::{from_c, Error, Result};
use crate::loader::{MapSrc, Vm, Where};
use alloc::vec::Vec;
use core::ffi::{c_char, c_int, c_void};

pub mod ffi {
    use core::ffi::{c_char, c_int, c_void};

    /// Mirrors `struct elfrs_cfg` in `glue/shim.h`. Field order and types must
    /// stay in lockstep; `elfrs_cfg_size_check()` in the shim asserts the size
    /// matches at compile time.
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct Cfg {
        pub stack_len: u32,
        pub page_size: u32,
        pub uid: u32,
        pub gid: u32,

        pub have_vfs: u8,
        pub have_mmap: u8,
        pub have_vmem: u8,
        pub have_environ: u8,
        pub have_random: u8,
        pub have_pthread: u8,

        pub vfsexec: u8,
        pub customappname: u8,
        pub envpath: u8,
        pub envpwd: u8,
        pub execbit: u8,
        pub debug: u8,

        pub vfsexec_path: *const c_char,
        pub vdso_addr: u64,
    }

    extern "C" {
        pub fn elfrs_cfg_get(out: *mut Cfg);

        pub fn elfrs_printk(lvl: c_int, msg: *const c_char);
        pub fn elfrs_crash(msg: *const c_char) -> !;

        pub fn elfrs_memalign(align: u64, size: u64) -> *mut c_void;
        pub fn elfrs_free(ptr: *mut c_void);

        pub fn elfrs_map(
            addr: u64,
            len: u64,
            prot: c_int,
            kind: c_int,
            fd: c_int,
            off: i64,
            replace: c_int,
            err: *mut c_int,
        ) -> u64;
        pub fn elfrs_unmap(addr: u64, len: u64) -> c_int;
        pub fn elfrs_protect(addr: u64, len: u64, prot: c_int) -> c_int;

        pub fn elfrs_open_ro(path: *const c_char) -> c_int;
        pub fn elfrs_close(fd: c_int);
        pub fn elfrs_pread(fd: c_int, buf: *mut c_void, len: u64, off: i64) -> i64;
        pub fn elfrs_fsize(fd: c_int) -> i64;
        pub fn elfrs_fd_is_exec(fd: c_int) -> c_int;
        pub fn elfrs_path_is_exec(path: *const c_char) -> c_int;

        pub fn elfrs_environ() -> *const *const c_char;
        pub fn elfrs_getenv(name: *const c_char) -> *const c_char;
        pub fn elfrs_chdir(path: *const c_char) -> c_int;
        pub fn elfrs_random_fill(buf: *mut c_void, len: u64) -> c_int;

        pub fn elfrs_initrd(base: *mut u64, len: *mut u64) -> c_int;

        pub fn elfrs_thread_create(name: *const c_char, stack_len: u64) -> *mut c_void;
        pub fn elfrs_thread_release(thread: *mut c_void);
        pub fn elfrs_thread_ctx(thread: *mut c_void) -> *mut c_void;
        pub fn elfrs_thread_stack_base(thread: *mut c_void) -> u64;
        pub fn elfrs_thread_set_runnable(thread: *mut c_void);
        pub fn elfrs_thread_make_pthread(thread: *mut c_void) -> c_int;
        pub fn elfrs_thread_schedule(thread: *mut c_void) -> c_int;
        pub fn elfrs_wait_forever() -> !;

        pub fn elfrs_ctx_get_sp(ctx: *mut c_void) -> u64;
        pub fn elfrs_ctx_init(ctx: *mut c_void, sp: u64, ip: u64);

        pub fn elfrs_icache_sync(addr: u64, len: u64);
        pub fn elfrs_hwcap() -> u64;
        pub fn elfrs_hwcap2() -> u64;
        pub fn elfrs_platform() -> *const c_char;
    }

    pub const MAP_ANON: c_int = 0;
    pub const MAP_FILE: c_int = 1;
}

/// Cached copy of the compile-time configuration.
static mut CFG: Option<ffi::Cfg> = None;

pub fn cfg() -> &'static ffi::Cfg {
    // SAFETY: written once, before any application thread exists, from the
    // single thread running `main()`.
    unsafe {
        let p = &raw mut CFG;
        if (*p).is_none() {
            let mut c: ffi::Cfg = core::mem::zeroed();
            ffi::elfrs_cfg_get(&mut c);
            *p = Some(c);
        }
        (*p).as_ref().unwrap_unchecked()
    }
}

pub fn page_size() -> u64 {
    cfg().page_size as u64
}

/// A NUL-terminated string built on the heap, for handing paths to C.
pub struct CString(Vec<u8>);

impl CString {
    pub fn new(s: &[u8]) -> Result<CString> {
        if s.contains(&0) {
            return Err(Error::EINVAL);
        }
        let mut v = Vec::new();
        v.try_reserve(s.len() + 1).map_err(|_| Error::ENOMEM)?;
        v.extend_from_slice(s);
        v.push(0);
        Ok(CString(v))
    }

    pub fn as_ptr(&self) -> *const c_char {
        self.0.as_ptr() as *const c_char
    }
}

/// Borrow a NUL-terminated C string as a byte slice, without the NUL.
///
/// # Safety
/// `p` must be a valid, NUL-terminated string that outlives the borrow.
pub unsafe fn cstr(p: *const c_char) -> &'static [u8] {
    if p.is_null() {
        return b"";
    }
    let mut n = 0usize;
    // SAFETY: the caller guarantees termination.
    while unsafe { *p.add(n) } != 0 {
        n += 1;
    }
    unsafe { core::slice::from_raw_parts(p as *const u8, n) }
}

// --- address space -------------------------------------------------------

pub struct UkVm;

impl Vm for UkVm {
    fn page_size(&self) -> u64 {
        page_size()
    }

    fn map(&self, at: Where, len: u64, prot: u32, src: MapSrc) -> Result<u64> {
        let (addr, replace) = match at {
            Where::Anywhere => (0, 0),
            Where::Hint(a) => (a, 0),
            Where::Exact(a) => (a, 1),
        };
        let (kind, fd, off) = match src {
            MapSrc::Anon => (ffi::MAP_ANON, -1, 0),
            MapSrc::File { fd, off } => (ffi::MAP_FILE, fd, off as i64),
        };
        let mut err: c_int = 0;
        // SAFETY: plain scalars; the shim validates nothing else.
        let got = unsafe {
            ffi::elfrs_map(
                addr,
                len,
                prot as c_int,
                kind,
                fd,
                off,
                replace,
                &mut err,
            )
        };
        if got == 0 {
            return Err(Error(if err > 0 { err } else { -err }));
        }
        Ok(got)
    }

    fn unmap(&self, addr: u64, len: u64) -> Result<()> {
        from_c(unsafe { ffi::elfrs_unmap(addr, len) } as i64).map(|_| ())
    }

    fn protect(&self, addr: u64, len: u64, prot: u32) -> Result<()> {
        from_c(unsafe { ffi::elfrs_protect(addr, len, prot as c_int) } as i64).map(|_| ())
    }

    fn write(&self, addr: u64, data: &[u8]) -> Result<()> {
        // SAFETY: the caller only ever passes an address inside a mapping this
        // loader created and made writable, with `data.len()` bytes of room.
        unsafe {
            core::ptr::copy_nonoverlapping(data.as_ptr(), addr as *mut u8, data.len());
        }
        Ok(())
    }

    fn zero(&self, addr: u64, len: u64) -> Result<()> {
        // SAFETY: as above.
        unsafe {
            core::ptr::write_bytes(addr as *mut u8, 0, len as usize);
        }
        Ok(())
    }

    fn icache_sync(&self, addr: u64, len: u64) {
        unsafe { ffi::elfrs_icache_sync(addr, len) }
    }

    fn can_map_files(&self) -> bool {
        cfg().have_mmap != 0
    }

    fn alloc_aligned(&self, align: u64, len: u64) -> Result<u64> {
        let p = unsafe { ffi::elfrs_memalign(align, len) };
        if p.is_null() {
            return Err(Error::ENOMEM);
        }
        Ok(p as u64)
    }

    fn free_aligned(&self, addr: u64, _len: u64) {
        unsafe { ffi::elfrs_free(addr as *mut c_void) }
    }
}

// --- image sources -------------------------------------------------------

/// An open file. Closes on drop, so no error path can leak a descriptor -- the
/// C version had a `goto` ladder for this and one path that did not take it.
pub struct File {
    fd: c_int,
    size: Option<u64>,
}

impl File {
    pub fn open(path: &[u8]) -> Result<File> {
        let c = CString::new(path)?;
        let fd = unsafe { ffi::elfrs_open_ro(c.as_ptr()) };
        if fd < 0 {
            return Err(Error(-fd));
        }
        let size = unsafe { ffi::elfrs_fsize(fd) };
        Ok(File {
            fd,
            size: if size >= 0 { Some(size as u64) } else { None },
        })
    }

    pub fn fd(&self) -> c_int {
        self.fd
    }

    /// Enforce the executable bit, when the build asks for it.
    pub fn check_exec_bit(&self) -> Result<()> {
        if cfg().execbit == 0 {
            return Ok(());
        }
        from_c(unsafe { ffi::elfrs_fd_is_exec(self.fd) } as i64).map(|_| ())
    }
}

impl Drop for File {
    fn drop(&mut self) {
        unsafe { ffi::elfrs_close(self.fd) }
    }
}

impl ImageSource for File {
    fn read_exact_at(&self, off: u64, buf: &mut [u8]) -> Result<()> {
        let mut done = 0usize;
        while done < buf.len() {
            let n = unsafe {
                ffi::elfrs_pread(
                    self.fd,
                    buf[done..].as_mut_ptr() as *mut c_void,
                    (buf.len() - done) as u64,
                    (off + done as u64) as i64,
                )
            };
            match n {
                0 => return Err(Error::ENOEXEC), // unexpected end of file
                n if n < 0 => return Err(Error(-n as i32)),
                n => done += n as usize,
            }
        }
        Ok(())
    }

    fn size(&self) -> Option<u64> {
        self.size
    }
}

/// An image already resident in memory: the initrd.
pub struct MemImage {
    base: *const u8,
    len: usize,
}

impl MemImage {
    /// # Safety
    /// `base` must point at `len` readable bytes that outlive this value.
    pub unsafe fn new(base: u64, len: u64) -> MemImage {
        MemImage {
            base: base as *const u8,
            len: len as usize,
        }
    }
}

impl ImageSource for MemImage {
    fn read_exact_at(&self, off: u64, buf: &mut [u8]) -> Result<()> {
        let off: usize = off.try_into().map_err(|_| Error::ENOEXEC)?;
        let end = off.checked_add(buf.len()).ok_or(Error::ENOEXEC)?;
        if end > self.len {
            return Err(Error::ENOEXEC);
        }
        // SAFETY: bounds checked against the region described at construction.
        unsafe {
            core::ptr::copy_nonoverlapping(self.base.add(off), buf.as_mut_ptr(), buf.len());
        }
        Ok(())
    }

    fn size(&self) -> Option<u64> {
        Some(self.len as u64)
    }
}

// --- the application stack -----------------------------------------------

pub struct AppStack {
    lo: u64,
    hi: u64,
}

impl AppStack {
    pub fn new(lo: u64, hi: u64) -> AppStack {
        AppStack { lo, hi }
    }
}

impl StackWriter for AppStack {
    fn top(&self) -> u64 {
        self.hi
    }

    fn bottom(&self) -> u64 {
        self.lo
    }

    fn write(&mut self, addr: u64, data: &[u8]) -> Result<()> {
        // Belt and braces: `build_stack` already checks, but this is the last
        // place before a raw write into another thread's stack.
        if addr < self.lo || addr.saturating_add(data.len() as u64) > self.hi {
            return Err(Error::E2BIG);
        }
        // SAFETY: bounds checked immediately above; the target thread has not
        // been scheduled yet, so nothing else is touching this memory.
        unsafe {
            core::ptr::copy_nonoverlapping(data.as_ptr(), addr as *mut u8, data.len());
        }
        Ok(())
    }
}

// --- odds and ends -------------------------------------------------------

pub fn environ() -> Vec<&'static [u8]> {
    let mut v = Vec::new();
    if cfg().have_environ == 0 {
        return v;
    }
    let p = unsafe { ffi::elfrs_environ() };
    if p.is_null() {
        return v;
    }
    let mut i = 0isize;
    loop {
        // SAFETY: `environ` is a NULL-terminated array of C strings.
        let e = unsafe { *p.offset(i) };
        if e.is_null() {
            break;
        }
        v.push(unsafe { cstr(e) });
        i += 1;
    }
    v
}

pub fn getenv(name: &[u8]) -> Option<&'static [u8]> {
    if cfg().have_environ == 0 {
        return None;
    }
    let c = CString::new(name).ok()?;
    let p = unsafe { ffi::elfrs_getenv(c.as_ptr()) };
    if p.is_null() {
        None
    } else {
        Some(unsafe { cstr(p) })
    }
}

pub fn chdir(path: &[u8]) -> Result<()> {
    let c = CString::new(path)?;
    from_c(unsafe { ffi::elfrs_chdir(c.as_ptr()) } as i64).map(|_| ())
}

/// 16 bytes for `AT_RANDOM`.
///
/// Falls back to a fixed value with a loud warning when the build has no
/// entropy source, exactly as the C version did -- the difference is that the
/// bytes end up on the application's own stack rather than in a kernel stack
/// frame that may already have been reused.
pub fn random_bytes() -> [u8; 16] {
    let mut b = [0u8; 16];
    if cfg().have_random != 0 {
        let rc = unsafe { ffi::elfrs_random_fill(b.as_mut_ptr() as *mut c_void, 16) };
        if rc == 0 {
            return b;
        }
        crate::log::warn(format_args!(
            "could not obtain randomness ({rc}); falling back to a fixed seed"
        ));
    } else {
        crate::log::warn(format_args!(
            "no entropy source in this build; using a fixed seed for AT_RANDOM"
        ));
    }
    b.copy_from_slice(&[
        0xb0, 0xb0, 0x00, 0x00, 0x0d, 0xf0, 0x00, 0x00, 0xb0, 0xb0, 0x00, 0x00, 0x0d, 0xf0, 0x00,
        0x00,
    ]);
    b
}

pub fn platform() -> &'static [u8] {
    unsafe { cstr(ffi::elfrs_platform()) }
}

pub fn hwcap() -> (u64, u64) {
    unsafe { (ffi::elfrs_hwcap(), ffi::elfrs_hwcap2()) }
}

/// Look `name` up in a colon-separated search path.
///
/// Reimplemented rather than bound because the C version leaned on
/// `uk_streambuf` and `uk_nextarg_r` for what is a `split` and a `join`, and
/// its reserve-two-bytes dance was load-bearing in a way no reader could
/// verify. The candidate generation itself lives in `util`, where it is
/// tested; this only adds the "does it exist and is it executable" filter.
pub fn locate_in_path(name: &[u8], path_env: &[u8]) -> Option<Vec<u8>> {
    if !crate::util::is_bare_name(name) {
        return None;
    }
    for cand in crate::util::path_candidates(name, path_env) {
        let Ok(c) = CString::new(&cand) else { continue };
        crate::log::debug(format_args!(
            "looking for the executable at {}",
            crate::util::Show(&cand)
        ));
        if unsafe { ffi::elfrs_path_is_exec(c.as_ptr()) } == 0 {
            return Some(cand);
        }
    }
    None
}
