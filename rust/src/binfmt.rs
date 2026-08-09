// SPDX-License-Identifier: BSD-3-Clause
//! `libukbinfmt` loader, so an `execve()` from inside the guest lands here.
//!
//! Everything specific to `struct uk_binfmt_loader_args` is behind accessors
//! in `glue/shim.c`; this side only sees the fields it needs.

use crate::auxv;
use crate::err::{Error, Result};
use crate::loader::Vm;
use crate::log;
use crate::program::{self, LoadedProgram};
use crate::sys::{self, cfg, AppStack, UkVm};
use crate::util::{basename, Show};
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::ffi::{c_char, c_int, c_void};

/// Return values for the C wrapper, which maps them onto `UK_BINFMT_*`.
const HANDLED: c_int = 0;
const NOT_HANDLED: c_int = 1;

mod ffi {
    use core::ffi::{c_char, c_int, c_void};
    extern "C" {
        pub fn elfrs_binfmt_pathname(args: *mut c_void) -> *const c_char;
        pub fn elfrs_binfmt_progname(args: *mut c_void) -> *const c_char;
        pub fn elfrs_binfmt_argc(args: *mut c_void) -> c_int;
        pub fn elfrs_binfmt_argv(args: *mut c_void) -> *const *const c_char;
        pub fn elfrs_binfmt_envc(args: *mut c_void) -> c_int;
        pub fn elfrs_binfmt_envp(args: *mut c_void) -> *const *const c_char;
        pub fn elfrs_binfmt_ctx(args: *mut c_void) -> *mut c_void;
        pub fn elfrs_binfmt_stack_size(args: *mut c_void) -> u64;
        pub fn elfrs_binfmt_set_user(args: *mut c_void, user: *mut c_void);
        pub fn elfrs_binfmt_get_user(args: *mut c_void) -> *mut c_void;
    }
}

fn vec_from_c(p: *const *const c_char, n: c_int) -> Vec<&'static [u8]> {
    let mut v = Vec::new();
    if p.is_null() || n <= 0 {
        return v;
    }
    for i in 0..n as isize {
        // SAFETY: libukbinfmt guarantees `n` valid pointers.
        v.push(unsafe { sys::cstr(*p.offset(i)) });
    }
    v
}

#[no_mangle]
pub extern "C" fn elfrs_binfmt_load(args: *mut c_void) -> c_int {
    match load(args) {
        Ok(rc) => rc,
        Err(e) => {
            // ENOEXEC means "not an ELF" -- let the next loader try. Anything
            // else is a real failure and must not be masked as "not mine".
            if e == Error::ENOEXEC {
                log::warn(format_args!("not handled by the ELF binfmt loader"));
                return NOT_HANDLED;
            }
            log::err(format_args!("could not load ELF: {e}"));
            e.as_neg()
        }
    }
}

fn load(args: *mut c_void) -> Result<c_int> {
    let c = cfg();
    let vm = UkVm;

    let path = unsafe { sys::cstr(ffi::elfrs_binfmt_pathname(args)) };
    let progname_raw = unsafe { sys::cstr(ffi::elfrs_binfmt_progname(args)) };
    let progname = if progname_raw.is_empty() {
        basename(path)
    } else {
        progname_raw
    };

    let argv = vec_from_c(
        unsafe { ffi::elfrs_binfmt_argv(args) },
        unsafe { ffi::elfrs_binfmt_argc(args) },
    );
    let envp = vec_from_c(
        unsafe { ffi::elfrs_binfmt_envp(args) },
        unsafe { ffi::elfrs_binfmt_envc(args) },
    );

    log::debug(format_args!(
        "binfmt: loading {} as {}",
        Show(path),
        Show(progname)
    ));

    let loaded = program::load_program("exec", path, &VfsOpener, &vm)?;

    let ctx = unsafe { ffi::elfrs_binfmt_ctx(args) };
    let sp_top = unsafe { sys::ffi::elfrs_ctx_get_sp(ctx) };
    let stack_size = unsafe { ffi::elfrs_binfmt_stack_size(args) };
    if sp_top < stack_size {
        loaded.unload(&vm);
        return Err(Error::EINVAL);
    }
    let mut stack = AppStack::new(sp_top - stack_size, sp_top);

    // argv comes through complete, argv[0] included; upstream split it into
    // `argv[0]` plus `&argv[1]` and passed both, which only worked because the
    // two were reassembled in the same order at the other end.
    let argv_ref: Vec<&[u8]> = if argv.is_empty() {
        alloc::vec![progname]
    } else {
        argv.clone()
    };

    let aux = loaded.auxv(&program::Environment {
        page_size: vm.page_size(),
        platform: sys::platform(),
        execfn: path,
        random: sys::random_bytes(),
        uid: c.uid as u64,
        gid: c.gid as u64,
        hwcap: sys::hwcap(),
        sysinfo_ehdr: (c.vdso_addr != 0).then_some(c.vdso_addr),
    });

    let layout = match auxv::build_stack(&mut stack, &argv_ref, &envp, &aux) {
        Ok(l) => l,
        Err(e) => {
            loaded.unload(&vm);
            return Err(e);
        }
    };

    unsafe { sys::ffi::elfrs_ctx_init(ctx, layout.sp, loaded.entry()) };

    // Hand ownership to libukbinfmt, which calls back into `unload`.
    let boxed = Box::into_raw(Box::new(loaded));
    unsafe { ffi::elfrs_binfmt_set_user(args, boxed as *mut c_void) };
    Ok(HANDLED)
}

#[no_mangle]
pub extern "C" fn elfrs_binfmt_unload(args: *mut c_void) -> c_int {
    let user = unsafe { ffi::elfrs_binfmt_get_user(args) };
    if user.is_null() {
        return HANDLED;
    }
    // SAFETY: `user` is the pointer `load` handed over, and libukbinfmt calls
    // unload at most once for it.
    let loaded: Box<LoadedProgram> = unsafe { Box::from_raw(user as *mut LoadedProgram) };
    loaded.unload(&UkVm);
    unsafe { ffi::elfrs_binfmt_set_user(args, core::ptr::null_mut()) };
    HANDLED
}

/// Same as `app.rs`'s, duplicated rather than shared because the binfmt path
/// must not enforce the executable bit twice (libukbinfmt has already checked
/// it before dispatching).
struct VfsOpener;

impl program::Opener for VfsOpener {
    fn open(&self, path: &[u8]) -> Result<program::Opened> {
        let f = sys::File::open(path)?;
        let fd = if cfg().have_mmap != 0 {
            Some(f.fd())
        } else {
            None
        };
        Ok(program::Opened {
            src: Box::new(f),
            fd,
        })
    }
}
