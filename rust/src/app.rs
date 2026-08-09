// SPDX-License-Identifier: BSD-3-Clause
//! The `main()` the unikernel boots into: work out what to run, load it, hand
//! it a stack, and schedule it.
//!
//! This is the port of `main.c`. The observable behaviour is the same, with
//! one deliberate difference noted at [`run`].

use crate::auxv;
use crate::err::{Error, Result};
use crate::loader::Vm;
use crate::log;
use crate::program::{self, Opened, Opener};
use crate::sys::{self, cfg, AppStack, CString, MemImage, UkVm};
use crate::util::{basename, is_bare_name, Show};
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::ffi::{c_char, c_int};

/// Opens images through the VFS.
struct VfsOpener;

impl Opener for VfsOpener {
    fn open(&self, path: &[u8]) -> Result<Opened> {
        let f = sys::File::open(path)?;
        f.check_exec_bit()?;
        let fd = if cfg().have_mmap != 0 {
            Some(f.fd())
        } else {
            None
        };
        Ok(Opened {
            src: Box::new(f),
            fd,
        })
    }
}

/// Serves a single image that is already in memory (the initrd), and nothing
/// else -- so a `PT_INTERP` in an initrd image fails with a clear `ENOENT`
/// rather than being silently ignored.
struct InitrdOpener {
    base: u64,
    len: u64,
}

impl Opener for InitrdOpener {
    fn open(&self, path: &[u8]) -> Result<Opened> {
        if path != b"<initrd>" {
            log::err(format_args!(
                "cannot open {} : an initrd image has no filesystem to load an interpreter from",
                Show(path)
            ));
            return Err(Error::ENOENT);
        }
        // SAFETY: the region comes from `ukplat_memregion_find_initrd0` and
        // stays mapped for the life of the unikernel.
        Ok(Opened {
            src: Box::new(unsafe { MemImage::new(self.base, self.len) }),
            fd: None,
        })
    }
}

/// C entry point, called from `main()` in `glue/shim.c`.
#[no_mangle]
pub extern "C" fn elfrs_main(argc: c_int, argv: *const *const c_char) -> c_int {
    let args = collect_argv(argc, argv);
    match run(&args) {
        Ok(()) => 0,
        Err(e) => {
            log::err(format_args!("elfloader: {e}"));
            // main() returns to libukboot, which treats non-zero as failure.
            if e.0 != 0 {
                e.0
            } else {
                1
            }
        }
    }
}

fn collect_argv(argc: c_int, argv: *const *const c_char) -> Vec<&'static [u8]> {
    let mut v = Vec::new();
    if argv.is_null() || argc <= 0 {
        return v;
    }
    for i in 0..argc as isize {
        // SAFETY: libukboot guarantees `argv` holds `argc` valid pointers that
        // live for the life of the unikernel.
        let p = unsafe { *argv.offset(i) };
        v.push(unsafe { sys::cstr(p) });
    }
    v
}

/// What to run, and under what name.
struct Target {
    /// Path to open, or `<initrd>` in the initrd configuration.
    path: Vec<u8>,
    /// `argv[0]` as the application will see it.
    progname: Vec<u8>,
    /// Everything after `argv[0]`.
    rest: Vec<&'static [u8]>,
}

/// Split the kernel command line the way `main.c` does.
///
/// The rules are inherited verbatim, because the command line is a user
/// interface:
///
/// * With `APPELFLOADER_CUSTOMAPPNAME`, `argv[1]` names the program (and, for
///   the VFS configuration, is also its path). The kernel name and the program
///   name are both dropped from what the application sees, and the basename of
///   the path becomes its `argv[0]`.
/// * Without it, the program is the compiled-in `APPELFLOADER_VFSEXEC_PATH`
///   and only the kernel name is dropped.
fn split_command_line(args: &[&'static [u8]]) -> Result<Target> {
    let c = cfg();
    let initrd = c.vfsexec == 0;

    if c.customappname != 0 {
        if args.len() < 2 {
            log::err(format_args!("program name missing (no argv[1])"));
            return Err(Error::EINVAL);
        }
        let named = args[1];
        let path = if initrd { b"<initrd>".to_vec() } else { named.to_vec() };
        let progname = if initrd {
            named.to_vec()
        } else {
            basename(named).to_vec()
        };
        Ok(Target {
            path,
            progname,
            rest: args[2..].to_vec(),
        })
    } else {
        if args.is_empty() {
            return Err(Error::EINVAL);
        }
        let (path, progname) = if initrd {
            (b"<initrd>".to_vec(), args[0].to_vec())
        } else {
            // SAFETY: the pointer comes from the compiled-in Kconfig string.
            let p = unsafe { sys::cstr(c.vfsexec_path) };
            if p.is_empty() {
                log::err(format_args!(
                    "no program path: set CONFIG_APPELFLOADER_VFSEXEC_PATH or enable CUSTOMAPPNAME"
                ));
                return Err(Error::EINVAL);
            }
            (p.to_vec(), basename(p).to_vec())
        };
        Ok(Target {
            path,
            progname,
            rest: args[1..].to_vec(),
        })
    }
}

/// Resolve the program through `$PATH` when it was given as a bare name.
fn resolve(target: &mut Target) {
    if cfg().envpath == 0 || !is_bare_name(&target.path) {
        return;
    }
    let Some(path_env) = sys::getenv(b"PATH") else {
        return;
    };
    match sys::locate_in_path(&target.path, path_env) {
        Some(full) => {
            log::debug(format_args!("resolved to {}", Show(&full)));
            target.path = full;
        }
        None => log::warn(format_args!(
            "{} not found in $PATH; trying it as a path",
            Show(&target.path)
        )),
    }
}

/// Load and start the application.
///
/// One deliberate difference from `main.c`: where upstream delegates to
/// `execve()` when `CONFIG_LIBPOSIX_PROCESS_EXECVE` is on, this always loads
/// directly and separately registers the binfmt handler (see `binfmt.rs`) so
/// that an `execve()` *from the application* still works. Two code paths that
/// load the first program, selected by a Kconfig symbol, is one more than the
/// problem needs.
fn run(args: &[&'static [u8]]) -> Result<()> {
    let c = cfg();
    let vm = UkVm;
    let page = vm.page_size();

    let mut target = split_command_line(args)?;
    resolve(&mut target);

    let name_str = "app";
    log::info(format_args!(
        "loading {} as {}",
        Show(&target.path),
        Show(&target.progname)
    ));

    // The thread container gives us the stack the application will start on.
    let cname = CString::new(&target.progname)?;
    // SAFETY: `cname` outlives the call; Unikraft copies the name.
    let thread = unsafe { sys::ffi::elfrs_thread_create(cname.as_ptr(), c.stack_len as u64) };
    if thread.is_null() {
        log::err(format_args!("failed to allocate the application thread"));
        return Err(Error::ENOMEM);
    }
    let guard = ThreadGuard(thread);

    if c.envpwd != 0 {
        if let Some(pwd) = sys::getenv(b"PWD") {
            if let Err(e) = sys::chdir(pwd) {
                log::err(format_args!(
                    "could not change directory to {}: {e}",
                    Show(pwd)
                ));
                return Err(e);
            }
        }
    }

    let loaded = if c.vfsexec != 0 {
        program::load_program(name_str, &target.path, &VfsOpener, &vm)?
    } else {
        let mut base: u64 = 0;
        let mut len: u64 = 0;
        let rc = unsafe { sys::ffi::elfrs_initrd(&mut base, &mut len) };
        if rc < 0 || base == 0 || len == 0 {
            log::err(format_args!("no initrd image found (missing initrd?)"));
            return Err(Error::ENOENT);
        }
        log::info(format_args!("initrd image at {base:#x}, {len} bytes"));
        program::load_program(name_str, b"<initrd>", &InitrdOpener { base, len }, &vm)?
    };

    // --- the application's stack ---

    let ctx = unsafe { sys::ffi::elfrs_thread_ctx(thread) };
    let stack_lo = unsafe { sys::ffi::elfrs_thread_stack_base(thread) };
    let stack_hi = unsafe { sys::ffi::elfrs_ctx_get_sp(ctx) };
    if stack_hi <= stack_lo {
        log::err(format_args!(
            "implausible application stack {stack_lo:#x}..{stack_hi:#x}"
        ));
        loaded.unload(&vm);
        return Err(Error::EINVAL);
    }
    let mut stack = AppStack::new(stack_lo, stack_hi);

    let mut argv: Vec<&[u8]> = Vec::new();
    argv.try_reserve(target.rest.len() + 1)
        .map_err(|_| Error::ENOMEM)?;
    argv.push(&target.progname);
    argv.extend_from_slice(&target.rest);
    let envp = sys::environ();

    let execfn: &[u8] = &target.path;
    let aux = loaded.auxv(&program::Environment {
        page_size: page,
        platform: sys::platform(),
        execfn,
        random: sys::random_bytes(),
        uid: c.uid as u64,
        gid: c.gid as u64,
        hwcap: sys::hwcap(),
        sysinfo_ehdr: (c.vdso_addr != 0).then_some(c.vdso_addr),
    });

    log::debug(format_args!(
        "auxv: phdr={:?} phent={} phnum={} base={:#x} entry={:#x} pagesz={} \
         hwcap={:#x}/{:#x} platform={}",
        aux.phdr.map(|v| Show2(v)),
        aux.phent,
        aux.phnum,
        aux.base,
        aux.entry,
        aux.pagesz,
        aux.hwcap,
        aux.hwcap2,
        Show(aux.platform)
    ));

    let layout = match auxv::build_stack(&mut stack, &argv, &envp, &aux) {
        Ok(l) => l,
        Err(e) => {
            log::err(format_args!(
                "arguments and environment do not fit in a {} KiB stack: {e}",
                (stack_hi - stack_lo) / 1024
            ));
            loaded.unload(&vm);
            return Err(e);
        }
    };

    let entry = loaded.entry();
    log::debug(format_args!(
        "stack {stack_lo:#x}..{stack_hi:#x}, sp {:#x}, entry {entry:#x}",
        layout.sp
    ));

    unsafe { sys::ffi::elfrs_ctx_init(ctx, layout.sp, entry) };
    unsafe { sys::ffi::elfrs_thread_set_runnable(thread) };

    if c.have_pthread != 0 {
        let rc = unsafe { sys::ffi::elfrs_thread_make_pthread(thread) };
        if rc != 0 {
            log::err(format_args!("could not register the application thread ({rc})"));
            loaded.unload(&vm);
            return Err(Error(-rc));
        }
    }

    let rc = unsafe { sys::ffi::elfrs_thread_schedule(thread) };
    if rc != 0 {
        log::err(format_args!("could not schedule the application ({rc})"));
        loaded.unload(&vm);
        return Err(Error(-rc));
    }

    // The thread now owns everything: do not release it on the way out.
    core::mem::forget(guard);
    core::mem::forget(loaded);

    // No way to join yet -- uksched has no thread-exit wait and posix-process
    // does not expose one either. Upstream sleeps in a loop; this parks in the
    // scheduler instead, which costs nothing.
    unsafe { sys::ffi::elfrs_wait_forever() }
}

/// Hex in a `{:?}` position, for the `Option<u64>` in the auxv dump.
struct Show2(u64);

impl core::fmt::Debug for Show2 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

/// Releases a thread container if we bail out before handing it to the
/// scheduler. The C version had a `goto out_free_thread` ladder and one path
/// (`chdir` failure) that jumped to it after the thread was already partly
/// initialised.
struct ThreadGuard(*mut core::ffi::c_void);

impl Drop for ThreadGuard {
    fn drop(&mut self) {
        unsafe { sys::ffi::elfrs_thread_release(self.0) }
    }
}
