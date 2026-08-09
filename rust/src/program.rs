// SPDX-License-Identifier: BSD-3-Clause
//! Putting it together: load an executable, side-load its interpreter, and
//! describe the auxiliary vector the pair implies.
//!
//! Generic over how files are opened so the interpreter chain -- which is
//! where `AT_BASE`, `AT_ENTRY` and `AT_PHDR` all come from, and where the C
//! loader's mistakes were invisible because a real `ld.so` happens to have
//! `p_vaddr == 0` -- can be exercised on the host.

use crate::auxv::AuxvSpec;
use crate::elf::{Image, ImageSource, ET_DYN};
use crate::err::{Error, Result};
use crate::loader::{self, Loaded, Vm};
use crate::log;
use crate::util::Show;
use alloc::boxed::Box;
use alloc::vec::Vec;

/// An image the loader can read, plus the descriptor to map it from when the
/// platform supports file-backed mappings.
pub struct Opened {
    pub src: Box<dyn ImageSource>,
    pub fd: Option<i32>,
}

pub trait Opener {
    fn open(&self, path: &[u8]) -> Result<Opened>;
}

#[derive(Debug)]
pub struct LoadedProgram {
    pub image: Image,
    pub main: Loaded,
    pub interp: Option<(Image, Loaded)>,
    pub interp_path: Option<Vec<u8>>,
}

impl LoadedProgram {
    /// Where execution begins: the interpreter when there is one, otherwise
    /// the program itself.
    pub fn entry(&self) -> u64 {
        match &self.interp {
            Some((_, l)) => l.plan.entry,
            None => self.main.plan.entry,
        }
    }

    /// Load bias of the interpreter, for `AT_BASE`.
    ///
    /// The C loader passed the address of the interpreter's first mapped
    /// segment. That is the same number only while the first `PT_LOAD` has
    /// `p_vaddr == 0`, which every shipped dynamic linker does but nothing
    /// guarantees; a prelinked or oddly scripted one would have been given a
    /// bias off by its own `p_vaddr` and crashed in relocation processing.
    pub fn interp_base(&self) -> u64 {
        self.interp.as_ref().map(|(_, l)| l.plan.bias).unwrap_or(0)
    }

    pub fn auxv<'a>(&'a self, env: &Environment<'a>) -> AuxvSpec<'a> {
        let Environment {
            page_size,
            platform,
            execfn,
            random,
            uid,
            gid,
            hwcap,
            sysinfo_ehdr,
        } = *env;
        AuxvSpec {
            phdr: self.main.plan.phdr_addr(&self.image),
            phent: self.image.ehdr.e_phentsize as u64,
            phnum: self.image.ehdr.e_phnum as u64,
            base: self.interp_base(),
            entry: self.main.plan.entry,
            pagesz: page_size,
            uid,
            gid,
            hwcap: hwcap.0,
            hwcap2: hwcap.1,
            clktck: 100,
            secure: false,
            random,
            platform,
            execfn,
            sysinfo_ehdr,
            minsigstksz: min_sig_stack_size(),
        }
    }

    pub fn unload<V: Vm>(&self, vm: &V) {
        if let Some((_, l)) = &self.interp {
            l.unload(vm);
        }
        self.main.unload(vm);
    }
}

/// The parts of the auxiliary vector that come from the system rather than
/// from the image. Grouped because passing eight of them positionally is how
/// you eventually swap `uid` and `gid`.
#[derive(Clone, Copy, Debug)]
pub struct Environment<'a> {
    pub page_size: u64,
    pub platform: &'a [u8],
    pub execfn: &'a [u8],
    pub random: [u8; 16],
    pub uid: u64,
    pub gid: u64,
    /// `AT_HWCAP` and `AT_HWCAP2`.
    pub hwcap: (u64, u64),
    /// Address of the vDSO image, when the build provides one.
    pub sysinfo_ehdr: Option<u64>,
}

/// `AT_MINSIGSTKSZ`, which glibc 2.34+ reads on aarch64 to size alternate
/// signal stacks. Absent, glibc falls back to a compile-time constant, so this
/// is advisory -- but reporting the architectural minimum is more honest than
/// silently omitting it.
fn min_sig_stack_size() -> Option<u64> {
    if cfg!(target_arch = "aarch64") {
        Some(4096)
    } else {
        None
    }
}

/// Load `path` and, if it asks for one, its program interpreter.
pub fn load_program<O: Opener, V: Vm>(
    name: &str,
    path: &[u8],
    opener: &O,
    vm: &V,
) -> Result<LoadedProgram> {
    let page = vm.page_size();

    let opened = opener.open(path)?;
    let image = Image::parse(opened.src.as_ref(), page).map_err(|r| {
        log::err(format_args!("{name}: {}", r.as_str()));
        Error::from(r)
    })?;
    loader::check_stack_request(name, &image)?;

    let interp_path = if image.needs_interp() {
        Some(image.interp_path(opened.src.as_ref())?)
    } else {
        None
    };

    let main = loader::load(name, &image, opened.src.as_ref(), opened.fd, vm)?;
    log::info(format_args!(
        "{name}: loaded to {:#x}-{:#x} ({} B), entry at {:#x}",
        main.plan.base,
        main.plan.end,
        main.plan.end - main.plan.base,
        main.plan.entry
    ));
    if !loader::entry_is_executable(&image, &main.plan) {
        log::warn(format_args!(
            "{name}: entry point {:#x} is not in an executable segment",
            main.plan.entry
        ));
    }

    let interp = match &interp_path {
        None => None,
        Some(ip) => {
            log::debug(format_args!(
                "{name}: loading program interpreter {}",
                Show(ip)
            ));
            match load_interp(ip, opener, vm, page) {
                Ok(v) => Some(v),
                Err(e) => {
                    log::err(format_args!(
                        "{name}: failed to load program interpreter {}: {e}",
                        Show(ip)
                    ));
                    main.unload(vm);
                    return Err(e);
                }
            }
        }
    };

    Ok(LoadedProgram {
        image,
        main,
        interp,
        interp_path,
    })
}

fn load_interp<O: Opener, V: Vm>(
    path: &[u8],
    opener: &O,
    vm: &V,
    page: u64,
) -> Result<(Image, Loaded)> {
    let opened = opener.open(path)?;
    let image = Image::parse(opened.src.as_ref(), page).map_err(Error::from)?;

    // An interpreter that is itself ET_EXEC would have to live at a fixed
    // address, and one with its own PT_INTERP would need a loader of its own.
    // Linux rejects both; so does this.
    if image.ehdr.e_type != ET_DYN {
        log::err(format_args!("program interpreter is not position-independent"));
        return Err(Error::ENOEXEC);
    }
    if image.needs_interp() {
        log::err(format_args!("program interpreter requests an interpreter"));
        return Err(Error::ENOEXEC);
    }

    let loaded = loader::load("<interp>", &image, opened.src.as_ref(), opened.fd, vm)?;
    log::info(format_args!(
        "<interp>: loaded to {:#x}-{:#x}, bias {:#x}, entry at {:#x}",
        loaded.plan.base, loaded.plan.end, loaded.plan.bias, loaded.plan.entry
    ));
    Ok((image, loaded))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auxv::{self, AT_BASE, AT_ENTRY, AT_PHDR};
    use crate::testutil::vm::*;
    use crate::testutil::*;
    use alloc::collections::BTreeMap;
    use alloc::vec;

    struct FakeFs {
        files: BTreeMap<Vec<u8>, Vec<u8>>,
        /// Whether to hand out descriptors, i.e. whether mmap is available.
        mappable: bool,
    }

    impl FakeFs {
        fn new(mappable: bool) -> Self {
            FakeFs {
                files: BTreeMap::new(),
                mappable,
            }
        }
        fn add(&mut self, path: &[u8], img: &TestImage, fd: i32) -> &mut Self {
            self.files.insert(path.to_vec(), img.bytes.clone());
            if self.mappable {
                install(fd, img);
            }
            self
        }
    }

    struct Owned(Vec<u8>);
    impl ImageSource for Owned {
        fn read_exact_at(&self, off: u64, buf: &mut [u8]) -> Result<()> {
            self.0.as_slice().read_exact_at(off, buf)
        }
        fn size(&self) -> Option<u64> {
            Some(self.0.len() as u64)
        }
    }

    impl Opener for FakeFs {
        fn open(&self, path: &[u8]) -> Result<Opened> {
            let data = self.files.get(path).ok_or(Error::ENOENT)?;
            // Descriptors are assigned in `add`; look the content back up to
            // find which one this is. A file that was never installed has no
            // descriptor, which drives the loader down its copy path.
            let fd = if self.mappable { fd_for(data) } else { None };
            Ok(Opened {
                src: Box::new(Owned(data.clone())),
                fd,
            })
        }
    }

    fn fd_for(data: &[u8]) -> Option<i32> {
        crate::testutil::vm::find_fd(data)
    }

    #[test]
    fn dynamic_program_jumps_into_the_interpreter() {
        let vm = FakeVm::new();
        let prog = ElfBuilder::new().glibc_arm64_style().build();
        let ld = ElfBuilder::new().pie_two_segment().build();
        let mut fs = FakeFs::new(true);
        fs.add(b"/usr/bin/node", &prog, 3)
            .add(b"/lib/ld-linux-aarch64.so.1", &ld, 4);

        let p = load_program("node", b"/usr/bin/node", &fs, &vm).unwrap();
        let (_, il) = p.interp.as_ref().unwrap();

        assert_eq!(p.entry(), il.plan.entry, "must enter the interpreter");
        assert_ne!(p.entry(), p.main.plan.entry);
        assert_eq!(p.interp_base(), il.plan.bias);
        assert_eq!(
            p.interp_path.as_deref(),
            Some(b"/lib/ld-linux-aarch64.so.1".as_slice())
        );
    }

    #[test]
    fn at_base_is_the_interpreter_bias_not_its_first_segment() {
        // Give the interpreter a non-zero first p_vaddr. The two numbers then
        // differ, and only the bias is correct.
        let vm = FakeVm::new();
        let prog = ElfBuilder::new().glibc_arm64_style().build();
        let ld = ElfBuilder::new()
            .pie_two_segment()
            .patch_phdr(0, |p| {
                p.p_offset = 0x1000;
                p.p_vaddr = 0x1000;
            })
            .patch_phdr(1, |p| {
                p.p_offset = 0x2000;
                p.p_vaddr = 0x3000;
            })
            .build();
        let mut fs = FakeFs::new(true);
        fs.add(b"/usr/bin/node", &prog, 3)
            .add(b"/lib/ld-linux-aarch64.so.1", &ld, 4);

        let p = load_program("node", b"/usr/bin/node", &fs, &vm).unwrap();
        let (_, il) = p.interp.as_ref().unwrap();
        assert_ne!(
            il.plan.bias, il.plan.base,
            "fixture should have a non-zero first p_vaddr"
        );
        assert_eq!(p.interp_base(), il.plan.bias);
    }

    #[test]
    fn program_and_interpreter_do_not_overlap() {
        let vm = FakeVm::new();
        let prog = ElfBuilder::new().glibc_arm64_style().build();
        let ld = ElfBuilder::new().glibc_arm64_style().no_interp().build();
        let mut fs = FakeFs::new(true);
        fs.add(b"/usr/bin/node", &prog, 3)
            .add(b"/lib/ld-linux-aarch64.so.1", &ld, 4);

        let p = load_program("node", b"/usr/bin/node", &fs, &vm).unwrap();
        let (_, il) = p.interp.as_ref().unwrap();
        let a = (
            p.main.plan.reserve_addr,
            p.main.plan.reserve_addr + p.main.plan.reserve_len,
        );
        let b = (
            il.plan.reserve_addr,
            il.plan.reserve_addr + il.plan.reserve_len,
        );
        assert!(a.1 <= b.0 || b.1 <= a.0, "{a:#x?} overlaps {b:#x?}");
    }

    #[test]
    fn auxv_describes_the_program_not_the_interpreter() {
        let vm = FakeVm::new();
        let prog = ElfBuilder::new().glibc_arm64_style().build();
        let ld = ElfBuilder::new().pie_two_segment().build();
        let mut fs = FakeFs::new(true);
        fs.add(b"/usr/bin/node", &prog, 3)
            .add(b"/lib/ld-linux-aarch64.so.1", &ld, 4);
        let p = load_program("node", b"/usr/bin/node", &fs, &vm).unwrap();

        let a = p.auxv(&Environment {
            page_size: 4096,
            platform: b"aarch64",
            execfn: b"/usr/bin/node",
            random: [7u8; 16],
            uid: 0,
            gid: 0,
            hwcap: (0, 0),
            sysinfo_ehdr: None,
        });
        // AT_ENTRY is the *program's* entry even though control starts in the
        // interpreter; ld.so uses it to find the executable it is loading for.
        assert_eq!(a.entry, p.main.plan.entry);
        assert_eq!(a.base, p.interp_base());
        assert_eq!(a.phnum, p.image.ehdr.e_phnum as u64);
        assert_eq!(a.phdr, Some(p.main.plan.phdr_addr(&p.image).unwrap()));

        // And the numbers survive a round trip through a real stack.
        let mut st = FakeStack::new(0x7000_0000, 64 * 1024);
        let l = auxv::build_stack(&mut st, &[b"node"], &[], &a).unwrap();
        assert_eq!(st.auxv_value(l.sp, AT_ENTRY), Some(p.main.plan.entry));
        assert_eq!(st.auxv_value(l.sp, AT_BASE), Some(p.interp_base()));
        assert_eq!(
            st.auxv_value(l.sp, AT_PHDR),
            Some(p.main.plan.phdr_addr(&p.image).unwrap())
        );
    }

    #[test]
    fn a_static_program_needs_no_interpreter() {
        let vm = FakeVm::new();
        let prog = ElfBuilder::new().pie_two_segment().build();
        let mut fs = FakeFs::new(true);
        fs.add(b"/bin/hello", &prog, 3);
        let p = load_program("hello", b"/bin/hello", &fs, &vm).unwrap();
        assert!(p.interp.is_none());
        assert_eq!(p.entry(), p.main.plan.entry);
        assert_eq!(p.interp_base(), 0);
    }

    #[test]
    fn a_missing_interpreter_unloads_the_program() {
        let vm = FakeVm::new();
        let prog = ElfBuilder::new().glibc_arm64_style().build();
        let mut fs = FakeFs::new(true);
        fs.add(b"/usr/bin/node", &prog, 3);
        assert_eq!(
            load_program("node", b"/usr/bin/node", &fs, &vm).unwrap_err(),
            Error::ENOENT
        );
        assert!(
            vm.regions().is_empty(),
            "the program stayed mapped after the interpreter failed: {:#x?}",
            vm.regions()
        );
    }

    #[test]
    fn an_interpreter_that_is_not_pie_is_refused() {
        let vm = FakeVm::new();
        let prog = ElfBuilder::new().glibc_arm64_style().build();
        let ld = ElfBuilder::new().non_pie().build();
        let mut fs = FakeFs::new(true);
        fs.add(b"/usr/bin/node", &prog, 3)
            .add(b"/lib/ld-linux-aarch64.so.1", &ld, 4);
        assert_eq!(
            load_program("node", b"/usr/bin/node", &fs, &vm).unwrap_err(),
            Error::ENOEXEC
        );
        assert!(vm.regions().is_empty());
    }

    #[test]
    fn an_executable_stack_request_is_refused() {
        let vm = FakeVm::new();
        let prog = ElfBuilder::new().pie_two_segment().exec_stack().build();
        let mut fs = FakeFs::new(true);
        fs.add(b"/bin/trampoline", &prog, 3);
        assert_eq!(
            load_program("t", b"/bin/trampoline", &fs, &vm).unwrap_err(),
            Error::ENOTSUP
        );
        assert!(vm.regions().is_empty());
    }

    #[test]
    fn a_non_pie_program_loads_at_its_link_address() {
        let vm = FakeVm::new();
        let prog = ElfBuilder::new().non_pie().build();
        let mut fs = FakeFs::new(true);
        fs.add(b"/bin/static", &prog, 3);
        let p = load_program("static", b"/bin/static", &fs, &vm).unwrap();
        assert_eq!(p.main.plan.bias, 0);
        assert_eq!(p.main.plan.base, 0x400000);
        assert_eq!(p.entry(), 0x400500);

        let a = p.auxv(&Environment {
            page_size: 4096,
            platform: b"x86_64",
            execfn: b"/bin/static",
            random: [0; 16],
            uid: 0,
            gid: 0,
            hwcap: (0, 0),
            sysinfo_ehdr: None,
        });
        // With a zero bias, AT_PHDR is just the link-time address.
        assert_eq!(a.phdr, Some(0x400000 + p.image.ehdr.e_phoff));
        assert_eq!(a.base, 0);
    }

    #[test]
    fn a_bad_program_is_not_loaded_at_all() {
        let vm = FakeVm::new();
        let mut fs = FakeFs::new(true);
        let junk = TestImage {
            bytes: vec![0x41; 4096],
        };
        fs.files.insert(b"/bin/junk".to_vec(), junk.bytes.clone());
        assert_eq!(
            load_program("junk", b"/bin/junk", &fs, &vm).unwrap_err(),
            Error::ENOEXEC
        );
        assert!(vm.regions().is_empty());
    }
}
