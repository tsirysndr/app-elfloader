// SPDX-License-Identifier: BSD-3-Clause
//! A Rust rewrite of Unikraft's `app-elfloader`: it loads an unmodified Linux
//! ELF executable, and its dynamic linker, into a unikernel and starts it.
//!
//! Layout of the crate:
//!
//! | module    | what it does                                  | tested on host |
//! |-----------|-----------------------------------------------|----------------|
//! | `elf`     | bounds-checked ELF64 header parsing           | yes            |
//! | `layout`  | turns headers into a concrete plan of mappings| yes            |
//! | `loader`  | executes a plan against a `Vm`                | yes, with a fake |
//! | `auxv`    | builds the initial stack (argv/envp/auxv)     | yes, with a fake |
//! | `sys`     | the Unikraft `Vm`/file/thread implementations | no             |
//! | `app`     | the `main()` the unikernel boots into         | no             |
//! | `binfmt`  | `libukbinfmt` registration for `execve`       | no             |
//!
//! The split is deliberate: everything that decides *what* to map is pure and
//! runs under `cargo test` on a developer machine, so the cases that are
//! painful to reach by booting -- a non-PIE at its link address, arm64's
//! 64 KiB segment alignment over a 4 KiB page, a truncated or hostile header
//! -- are covered without a unikernel in the loop.

#![cfg_attr(not(test), no_std)]
// Rust's `unused` lints do not know that `#[no_mangle] extern "C"` items are
// the entry points; and the FFI layer intentionally mirrors C names.
#![allow(clippy::missing_safety_doc)]
#![deny(unsafe_op_in_unsafe_fn)]

extern crate alloc;

#[cfg(test)]
extern crate std;

pub mod auxv;
pub mod elf;
pub mod err;
pub mod layout;
pub mod loader;
pub mod program;
pub mod log;
pub mod util;

#[cfg(test)]
mod testutil;

#[cfg(not(test))]
mod app;
#[cfg(not(test))]
mod binfmt;
#[cfg(not(test))]
mod rt;
#[cfg(not(test))]
mod sys;
