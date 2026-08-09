// SPDX-License-Identifier: BSD-3-Clause
//! Kernel logging.
//!
//! Unikraft's `uk_pr_*` are macros, so they cannot be called from Rust
//! directly; messages are formatted here into a stack buffer and handed to
//! `elfrs_printk()`. Under `cargo test` they go to stderr instead, which keeps
//! the core modules testable without a Unikraft build.

use core::fmt::{self, Write};

pub const LVL_ERR: i32 = 0;
pub const LVL_WARN: i32 = 1;
pub const LVL_INFO: i32 = 2;
pub const LVL_DEBUG: i32 = 3;

/// Longest message emitted in one call. Long enough for a path plus a couple
/// of addresses; anything longer is truncated with an ellipsis rather than
/// dropped, so a truncated log line is still recognisable as one.
const MSG_MAX: usize = 512;

struct Buf {
    b: [u8; MSG_MAX],
    n: usize,
    truncated: bool,
}

impl Buf {
    fn new() -> Self {
        Buf {
            b: [0; MSG_MAX],
            n: 0,
            truncated: false,
        }
    }

    fn finish(&mut self) -> &[u8] {
        if self.truncated && self.n >= 4 {
            self.b[self.n - 4..self.n].copy_from_slice(b"...\0");
        } else {
            self.b[self.n] = 0;
            self.n += 1;
        }
        &self.b[..self.n]
    }
}

impl Write for Buf {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let room = MSG_MAX - 1 - self.n;
        let take = s.len().min(room);
        if take < s.len() {
            self.truncated = true;
        }
        self.b[self.n..self.n + take].copy_from_slice(&s.as_bytes()[..take]);
        self.n += take;
        Ok(())
    }
}

#[cfg(not(test))]
fn emit(lvl: i32, args: fmt::Arguments<'_>) {
    let mut b = Buf::new();
    let _ = b.write_fmt(args);
    let msg = b.finish();
    // SAFETY: `msg` is NUL-terminated by `finish` and lives until the call
    // returns; `elfrs_printk` copies it into the kernel log.
    unsafe { crate::sys::ffi::elfrs_printk(lvl, msg.as_ptr() as *const core::ffi::c_char) }
}

#[cfg(test)]
fn emit(lvl: i32, args: fmt::Arguments<'_>) {
    let tag = match lvl {
        LVL_ERR => "ERR",
        LVL_WARN => "WARN",
        LVL_INFO => "INFO",
        _ => "DBG",
    };
    // Exercise the same truncation path the unikernel uses, so a message that
    // would be mangled there is mangled here too.
    let mut b = Buf::new();
    let _ = b.write_fmt(args);
    let msg = b.finish();
    std::eprintln!(
        "[{tag}] {}",
        core::str::from_utf8(&msg[..msg.len() - 1]).unwrap_or("<invalid utf-8>")
    );
}

pub fn err(args: fmt::Arguments<'_>) {
    emit(LVL_ERR, args);
}

pub fn warn(args: fmt::Arguments<'_>) {
    emit(LVL_WARN, args);
}

pub fn info(args: fmt::Arguments<'_>) {
    emit(LVL_INFO, args);
}

pub fn debug(args: fmt::Arguments<'_>) {
    emit(LVL_DEBUG, args);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncates_instead_of_overflowing() {
        let mut b = Buf::new();
        let long: String = "x".repeat(MSG_MAX * 2);
        let _ = write!(b, "{long}");
        let msg = b.finish();
        assert!(msg.len() <= MSG_MAX);
        assert_eq!(&msg[msg.len() - 4..], b"...\0");
    }

    #[test]
    fn short_messages_are_nul_terminated_verbatim() {
        let mut b = Buf::new();
        let _ = write!(b, "hello {}", 42);
        assert_eq!(b.finish(), b"hello 42\0");
    }
}
