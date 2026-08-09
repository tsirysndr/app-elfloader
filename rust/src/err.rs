// SPDX-License-Identifier: BSD-3-Clause
//! Errors, shaped as POSIX errnos because that is what crosses back into C.

use core::fmt;

/// A negatable POSIX error number. Stored positive; `as_neg()` is what the C
/// side expects.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Error(pub i32);

impl Error {
    pub const fn as_neg(self) -> i32 {
        -self.0
    }
}

macro_rules! errnos {
    ($($name:ident = $val:expr, $desc:expr;)*) => {
        impl Error {
            $(pub const $name: Error = Error($val);)*

            pub fn as_str(self) -> &'static str {
                match self.0 {
                    $($val => $desc,)*
                    _ => "unknown error",
                }
            }
        }
    };
}

// Values are the Linux/asm-generic ones, which is what Unikraft uses.
errnos! {
    EPERM   =  1, "operation not permitted";
    ENOENT  =  2, "no such file or directory";
    EIO     =  5, "input/output error";
    E2BIG   =  7, "argument list too long";
    ENOEXEC =  8, "exec format error";
    EBADF   =  9, "bad file descriptor";
    ENOMEM  = 12, "cannot allocate memory";
    EFAULT  = 14, "bad address";
    EINVAL  = 22, "invalid argument";
    ENOSPC  = 28, "no space left on device";
    ERANGE  = 34, "numerical result out of range";
    ENOSYS  = 38, "function not implemented";
    ELOOP   = 40, "too many levels of symbolic links";
    ENOTSUP = 95, "operation not supported";
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.as_str(), self.0)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

pub type Result<T> = core::result::Result<T, Error>;

/// Turn a negative-errno C return into a `Result`.
pub fn from_c(rc: i64) -> Result<i64> {
    if rc < 0 {
        Err(Error(-rc as i32))
    } else {
        Ok(rc)
    }
}
