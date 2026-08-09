// SPDX-License-Identifier: BSD-3-Clause
//! The bits a freestanding Rust crate has to supply itself: a heap and a way
//! to die.

use crate::sys::ffi;
use core::alloc::{GlobalAlloc, Layout};
use core::ffi::c_void;

/// Routes Rust's allocator to Unikraft's default heap, so the loader shares an
/// allocator with the rest of the unikernel rather than carving out its own.
struct UkHeap;

unsafe impl GlobalAlloc for UkHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // `uk_memalign` handles the plain case too, and Rust's `Layout` always
        // carries an alignment, so there is no reason to split the two.
        unsafe { ffi::elfrs_memalign(layout.align() as u64, layout.size() as u64) as *mut u8 }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        unsafe { ffi::elfrs_free(ptr as *mut c_void) }
    }
}

#[global_allocator]
static HEAP: UkHeap = UkHeap;

/// Panics become `UK_CRASH`.
///
/// The crate is built with `panic = "abort"` and `overflow-checks = on`: a
/// wrapped arithmetic operation while parsing a hostile ELF header stops the
/// unikernel with a message naming the file and line, rather than continuing
/// with a nonsensical address.
#[panic_handler]
fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    use core::fmt::Write;

    // Deliberately small and stack-allocated: the heap may be what failed.
    struct Buf {
        b: [u8; 256],
        n: usize,
    }
    impl Write for Buf {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            let room = self.b.len() - 1 - self.n;
            let take = s.len().min(room);
            self.b[self.n..self.n + take].copy_from_slice(&s.as_bytes()[..take]);
            self.n += take;
            Ok(())
        }
    }

    let mut buf = Buf { b: [0; 256], n: 0 };
    let _ = write!(buf, "elfloader panic: {info}");
    buf.b[buf.n] = 0;

    // SAFETY: NUL-terminated, and `elfrs_crash` does not return.
    unsafe { ffi::elfrs_crash(buf.b.as_ptr() as *const core::ffi::c_char) }
}
