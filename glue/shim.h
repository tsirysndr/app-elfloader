/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Flat C ABI between the Rust loader core and Unikraft.
 *
 * Everything Unikraft exposes as a macro, a `static inline`, or a struct whose
 * layout is a build-time detail lives behind one of these functions. The Rust
 * side therefore never needs a bindgen pass and never encodes a struct offset,
 * so a Unikraft bump can change `struct uk_thread` without silently corrupting
 * the loader.
 *
 * Naming: every symbol crossing the boundary is prefixed `elfrs_`. Functions
 * defined here and called from Rust are declared in this header; functions
 * defined in Rust and called from here are declared at the bottom.
 */

#ifndef ELFRS_SHIM_H
#define ELFRS_SHIM_H

#include <uk/config.h>
#include <uk/essentials.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Kernel log levels, decoupled from uk/print.h's numbering. */
#define ELFRS_LVL_ERR	0
#define ELFRS_LVL_WARN	1
#define ELFRS_LVL_INFO	2
#define ELFRS_LVL_DEBUG	3

/* Protection bits, decoupled from the platform's PROT_*. Rust speaks these. */
#define ELFRS_PROT_NONE		0x0
#define ELFRS_PROT_READ		0x1
#define ELFRS_PROT_WRITE	0x2
#define ELFRS_PROT_EXEC		0x4

/* Mapping kinds for elfrs_map(). */
#define ELFRS_MAP_ANON	0
#define ELFRS_MAP_FILE	1

/*
 * Compile-time configuration, handed to Rust as data rather than as a pile of
 * `--cfg` flags, so that a Kconfig rename shows up as a C build error here
 * instead of as a silently-dead `#[cfg]` branch over there.
 */
struct elfrs_cfg {
	uint32_t stack_len;	/* application stack, bytes */
	uint32_t page_size;
	uint32_t uid;
	uint32_t gid;

	uint8_t have_vfs;
	uint8_t have_mmap;	/* CONFIG_LIBPOSIX_MMAP */
	uint8_t have_vmem;	/* CONFIG_LIBUKVMEM */
	uint8_t have_environ;
	uint8_t have_random;
	uint8_t have_pthread;	/* CONFIG_LIBPOSIX_PROCESS_MULTITHREADING */

	uint8_t vfsexec;	/* load from VFS (vs. initrd) */
	uint8_t customappname;	/* program name comes from the command line */
	uint8_t envpath;	/* resolve the program through $PATH */
	uint8_t envpwd;		/* chdir($PWD) before starting */
	uint8_t execbit;	/* require the executable bit */
	uint8_t debug;

	const char *vfsexec_path;	/* compiled-in path, or NULL */
	uint64_t vdso_addr;		/* 0 when CONFIG_APPELFLOADER_VDSO=n */
};

void elfrs_cfg_get(struct elfrs_cfg *out);

/* --- diagnostics ------------------------------------------------------- */

void elfrs_printk(int lvl, const char *msg);
void elfrs_crash(const char *msg) __noreturn;

/* --- allocation -------------------------------------------------------- */

void *elfrs_malloc(unsigned long size);
void *elfrs_memalign(unsigned long align, unsigned long size);
void elfrs_free(void *ptr);

/* --- virtual memory ---------------------------------------------------- */

/*
 * Map `len` bytes at `addr`.
 *
 * addr == 0            let the system place the mapping
 * addr != 0, replace=0  a hint: the mapping may come back elsewhere, and the
 *                       caller must check. Nothing existing is displaced.
 * addr != 0, replace=1  MAP_FIXED: exactly there, replacing whatever is in the
 *                       way. Only used to fill in a reservation this loader
 *                       already holds.
 *
 * Returns the mapped address, or 0 on failure with -errno stored in *err.
 */
unsigned long elfrs_map(unsigned long addr, unsigned long len, int prot,
			int kind, int fd, long off, int replace, int *err);
int elfrs_unmap(unsigned long addr, unsigned long len);

/*
 * Change the protection of an already-mapped range. Uses mprotect() when
 * CONFIG_LIBPOSIX_MMAP is on and uk_vma_set_attr() otherwise, so the loader's
 * copy path gets page protections too.
 */
int elfrs_protect(unsigned long addr, unsigned long len, int prot);

/* --- files ------------------------------------------------------------- */

int elfrs_open_ro(const char *path);		/* fd, or -errno */
void elfrs_close(int fd);
long elfrs_pread(int fd, void *buf, unsigned long len, long off);
long elfrs_fsize(int fd);			/* size, or -errno */
int elfrs_fd_is_exec(int fd);			/* 0, or -errno */
int elfrs_path_is_exec(const char *path);	/* 0, or -errno */

/* --- process environment ----------------------------------------------- */

const char *const *elfrs_environ(void);
const char *elfrs_getenv(const char *name);
int elfrs_chdir(const char *path);
int elfrs_random_fill(void *buf, unsigned long len);

/* --- initrd ------------------------------------------------------------ */

int elfrs_initrd(unsigned long *base, unsigned long *len);

/* --- threads and contexts ---------------------------------------------- */

/*
 * The loader treats `struct uk_thread` and `struct ukarch_ctx` as opaque. In
 * the binfmt case the context is owned by libukbinfmt and there is no thread
 * yet, which is why context access is not folded into the thread handle.
 */
void *elfrs_thread_create(const char *name, unsigned long stack_len);
void elfrs_thread_release(void *thread);
void *elfrs_thread_ctx(void *thread);
unsigned long elfrs_thread_stack_base(void *thread);
void elfrs_thread_set_runnable(void *thread);
int elfrs_thread_make_pthread(void *thread);
int elfrs_thread_schedule(void *thread);
void elfrs_wait_forever(void) __noreturn;

unsigned long elfrs_ctx_get_sp(void *ctx);
void elfrs_ctx_init(void *ctx, unsigned long sp, unsigned long ip);

/* --- architecture ------------------------------------------------------ */

/*
 * Make `len` bytes of freshly written memory at `addr` visible to instruction
 * fetch. A no-op where the caches are coherent with respect to instruction
 * fetch (x86_64); real cache maintenance on arm64.
 */
void elfrs_icache_sync(unsigned long addr, unsigned long len);

/* Values for AT_HWCAP / AT_HWCAP2, derived from what the guest can actually
 * use (which is not the same as what the CPU implements: FP/SIMD is gated on
 * CONFIG_FPSIMD).
 */
uint64_t elfrs_hwcap(void);
uint64_t elfrs_hwcap2(void);
const char *elfrs_platform(void);

/* --- implemented in Rust ----------------------------------------------- */

int elfrs_main(int argc, const char *argv[]);

#ifdef __cplusplus
}
#endif

#endif /* ELFRS_SHIM_H */
