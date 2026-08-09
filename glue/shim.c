/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * The C half of the boundary described in shim.h.
 *
 * Every Unikraft macro, `static inline` and struct layout the loader depends
 * on is resolved here. Keeping it in C rather than in a bindgen pass means a
 * Unikraft API change is a compile error in this file, at the line that uses
 * it, instead of a silently wrong offset at run time.
 */

#include "shim.h"

#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>

#include <uk/assert.h>
#include <uk/print.h>
#include <uk/alloc.h>
#include <uk/arch/ctx.h>
#include <uk/arch/limits.h>
#include <uk/essentials.h>
#include <uk/plat/memory.h>
#include <uk/sched.h>
#include <uk/thread.h>

#if CONFIG_HAVE_VFS
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#endif /* CONFIG_HAVE_VFS */

#if CONFIG_LIBPOSIX_MMAP
#include <sys/mman.h>
#endif /* CONFIG_LIBPOSIX_MMAP */

#if CONFIG_LIBUKVMEM
#include <uk/vmem.h>
#include <uk/paging.h>
#endif /* CONFIG_LIBUKVMEM */

#if CONFIG_LIBUKRANDOM
#include <uk/random.h>
#endif /* CONFIG_LIBUKRANDOM */

#if CONFIG_LIBPOSIX_PROCESS
#include <uk/process.h>
#endif /* CONFIG_LIBPOSIX_PROCESS */

#if CONFIG_LIBPOSIX_ENVIRON
extern const char **environ;
#endif /* CONFIG_LIBPOSIX_ENVIRON */

#if CONFIG_APPELFLOADER_VDSO
extern char *vdso_image_addr;
#endif /* CONFIG_APPELFLOADER_VDSO */

#ifndef PAGES2BYTES
#define PAGES2BYTES(x) ((x) << __PAGE_SHIFT)
#endif

/*
 * Kconfig booleans are `#define CONFIG_X 1` when set and simply absent when
 * not, so they work in `#if` but not in a C expression. This is Linux's
 * IS_ENABLED() trick, which yields 1 or 0 either way and lets the config be
 * filled in as plain assignments rather than a dozen #if blocks.
 */
#define ELFRS_PLACEHOLDER_1	0,
#define ELFRS_SECOND(ignored, val, ...)	val
#define ELFRS_ON3(arg)		ELFRS_SECOND(arg 1, 0)
#define ELFRS_ON2(val)		ELFRS_ON3(ELFRS_PLACEHOLDER_##val)
#define ELFRS_ON(cfg)		ELFRS_ON2(cfg)

/* --- configuration ------------------------------------------------------ */

void elfrs_cfg_get(struct elfrs_cfg *out)
{
	UK_ASSERT(out);
	memset(out, 0, sizeof(*out));

	out->stack_len = PAGES2BYTES(CONFIG_APPELFLOADER_STACK_NBPAGES);
	out->page_size = __PAGE_SIZE;

#if CONFIG_LIBPOSIX_USER
	out->uid = CONFIG_LIBPOSIX_USER_UID;
	out->gid = CONFIG_LIBPOSIX_USER_GID;
#endif /* CONFIG_LIBPOSIX_USER */

	out->have_vfs     = ELFRS_ON(CONFIG_HAVE_VFS);
	out->have_mmap    = ELFRS_ON(CONFIG_LIBPOSIX_MMAP);
	out->have_vmem    = ELFRS_ON(CONFIG_LIBUKVMEM);
	out->have_environ = ELFRS_ON(CONFIG_LIBPOSIX_ENVIRON);
	out->have_random  = ELFRS_ON(CONFIG_LIBUKRANDOM);
	out->have_pthread = ELFRS_ON(CONFIG_LIBPOSIX_PROCESS_MULTITHREADING);

	out->vfsexec       = ELFRS_ON(CONFIG_APPELFLOADER_VFSEXEC);
	out->customappname = ELFRS_ON(CONFIG_APPELFLOADER_CUSTOMAPPNAME);
	out->envpath       = ELFRS_ON(CONFIG_APPELFLOADER_VFSEXEC_ENVPATH);
	out->envpwd        = ELFRS_ON(CONFIG_APPELFLOADER_VFSEXEC_ENVPWD);
	out->execbit       = ELFRS_ON(CONFIG_APPELFLOADER_VFSEXEC_EXECBIT);
	out->debug         = ELFRS_ON(CONFIG_APPELFLOADER_DEBUG);

#if CONFIG_APPELFLOADER_VFSEXEC && !CONFIG_APPELFLOADER_CUSTOMAPPNAME
	out->vfsexec_path = CONFIG_APPELFLOADER_VFSEXEC_PATH;
#else
	out->vfsexec_path = NULL;
#endif

#if CONFIG_APPELFLOADER_VDSO
	out->vdso_addr = (uint64_t)(uintptr_t)vdso_image_addr;
#endif /* CONFIG_APPELFLOADER_VDSO */
}

/* --- diagnostics -------------------------------------------------------- */

void elfrs_printk(int lvl, const char *msg)
{
#if CONFIG_APPELFLOADER_DEBUG
	/*
	 * Force every loader message out at error level.
	 *
	 * The kernel log level is a Kconfig `choice`, so it usually sits at
	 * KLVL_ERR and cannot be raised from a Kraftfile at all. Without this,
	 * turning APPELFLOADER_DEBUG on compiles the messages in and then
	 * filters every one of them away, which makes the option look broken.
	 */
	uk_pr_err("%s\n", msg);
	(void)lvl;
#else /* !CONFIG_APPELFLOADER_DEBUG */
	switch (lvl) {
	case ELFRS_LVL_ERR:
		uk_pr_err("%s\n", msg);
		break;
	case ELFRS_LVL_WARN:
		uk_pr_warn("%s\n", msg);
		break;
	case ELFRS_LVL_INFO:
		uk_pr_info("%s\n", msg);
		break;
	default:
		uk_pr_debug("%s\n", msg);
		break;
	}
#endif /* !CONFIG_APPELFLOADER_DEBUG */
}

void elfrs_crash(const char *msg)
{
	UK_CRASH("%s\n", msg);
}

/* --- allocation --------------------------------------------------------- */

void *elfrs_malloc(unsigned long size)
{
	return uk_malloc(uk_alloc_get_default(), (__sz)size);
}

void *elfrs_memalign(unsigned long align, unsigned long size)
{
	/* Rust's Layout permits an alignment of 1; uk_memalign wants at least
	 * a power of two that the allocator can honour, and every allocator
	 * gives back at least pointer alignment anyway.
	 */
	if (align < sizeof(void *))
		align = sizeof(void *);
	return uk_memalign(uk_alloc_get_default(), (__sz)align, (__sz)size);
}

void elfrs_free(void *ptr)
{
	uk_free(uk_alloc_get_default(), ptr);
}

/* --- virtual memory ----------------------------------------------------- */

#if CONFIG_LIBPOSIX_MMAP
static int elfrs_to_prot(int prot)
{
	int p = PROT_NONE;

	if (prot & ELFRS_PROT_READ)
		p |= PROT_READ;
	if (prot & ELFRS_PROT_WRITE)
		p |= PROT_WRITE;
	if (prot & ELFRS_PROT_EXEC)
		p |= PROT_EXEC;
	return p;
}

unsigned long elfrs_map(unsigned long addr, unsigned long len, int prot,
			int kind, int fd, long off, int replace, int *err)
{
	int flags = MAP_PRIVATE;
	void *got;

	if (kind == ELFRS_MAP_ANON) {
		flags |= MAP_ANONYMOUS;
		fd = -1;
		off = 0;
	}
	if (addr && replace)
		flags |= MAP_FIXED;

	got = mmap((void *)addr, (size_t)len, elfrs_to_prot(prot), flags,
		   fd, (off_t)off);
	if (got == MAP_FAILED) {
		if (err)
			*err = errno ? errno : ENOMEM;
		return 0;
	}
	if (err)
		*err = 0;
	return (unsigned long)got;
}

int elfrs_unmap(unsigned long addr, unsigned long len)
{
	if (munmap((void *)addr, (size_t)len) < 0)
		return -errno;
	return 0;
}

int elfrs_protect(unsigned long addr, unsigned long len, int prot)
{
	if (mprotect((void *)addr, (size_t)len, elfrs_to_prot(prot)) < 0)
		return -errno;
	return 0;
}
#else /* !CONFIG_LIBPOSIX_MMAP */
unsigned long elfrs_map(unsigned long addr __unused, unsigned long len __unused,
			int prot __unused, int kind __unused, int fd __unused,
			long off __unused, int replace __unused, int *err)
{
	if (err)
		*err = ENOSYS;
	return 0;
}

int elfrs_unmap(unsigned long addr __unused, unsigned long len __unused)
{
	return -ENOSYS;
}

int elfrs_protect(unsigned long addr __maybe_unused,
		  unsigned long len __maybe_unused, int prot __maybe_unused)
{
#if CONFIG_LIBUKVMEM
	/* No mmap, but there is still a page table worth setting up: this is
	 * what gives the copy path W^X.
	 */
	struct uk_vas *vas = uk_vas_get_active();
	unsigned long attr = 0;
	__vaddr_t start;
	__sz vlen;

	if (unlikely(PTRISERR(vas)))
		return -ENOTSUP;

	if (prot & ELFRS_PROT_READ)
		attr |= UK_PAGING_PAGE_ATTR_PROT_READ;
	if (prot & ELFRS_PROT_WRITE)
		attr |= UK_PAGING_PAGE_ATTR_PROT_WRITE;
	if (prot & ELFRS_PROT_EXEC)
		attr |= UK_PAGING_PAGE_ATTR_PROT_EXEC;

	start = UK_PAGING_PAGE_ALIGN_DOWN(addr);
	vlen  = UK_PAGING_PAGE_ALIGN_UP(addr + len) - start;

	return uk_vma_set_attr(vas, start, vlen, attr, 0);
#else /* !CONFIG_LIBUKVMEM */
	return -ENOTSUP;
#endif /* !CONFIG_LIBUKVMEM */
}
#endif /* !CONFIG_LIBPOSIX_MMAP */

/* --- files -------------------------------------------------------------- */

#if CONFIG_HAVE_VFS
int elfrs_open_ro(const char *path)
{
	int fd = open(path, O_RDONLY);

	return (fd < 0) ? -errno : fd;
}

void elfrs_close(int fd)
{
	if (fd >= 0)
		close(fd);
}

long elfrs_pread(int fd, void *buf, unsigned long len, long off)
{
	ssize_t rc;

	do {
		rc = pread(fd, buf, (size_t)len, (off_t)off);
	} while (rc < 0 && errno == EINTR);

	return (rc < 0) ? -errno : (long)rc;
}

long elfrs_fsize(int fd)
{
	struct stat st;

	if (fstat(fd, &st) < 0)
		return -errno;
	return (long)st.st_size;
}

int elfrs_fd_is_exec(int fd)
{
	struct stat st;

	if (fstat(fd, &st) < 0)
		return -errno;
	if (!S_ISREG(st.st_mode))
		return -EACCES;
	if (!(st.st_mode & S_IXUSR))
		return -EACCES;
	return 0;
}

int elfrs_path_is_exec(const char *path)
{
	struct stat st;

	if (stat(path, &st) < 0)
		return -errno;
	if (!S_ISREG(st.st_mode))
		return -EACCES;
#if CONFIG_APPELFLOADER_VFSEXEC_EXECBIT
	if (!(st.st_mode & S_IXUSR))
		return -EACCES;
#endif /* CONFIG_APPELFLOADER_VFSEXEC_EXECBIT */
	return 0;
}
#else /* !CONFIG_HAVE_VFS */
int elfrs_open_ro(const char *path __unused)
{
	return -ENOSYS;
}
void elfrs_close(int fd __unused) {}
long elfrs_pread(int fd __unused, void *buf __unused,
		 unsigned long len __unused, long off __unused)
{
	return -ENOSYS;
}
long elfrs_fsize(int fd __unused)
{
	return -ENOSYS;
}
int elfrs_fd_is_exec(int fd __unused)
{
	return -ENOSYS;
}
int elfrs_path_is_exec(const char *path __unused)
{
	return -ENOSYS;
}
#endif /* !CONFIG_HAVE_VFS */

/* --- process environment ------------------------------------------------ */

const char *const *elfrs_environ(void)
{
#if CONFIG_LIBPOSIX_ENVIRON
	return (const char *const *)environ;
#else
	return NULL;
#endif
}

const char *elfrs_getenv(const char *name)
{
#if CONFIG_LIBPOSIX_ENVIRON
	return getenv(name);
#else
	(void)name;
	return NULL;
#endif
}

int elfrs_chdir(const char *path)
{
#if CONFIG_HAVE_VFS
	if (chdir(path) < 0)
		return -errno;
	return 0;
#else
	(void)path;
	return -ENOSYS;
#endif
}

int elfrs_random_fill(void *buf, unsigned long len)
{
#if CONFIG_LIBUKRANDOM
	return uk_random_fill_buffer(buf, (__sz)len);
#else
	(void)buf;
	(void)len;
	return -ENOTSUP;
#endif
}

/* --- initrd ------------------------------------------------------------- */

int elfrs_initrd(unsigned long *base, unsigned long *len)
{
	struct ukplat_memregion_desc *img;
	int rc;

	UK_ASSERT(base && len);

	rc = ukplat_memregion_find_initrd0(&img);
	if (rc < 0 || !img->vbase || !img->len)
		return -ENOENT;

	*base = (unsigned long)img->vbase;
	*len  = (unsigned long)img->len;
	return 0;
}

/* --- threads and contexts ----------------------------------------------- */

void *elfrs_thread_create(const char *name, unsigned long stack_len)
{
	struct uk_sched *s = uk_sched_current();

	UK_ASSERT(s);

	return uk_thread_create_container(uk_alloc_get_default(),
					  s->a_stack, (__sz)stack_len,
					  s->a_auxstack, 0,
					  s->a_uktls,
					  false, name, NULL, NULL);
}

void elfrs_thread_release(void *thread)
{
	if (thread)
		uk_thread_release((struct uk_thread *)thread);
}

void *elfrs_thread_ctx(void *thread)
{
	UK_ASSERT(thread);
	return &((struct uk_thread *)thread)->ctx;
}

unsigned long elfrs_thread_stack_base(void *thread)
{
	UK_ASSERT(thread);
	return (unsigned long)((struct uk_thread *)thread)->_mem.stack;
}

void elfrs_thread_set_runnable(void *thread)
{
	UK_ASSERT(thread);
	((struct uk_thread *)thread)->flags |= UK_THREADF_RUNNABLE;
}

int elfrs_thread_make_pthread(void *thread __maybe_unused)
{
#if CONFIG_LIBPOSIX_PROCESS_MULTITHREADING
	return uk_posix_process_create_pthread((struct uk_thread *)thread);
#else
	return 0;
#endif
}

int elfrs_thread_schedule(void *thread)
{
	struct uk_sched *s = uk_sched_current();

	UK_ASSERT(s);
	UK_ASSERT(thread);

	uk_sched_thread_add(s, (struct uk_thread *)thread);
	return 0;
}

void elfrs_wait_forever(void)
{
	/*
	 * There is still no way to wait for the application to exit: uksched
	 * has no thread-join and posix-process does not expose one. Upstream
	 * loops on sleep(10); blocking the thread outright is the same thing
	 * without waking up six times a minute to do nothing.
	 */
	for (;;)
		uk_sched_thread_sleep(__NSEC_MAX);
}

unsigned long elfrs_ctx_get_sp(void *ctx)
{
	UK_ASSERT(ctx);
	return (unsigned long)((struct ukarch_ctx *)ctx)->sp;
}

void elfrs_ctx_init(void *ctx, unsigned long sp, unsigned long ip)
{
	UK_ASSERT(ctx);
	UK_ASSERT(IS_ALIGNED(sp, UKARCH_SP_ALIGN));

	/* Enter with cleared registers, as the psABI requires for _start. */
	ukarch_ctx_init((struct ukarch_ctx *)ctx, (__uptr)sp, 0x0, (__uptr)ip);
}

/* --- architecture ------------------------------------------------------- */

#if CONFIG_ARCH_ARM_64
/*
 * arm64 instruction and data caches are not coherent with each other. Code
 * written through the data side is not guaranteed to be seen by instruction
 * fetch until it has been cleaned to the point of unification and the
 * instruction cache has been invalidated for those addresses.
 *
 * Unikraft has `invalidate_icache_range()` in plat/common/arm/cache64.S, but
 * nothing outside the GDB stub calls it, so the loader has to do this itself
 * for any code it writes with ordinary stores.
 */
void invalidate_icache_range(__sz addr, __sz len);

void elfrs_icache_sync(unsigned long addr, unsigned long len)
{
	if (!len)
		return;
	invalidate_icache_range((__sz)addr, (__sz)len);
}
#else /* !CONFIG_ARCH_ARM_64 */
void elfrs_icache_sync(unsigned long addr __unused, unsigned long len __unused)
{
	/* x86_64 keeps instruction fetch coherent with stores. */
}
#endif /* !CONFIG_ARCH_ARM_64 */

#if CONFIG_ARCH_ARM_64
/* Linux's AT_HWCAP bits, from arch/arm64/include/uapi/asm/hwcap.h. */
#define HWCAP_FP		(1UL << 0)
#define HWCAP_ASIMD		(1UL << 1)
#define HWCAP_AES		(1UL << 3)
#define HWCAP_PMULL		(1UL << 4)
#define HWCAP_SHA1		(1UL << 5)
#define HWCAP_SHA2		(1UL << 6)
#define HWCAP_CRC32		(1UL << 7)
#define HWCAP_ATOMICS		(1UL << 8)
#define HWCAP_ASIMDRDM		(1UL << 12)

static inline uint64_t read_id_aa64isar0(void)
{
	uint64_t v;

	__asm__ __volatile__("mrs %0, id_aa64isar0_el1" : "=r"(v));
	return v;
}

/*
 * Report what the guest can actually use.
 *
 * The C loader passed AT_HWCAP = 0. That is safe but not free: glibc and
 * OpenSSL both dispatch on these bits, so zero means node falls back to the
 * generic AES and SHA paths on a CPU that has the instructions.
 *
 * Everything derived from an ID register is additionally gated on
 * CONFIG_FPSIMD, because AES/PMULL/SHA operate on SIMD registers and
 * advertising them with FP/SIMD trapped would turn a slow path into a crash.
 */
uint64_t elfrs_hwcap(void)
{
#if CONFIG_FPSIMD
	uint64_t isar0 = read_id_aa64isar0();
	uint64_t caps = HWCAP_FP | HWCAP_ASIMD;

	if (((isar0 >> 4) & 0xf) >= 1)
		caps |= HWCAP_AES;
	if (((isar0 >> 4) & 0xf) >= 2)
		caps |= HWCAP_PMULL;
	if (((isar0 >> 8) & 0xf) >= 1)
		caps |= HWCAP_SHA1;
	if (((isar0 >> 12) & 0xf) >= 1)
		caps |= HWCAP_SHA2;
	if (((isar0 >> 16) & 0xf) >= 1)
		caps |= HWCAP_CRC32;
	if (((isar0 >> 20) & 0xf) >= 2)
		caps |= HWCAP_ATOMICS;
	if (((isar0 >> 28) & 0xf) >= 1)
		caps |= HWCAP_ASIMDRDM;

	return caps;
#else /* !CONFIG_FPSIMD */
	/* Without CONFIG_FPSIMD, CPACR_EL1.FPEN is never cleared and the first
	 * SIMD instruction traps. Advertise nothing.
	 */
	return 0;
#endif /* !CONFIG_FPSIMD */
}

uint64_t elfrs_hwcap2(void)
{
	return 0;
}

const char *elfrs_platform(void)
{
	return "aarch64";
}
#else /* x86_64 */
uint64_t elfrs_hwcap(void)
{
	/* Linux puts CPUID leaf 1 EDX here. glibc does not consult it on
	 * x86_64 (it runs CPUID itself), so 0 is what upstream passed and what
	 * we keep: reporting a feature word the guest can verify independently
	 * only creates a way to be wrong.
	 */
	return 0;
}

uint64_t elfrs_hwcap2(void)
{
	return 0;
}

const char *elfrs_platform(void)
{
	return "x86_64";
}
#endif

/* --- binfmt ------------------------------------------------------------- */

#if CONFIG_APPELFLOADER_ELF_BINFMT
#include <uk/binfmt.h>
#include <uk/init.h>

int elfrs_binfmt_load(void *args);
int elfrs_binfmt_unload(void *args);

const char *elfrs_binfmt_pathname(void *args)
{
	return ((struct uk_binfmt_loader_args *)args)->pathname;
}

const char *elfrs_binfmt_progname(void *args)
{
	return ((struct uk_binfmt_loader_args *)args)->progname;
}

int elfrs_binfmt_argc(void *args)
{
	return ((struct uk_binfmt_loader_args *)args)->argc;
}

const char *const *elfrs_binfmt_argv(void *args)
{
	return (const char *const *)
		((struct uk_binfmt_loader_args *)args)->argv;
}

int elfrs_binfmt_envc(void *args)
{
	return ((struct uk_binfmt_loader_args *)args)->envc;
}

const char *const *elfrs_binfmt_envp(void *args)
{
	return (const char *const *)
		((struct uk_binfmt_loader_args *)args)->envp;
}

void *elfrs_binfmt_ctx(void *args)
{
	return &((struct uk_binfmt_loader_args *)args)->ctx;
}

unsigned long elfrs_binfmt_stack_size(void *args)
{
	return (unsigned long)
		((struct uk_binfmt_loader_args *)args)->stack_size;
}

void elfrs_binfmt_set_user(void *args, void *user)
{
	((struct uk_binfmt_loader_args *)args)->user = user;
}

void *elfrs_binfmt_get_user(void *args)
{
	return ((struct uk_binfmt_loader_args *)args)->user;
}

/* Rust returns 0 for handled, 1 for not-handled, negative for an error. */
static int binfmt_load(struct uk_binfmt_loader_args *args)
{
	int rc = elfrs_binfmt_load(args);

	if (rc == 0)
		return UK_BINFMT_HANDLED;
	if (rc == 1)
		return UK_BINFMT_NOT_HANDLED;
	return rc;
}

static int binfmt_unload(struct uk_binfmt_loader_args *args)
{
	elfrs_binfmt_unload(args);
	return UK_BINFMT_HANDLED;
}

static struct uk_binfmt_loader elf_loader = {
	.name = "ELF loader (rust)",
	.type = UK_BINFMT_LOADER_TYPE_EXEC,
	.ops = {
		.load = binfmt_load,
		.unload = binfmt_unload,
	},
};

static int elfrs_binfmt_init(struct uk_init_ctx *ctx __unused)
{
	return uk_binfmt_register(&elf_loader);
}

uk_late_initcall(elfrs_binfmt_init, 0);
#endif /* CONFIG_APPELFLOADER_ELF_BINFMT */

/* --- entry point -------------------------------------------------------- */

int main(int argc, const char *argv[])
{
	return elfrs_main(argc, argv);
}
