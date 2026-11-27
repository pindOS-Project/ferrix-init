/*
 * ferrix-init — Ferrix root task / PID 0
 *
 * The first userspace code that runs on the Ferrix microkernel.  It
 * bootstraps the POSIX environment:
 *
 *   1. Allocates the shared POSIX fault endpoint.
 *   2. Loads dinit as the first POSIX process (pid 1) into its own
 *      VSpace; burmalda serves its syscalls.
 *   3. Serves the per-process hooks burmalda needs: child memory
 *      access, mmap/brk page mapping, TLS setup, and the process
 *      lifecycle (fork / execve / exit / wait4).
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sel4/sel4.h>
#include <sel4/bootinfo.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <burmalda/protocol.h>  /* burmalda_run() + hooks */

#include "elf_loader.h"
#include "vga.h"

/* Embedded ELF images (see hello_embed.S / dinit_embed.S / halt_embed.S). */
extern const uint8_t hello_elf_start[];
extern const uint8_t hello_elf_end[];
extern const uint8_t dinit_elf_start[];
extern const uint8_t dinit_elf_end[];
extern const uint8_t halt_elf_start[];
extern const uint8_t halt_elf_end[];

static seL4_CPtr _fault_ep;         /* shared POSIX fault endpoint     */
static seL4_Word _next_pid = 1;

static void ferrix_debug_puts(const char *s)
{
    while (*s != '\0') {
        seL4_DebugPutChar(*s++);
    }
}

static void ferrix_debug_put_hex(seL4_Word v)
{
    static const char digits[] = "0123456789abcdef";
    for (int i = 15; i >= 0; i--) {
        seL4_DebugPutChar(digits[(v >> (i * 4)) & 0xf]);
    }
}

#ifdef FERRIX_SMOKE_CHILD
/* ---------------------------------------------------------------------
 * Legacy smoke test: child shares the root VSpace and calls write().
 * Build with -DFERRIX_SMOKE_CHILD to re-enable.
 * --------------------------------------------------------------------- */
static char posix_test_stack[4096] __attribute__((aligned(16)));

static long posix_syscall3(long number, long arg0, long arg1, long arg2)
{
    register long rax __asm__("rax") = number;
    register long rdx __asm__("rdx") = arg2;

    __asm__ volatile("push %%rbx\n"
                     "mov %%rsp, %%rbx\n"
                     "syscall\n"
                     "mov %%rbx, %%rsp\n"
                     "pop %%rbx"
                     : "+a"(rax)
                     : "D"(arg0), "S"(arg1), "d"(rdx)
                     : "rcx", "r11", "memory");
    return rax;
}

static void posix_test_entry(void)
{
    static const char message[] = "ferrix-init: POSIX child write reached burmalda\n";
    posix_syscall3(BURMALDA_SYS_write, 1, (long)message, sizeof(message) - 1);
    for (;;) {
        __asm__ volatile("pause");
    }
}
#endif /* FERRIX_SMOKE_CHILD */

/* ---------------------------------------------------------------------------
 * Object allocation from bootinfo free slots.
 * --------------------------------------------------------------------------- */

static seL4_CPtr alloc_slot(seL4_BootInfo *bi)
{
    return ferrix_alloc_slot(bi);
}

static seL4_CPtr retype(seL4_BootInfo *bi, seL4_Word type, seL4_Word size_bits)
{
    return ferrix_retype(bi, type, size_bits);
}

static int fail(const char *msg, seL4_Error err)
{
    (void)err;
    ferrix_debug_puts("ferrix-init: FATAL: ");
    ferrix_debug_puts(msg);
    ferrix_debug_puts("\n");
    return 1;
}

/* ---------------------------------------------------------------------------
 * Badge routing helpers for burmalda's hooks.
 * --------------------------------------------------------------------------- */

static ferrix_proc_t *find_proc(seL4_Word badge)
{
    ferrix_proc_t *p = ferrix_proc_find(badge);
    if (p == NULL) {
        ferrix_debug_puts("ferrix-init: WARN: unknown badge ");
        ferrix_debug_put_hex(badge);
        ferrix_debug_puts("\n");
    }
    return p;
}

/* Mint a copy of the shared fault endpoint carrying `badge`. */
static seL4_CPtr make_child_ep(seL4_BootInfo *bi, seL4_Word badge)
{
    seL4_CPtr slot = alloc_slot(bi);
    seL4_Error err = seL4_CNode_Mint(
        seL4_CapInitThreadCNode, slot, seL4_WordBits,
        seL4_CapInitThreadCNode, _fault_ep, seL4_WordBits,
        seL4_AllRights, badge);
    if (err != seL4_NoError) return seL4_CapNull;
    return slot;
}

/* Configure + start a proc's TCB with the given user context. */
static int start_proc_tcb(seL4_BootInfo *bi, ferrix_proc_t *p,
                          seL4_Word rip, seL4_Word rsp)
{
#ifndef CONFIG_KERNEL_MCS
    seL4_Error err = seL4_TCB_Configure(
        p->tcb, p->ep,
        seL4_CapInitThreadCNode, 0,
        p->vspace, 0,
        FERRIX_CHILD_IPC_BUF_VADDR, p->ipc_frame);
    if (err != seL4_NoError) {
        fail("TCB configure", err);
        return -1;
    }

    err = seL4_TCB_SetPriority(p->tcb, seL4_CapInitThreadTCB, 0);
    if (err != seL4_NoError) {
        fail("TCB priority", err);
        return -1;
    }

    seL4_TCB_SetFlags_t flags = seL4_TCB_SetFlags(
        p->tcb, seL4_TCBFlag_NoFlag, seL4_TCBFlag_posixSyscalls);
    if (flags.error != seL4_NoError) {
        fail("TCB posix flag", flags.error);
        return -1;
    }

    seL4_UserContext regs = {0};
    regs.rip    = rip;
    regs.rsp    = rsp;
    regs.rflags = 0x202;
    err = seL4_TCB_WriteRegisters(p->tcb, true, 0,
                                  sizeof(regs) / sizeof(seL4_Word), &regs);
    if (err != seL4_NoError) {
        fail("TCB start", err);
        return -1;
    }
    return 0;
#else
    (void)bi; (void)p; (void)rip; (void)rsp;
    fail("MCS child scheduling is not implemented", seL4_InvalidArgument);
    return -1;
#endif
}

/* Load `elf` into a proc, prepare stack/IPC buffer/TCB, and start it. */
static int launch_proc_image(seL4_BootInfo *bi, ferrix_proc_t *p,
                             const void *elf, seL4_Word elf_size,
                             const char *const *argv)
{
    if (elf_create_vspace(bi, p) == seL4_CapNull) {
        ferrix_debug_puts("ferrix-init: vspace creation failed\n");
        return -1;
    }

    elf_load_result_t res;
    int rc = elf_load(bi, p, elf, elf_size, &res);
    if (rc != ELF_OK) {
        ferrix_debug_puts("ferrix-init: elf_load failed: ");
        ferrix_debug_puts(elf_strerror(rc));
        if (rc == ELF_E_MAP) {
            ferrix_debug_puts(" (stage ");
            char tag[2] = { elf_last_stage, 0 };
            ferrix_debug_puts(tag);
            ferrix_debug_puts(", seL4 err ");
            ferrix_debug_put_hex(elf_last_seL4_err);
            ferrix_debug_puts(")");
        }
        ferrix_debug_puts("\n");
        return -1;
    }

    rc = elf_map_zero_pages(bi, p, FERRIX_CHILD_STACK_TOP,
                            FERRIX_CHILD_STACK_PAGES);
    if (rc != ELF_OK) return -1;

    seL4_Word rsp = ferrix_setup_initial_stack(bi, p, FERRIX_CHILD_STACK_TOP,
                                               argv, NULL);
    if (rsp == 0) return -1;

    p->ipc_frame = elf_map_ipc_buffer(bi, p, FERRIX_CHILD_IPC_BUF_VADDR);
    if (p->ipc_frame == seL4_CapNull) return -1;

    p->ep = make_child_ep(bi, p->badge);
    if (p->ep == seL4_CapNull) return -1;

    p->tcb = retype(bi, seL4_TCBObject, seL4_TCBBits);
    if (p->tcb == seL4_CapNull) return -1;

    {
        char tname[16];
        const char *pfx = "pid";
        long i = 0, k = 0;
        for (; pfx[i] != '\0'; i++) tname[k++] = pfx[i];
        seL4_Word b = p->badge;
        char digits[20];
        int nd = 0;
        if (b == 0) digits[nd++] = '0';
        while (b > 0) { digits[nd++] = (char)('0' + (b % 10)); b /= 10; }
        while (nd > 0 && k < 15) tname[k++] = digits[--nd];
        tname[k] = '\0';
        seL4_DebugNameThread(p->tcb, tname);
    }

    return start_proc_tcb(bi, p, res.entry, rsp);
}

/* ---------------------------------------------------------------------------
 * burmalda hooks (badge-based)
 * --------------------------------------------------------------------------- */

static bool ferrix_child_mem_read(void *ctx, seL4_Word badge, void *dest,
                                  seL4_Word src, seL4_Word len)
{
    (void)ctx;
    ferrix_proc_t *p = find_proc(badge);
    if (p == NULL) return false;
    return ferrix_read_child_memory(p, dest, src, len);
}

static bool ferrix_child_mem_write(void *ctx, seL4_Word badge, seL4_Word dest,
                                   const void *src, seL4_Word len)
{
    (void)ctx;
    ferrix_proc_t *p = find_proc(badge);
    if (p == NULL) return false;
    return ferrix_write_child_memory(p, dest, src, len);
}

static seL4_Word ferrix_alloc_child_pages(void *ctx, seL4_Word badge,
                                          seL4_Word len, seL4_Word hint)
{
    seL4_BootInfo *bi = (seL4_BootInfo *)ctx;
    ferrix_proc_t *p = find_proc(badge);
    if (p == NULL || len == 0) return 0;

    seL4_Word start, end;
    if (hint != 0) {
        start = hint & ~0xfffUL;
        end   = start + ((len + 0xfffUL) & ~0xfffUL);
    } else {
        if (p->heap_top == 0) p->heap_top = FERRIX_CHILD_HEAP_BASE;
        start = (p->heap_top + 0xfffUL) & ~0xfffUL;
        end   = start + ((len + 0xfffUL) & ~0xfffUL);
    }

    if (end >= FERRIX_CHILD_HEAP_LIMIT || end < start) return 0;

    int rc = elf_map_zero_pages(bi, p, end, (end - start) / 0x1000);
    if (rc != ELF_OK) return 0;

    if (hint == 0) p->heap_top = end;
    return start;
}

/* arch_prctl(ARCH_SET_FS): write fs_base into the proc's context without
 * resuming (the normal reply resumes the thread).  TCB_WriteRegisters
 * marshals into MRs 0..19, so snapshot and restore the fault message. */
static long ferrix_set_fs_base(void *ctx, seL4_Word badge, seL4_Word addr)
{
    (void)ctx;
    ferrix_proc_t *p = find_proc(badge);
    if (p == NULL) return -BURMALDA_EPERM;

    seL4_UserContext ctxr;
    ctxr.rip    = seL4_GetMR(seL4_UnknownSyscall_FaultIP);
    ctxr.rsp    = seL4_GetMR(seL4_UnknownSyscall_SP);
    ctxr.rflags = seL4_GetMR(seL4_UnknownSyscall_FLAGS);
    ctxr.rax    = seL4_GetMR(seL4_UnknownSyscall_RAX);
    ctxr.rbx    = seL4_GetMR(seL4_UnknownSyscall_RBX);
    ctxr.rcx    = seL4_GetMR(seL4_UnknownSyscall_RCX);
    ctxr.rdx    = seL4_GetMR(seL4_UnknownSyscall_RDX);
    ctxr.rsi    = seL4_GetMR(seL4_UnknownSyscall_RSI);
    ctxr.rdi    = seL4_GetMR(seL4_UnknownSyscall_RDI);
    ctxr.rbp    = seL4_GetMR(seL4_UnknownSyscall_RBP);
    ctxr.r8     = seL4_GetMR(seL4_UnknownSyscall_R8);
    ctxr.r9     = seL4_GetMR(seL4_UnknownSyscall_R9);
    ctxr.r10    = seL4_GetMR(seL4_UnknownSyscall_R10);
    ctxr.r11    = seL4_GetMR(seL4_UnknownSyscall_R11);
    ctxr.r12    = seL4_GetMR(seL4_UnknownSyscall_R12);
    ctxr.r13    = seL4_GetMR(seL4_UnknownSyscall_R13);
    ctxr.r14    = seL4_GetMR(seL4_UnknownSyscall_R14);
    ctxr.r15    = seL4_GetMR(seL4_UnknownSyscall_R15);
    ctxr.fs_base = addr;
    ctxr.gs_base = 0;

    seL4_Word saved[19];
    for (int i = 0; i < 19; i++) saved[i] = seL4_GetMR(i);

    seL4_Error err = seL4_TCB_WriteRegisters(p->tcb, false, 0,
                                             sizeof(ctxr) / sizeof(seL4_Word),
                                             &ctxr);
    for (int i = 0; i < 19; i++) seL4_SetMR(i, saved[i]);

    if (err == seL4_NoError) p->fs_base = addr;
    return (err == seL4_NoError) ? 0 : -BURMALDA_EINVAL;
}

/* Write a full 20-word user context (UserContext layout) and optionally
 * resume the thread.  The fs_base field always comes from the proc's
 * tracked value. */
static long ferrix_write_ctx(void *ctx, seL4_Word badge,
                             const seL4_Word *regs20, bool resume)
{
    (void)ctx;
    ferrix_proc_t *p = find_proc(badge);
    if (p == NULL) return -1;

    seL4_UserContext ctxr;
    memcpy(&ctxr, regs20, sizeof(ctxr));
    ctxr.fs_base = p->fs_base;
    ctxr.gs_base = 0;

    seL4_Word saved[19];
    for (int i = 0; i < 19; i++) saved[i] = seL4_GetMR(i);

    seL4_Error err = seL4_TCB_WriteRegisters(p->tcb, resume ? true : false, 0,
                                             sizeof(ctxr) / sizeof(seL4_Word),
                                             &ctxr);
    for (int i = 0; i < 19; i++) seL4_SetMR(i, saved[i]);
    return (err == seL4_NoError) ? 0 : -1;
}

/* fork: duplicate the parent VSpace and prepare a fresh TCB.  The new
 * thread is not started here; burmalda resumes it via write_ctx with
 * the parent's registers (rax=0). */
static seL4_Word alloc_pid(void)
{
    for (seL4_Word pid = 2; pid < 1000; pid++) {
        if (ferrix_proc_find(pid) == NULL) return pid;
    }
    return 0;
}

static seL4_Word ferrix_spawn(void *ctx, seL4_Word parent_badge)
{
    seL4_BootInfo *bi = (seL4_BootInfo *)ctx;
    ferrix_proc_t *parent = find_proc(parent_badge);
    if (parent == NULL) return 0;

    seL4_Word pid = alloc_pid();
    if (pid == 0) { ferrix_debug_puts("spawn: proc table full\n"); return 0; }
    ferrix_proc_t *p = ferrix_proc_alloc(pid, parent_badge);
    if (p == NULL) { ferrix_debug_puts("spawn: proc table full\n"); return 0; }
    p->badge = pid;

    p->fs_base  = parent->fs_base;
    p->heap_top = parent->heap_top;
    p->brk      = parent->brk;

    if (elf_create_vspace(bi, p) == seL4_CapNull) {
        ferrix_debug_puts("spawn: vspace fail\n");
        return 0;
    }
    int frc = elf_fork_vspace(bi, parent, p);
    if (frc != ELF_OK) {
        ferrix_debug_puts("spawn: fork vspace fail rc=");
        ferrix_debug_put_hex((seL4_Word)frc);
        ferrix_debug_puts(" parent pages=");
        ferrix_debug_put_hex((seL4_Word)parent->reg_count);
        ferrix_debug_puts("\n");
        return 0;
    }

    p->ipc_frame = elf_proc_frame(p, FERRIX_CHILD_IPC_BUF_VADDR);
    if (p->ipc_frame == seL4_CapNull) return 0;

    p->ep = make_child_ep(bi, p->badge);
    if (p->ep == seL4_CapNull) return 0;

    p->tcb = retype(bi, seL4_TCBObject, seL4_TCBBits);
    if (p->tcb == seL4_CapNull) return 0;

    {
        char tname[16];
        const char *pfx = "pid";
        long i = 0, k = 0;
        for (; pfx[i] != '\0'; i++) tname[k++] = pfx[i];
        seL4_Word b = p->badge;
        char digits[20];
        int nd = 0;
        while (b > 0) { digits[nd++] = (char)('0' + (b % 10)); b /= 10; }
        while (nd > 0 && k < 15) tname[k++] = digits[--nd];
        tname[k] = '\0';
        seL4_DebugNameThread(p->tcb, tname);
    }

#ifndef CONFIG_KERNEL_MCS
    seL4_Error err = seL4_TCB_Configure(
        p->tcb, p->ep,
        seL4_CapInitThreadCNode, 0,
        p->vspace, 0,
        FERRIX_CHILD_IPC_BUF_VADDR, p->ipc_frame);
    if (err != seL4_NoError) return 0;

    err = seL4_TCB_SetPriority(p->tcb, seL4_CapInitThreadTCB, 0);
    if (err != seL4_NoError) return 0;

    seL4_TCB_SetFlags_t flags = seL4_TCB_SetFlags(
        p->tcb, seL4_TCBFlag_NoFlag, seL4_TCBFlag_posixSyscalls);
    if (flags.error != seL4_NoError) return 0;
#endif

    return p->badge;
}

/* execve: replace the proc's address space with a freshly loaded ELF. */
static long ferrix_exec(void *ctx, seL4_Word badge,
                        seL4_Word elf_data, seL4_Word elf_size,
                        const char *const *argv)
{
    seL4_BootInfo *bi = (seL4_BootInfo *)ctx;
    ferrix_proc_t *p = find_proc(badge);
    if (p == NULL) return -1;

    elf_proc_clear(p);
    p->fs_base = 0;
    p->heap_top = 0;
    p->brk = 0;

    elf_load_result_t res;
    int rc = elf_load(bi, p, (const void *)elf_data, elf_size, &res);
    if (rc != ELF_OK) {
        ferrix_debug_puts("ferrix-init: exec elf_load failed: ");
        ferrix_debug_puts(elf_strerror(rc));
        ferrix_debug_puts("\n");
        return -1;
    }

    rc = elf_map_zero_pages(bi, p, FERRIX_CHILD_STACK_TOP,
                            FERRIX_CHILD_STACK_PAGES);
    if (rc != ELF_OK) return -1;

    seL4_Word rsp = ferrix_setup_initial_stack(bi, p, FERRIX_CHILD_STACK_TOP,
                                               argv, NULL);
    if (rsp == 0) return -1;

    p->ipc_frame = elf_map_ipc_buffer(bi, p, FERRIX_CHILD_IPC_BUF_VADDR);
    if (p->ipc_frame == seL4_CapNull) return -1;


#ifndef CONFIG_KERNEL_MCS
    seL4_Error err = seL4_TCB_Configure(
        p->tcb, p->ep,
        seL4_CapInitThreadCNode, 0,
        p->vspace, 0,
        FERRIX_CHILD_IPC_BUF_VADDR, p->ipc_frame);
    if (err != seL4_NoError) {
        fail("exec TCB configure", err);
        return -1;
    }
#endif

    seL4_UserContext regs = {0};
    regs.rip    = res.entry;
    regs.rsp    = rsp;
    regs.rflags = 0x202;
    regs.fs_base = 0;
    err = seL4_TCB_WriteRegisters(p->tcb, true, 0,
                                  sizeof(regs) / sizeof(seL4_Word), &regs);
    return (err == seL4_NoError) ? 0 : -1;
}

/* exit: mark the proc dead, report the parent (0 if none). */
static seL4_Word ferrix_exit(void *ctx, seL4_Word badge, long status)
{
    (void)ctx;
    ferrix_proc_t *p = find_proc(badge);
    if (p == NULL) return 0;
    p->exited = true;
    p->exit_status = status;
    return p->parent_badge;
}

/* Late teardown once the parent has reaped the child: frees every CNode
 * slot the process consumed so forks keep succeeding. */
static void ferrix_reap(void *ctx, seL4_Word badge)
{
    (void)ctx;
    ferrix_proc_t *p = find_proc(badge);
    if (p != NULL && p->exited) {
        elf_proc_destroy(p);
        p->used = false;      /* free the table slot (pid becomes reusable) */
    }
}

/* Fatal signal: stop the thread immediately, mark dead. */
static void ferrix_terminate(void *ctx, seL4_Word badge, long signo)
{
    (void)ctx;
    ferrix_proc_t *p = find_proc(badge);
    if (p == NULL || p->exited) return;
#ifndef CONFIG_KERNEL_MCS
    seL4_TCB_Suspend(p->tcb);
#endif
    p->exited = true;
    p->exit_status = signo;   /* raw signal: parent sees WIFSIGNALED */
}

/* Find an unreaped exited child of `badge`; mark it reaped. */
static seL4_Word ferrix_dead_child(void *ctx, seL4_Word badge, long *status)
{
    (void)ctx;
    for (int i = 0; i < FERRIX_MAX_PROCS; i++) {
        ferrix_proc_t *p = ferrix_proc_at(i);
        if (p != NULL && p->used && p->exited && !p->reaped &&
            p->parent_badge == badge) {
            p->reaped = true;
            *status = p->exit_status;
            return p->badge;
        }
    }
    return 0;
}

/* ---------------------------------------------------------------------------
 * main
 * --------------------------------------------------------------------------- */

int main(void)
{
    seL4_BootInfo *bi = seL4_GetBootInfo();
    elf_set_bootinfo(bi);

    ferrix_debug_puts("ferrix-init: starting (Ferrix microkernel, x86_64)\n");

    /* Untyped memory diagnostics: total available, per-size histogram. */
    {
        seL4_Word total_bytes = 0, n_ut = bi->untyped.end - bi->untyped.start;
        seL4_Word ram_count = 0;
        seL4_Word size_hist[64];
        memset(size_hist, 0, sizeof(size_hist));
        for (seL4_Word i = 0; i < n_ut; i++) {
            if (bi->untypedList[i].isDevice) continue;
            seL4_Word sz = bi->untypedList[i].sizeBits;
            if (sz < 64) size_hist[sz]++;
            total_bytes += (1UL << sz);
            ram_count++;
        }
        ferrix_debug_puts("ferrix-init: RAM untypeds=");
        ferrix_debug_put_hex(ram_count);
        ferrix_debug_puts(" of ");
        ferrix_debug_put_hex(n_ut);
        ferrix_debug_puts(" total=");
        ferrix_debug_put_hex(total_bytes);
        ferrix_debug_puts(" bytes\n");
        for (int i = 12; i < 40; i++) {
            if (size_hist[i] > 0) {
                ferrix_debug_puts("  2^");
                ferrix_debug_put_hex(i);
                ferrix_debug_puts(" x ");
                ferrix_debug_put_hex(size_hist[i]);
                ferrix_debug_puts("\n");
            }
        }
    ferrix_debug_puts("ferrix-init: empty slots ");
    ferrix_debug_put_hex(bi->empty.end - bi->empty.start);
    ferrix_debug_puts("\n");
    }

    /* VGA framebuffer console (GRUB multiboot2 fb header in bootinfo);
     * harmless no-op when booting text-mode (QEMU -kernel path). */
    ferrix_vga_init(bi);

    _fault_ep = retype(bi, seL4_EndpointObject, seL4_EndpointBits);
    if (_fault_ep == seL4_CapNull) return fail("endpoint retype", seL4_NotEnoughMemory);

#ifdef FERRIX_SMOKE_CHILD
    /* Legacy shared-VSpace smoke child (syscall-path probe). */
    seL4_CPtr child_tcb = retype(bi, seL4_TCBObject, seL4_TCBBits);
    if (child_tcb == seL4_CapNull) return fail("child TCB retype", seL4_NotEnoughMemory);

#ifndef CONFIG_KERNEL_MCS
    seL4_Error err = seL4_TCB_Configure(
        child_tcb, _fault_ep,
        seL4_CapInitThreadCNode, 0,
        seL4_CapInitThreadVSpace, 0,
        (seL4_Word)seL4_GetIPCBuffer(), seL4_CapInitThreadIPCBuffer);
    if (err != seL4_NoError) return fail("child TCB configure", err);

    err = seL4_TCB_SetPriority(child_tcb, seL4_CapInitThreadTCB, 0);
    if (err != seL4_NoError) return fail("child TCB priority", err);

    seL4_TCB_SetFlags_t flags = seL4_TCB_SetFlags(
        child_tcb, seL4_TCBFlag_NoFlag, seL4_TCBFlag_posixSyscalls);
    if (flags.error != seL4_NoError) return fail("child POSIX flag", flags.error);

    seL4_UserContext registers = {0};
    registers.rip = (seL4_Word)posix_test_entry;
    registers.rsp = (seL4_Word)(posix_test_stack + sizeof(posix_test_stack) - 16);
    registers.rflags = 0x202;
    err = seL4_TCB_WriteRegisters(
        child_tcb, true, 0,
        sizeof(registers) / sizeof(seL4_Word), &registers);
    if (err != seL4_NoError) return fail("child TCB start", err);
#else
    return fail("MCS child scheduling is not implemented", seL4_InvalidArgument);
#endif
#else
    /* Load dinit as the first POSIX process (pid 1). */
    static const char *const dinit_argv[] = { "/sbin/dinit", NULL };
    ferrix_proc_t *p1 = ferrix_proc_alloc(_next_pid++, 0);
    if (p1 == NULL) return fail("proc table", seL4_NotEnoughMemory);

    if (launch_proc_image(bi, p1, dinit_elf_start,
                          (seL4_Word)(dinit_elf_end - dinit_elf_start),
                          dinit_argv) != 0) {
        return 1;
    }
#endif

#ifdef CONFIG_KERNEL_MCS
    seL4_CPtr reply_obj = retype(bi, seL4_ReplyObject, seL4_ReplyBits);
    if (reply_obj == seL4_CapNull) return fail("reply retype", seL4_NotEnoughMemory);
#else
    seL4_CPtr reply_obj = seL4_CapNull; /* unused in non-MCS */
#endif

    /* Serial (COM1, IRQ4) wakeup channel for blocking reads: the kernel
     * signals this notification on each serial interrupt; burmalda's
     * Recv returns from the bound notification when no fault is
     * pending, letting it complete deferred console reads. */
    seL4_CPtr serial_irq_notif = retype(bi, seL4_NotificationObject, seL4_NotificationBits);
    if (serial_irq_notif == seL4_CapNull) return fail("serial notification retype", seL4_NotEnoughMemory);

    seL4_CPtr irq_ctrl = seL4_CapIRQControl;   /* root task's IRQ control cap */
    seL4_Error err;
    seL4_CPtr irq_slot = alloc_slot(bi);
    /* Kernel is built with the IOAPIC path: ISA IRQ4 (COM1) maps to
     * IOAPIC 0, pin 4, edge-triggered, active-high, vector = pin. */
    seL4_Error irq_err = seL4_IRQControl_GetIOAPIC(irq_ctrl,
                                                   seL4_CapInitThreadCNode, irq_slot, seL4_WordBits,
                                                   0 /* ioapic */, 4 /* pin */,
                                                   0 /* level: edge */, 0 /* polarity: active-high */,
                                                   4 /* vector */);
    if (irq_err != seL4_NoError) {
        fail("serial IRQ4 get", irq_err);
        return 1;
    }
    err = seL4_IRQHandler_SetNotification(irq_slot, serial_irq_notif);
    if (err != seL4_NoError) {
        fail("IRQ set notification", err);
        return 1;
    }
    seL4_IRQHandler_Ack(irq_slot);

    /* Bind the notification to the root (burmalda) TCB: blocking Recv
     * returns from the notification when the serial IRQ fires. */
    err = seL4_TCB_BindNotification(seL4_CapInitThreadTCB, serial_irq_notif);
    if (err != seL4_NoError) {
        fail("TCB bind notification", err);
        return 1;
    }
    burmalda_set_serial_irq_notif(irq_slot);
    burmalda_set_serial_irq_slot(irq_slot);

    ferrix_debug_puts("ferrix-init: fault endpoint ready\n");
    ferrix_debug_puts("ferrix-init: handing off to burmalda POSIX personality\n");

    burmalda_set_child_mem_reader(ferrix_child_mem_read, bi);
    burmalda_set_child_mem_writer(ferrix_child_mem_write, bi);
    burmalda_set_page_allocator(ferrix_alloc_child_pages, bi);
    burmalda_set_fs_base_hook(ferrix_set_fs_base, bi);
    burmalda_set_write_ctx_hook(ferrix_write_ctx, bi);
    burmalda_set_spawn_hook(ferrix_spawn, bi);
    burmalda_set_exec_hook(ferrix_exec, bi);
    burmalda_set_exit_hook(ferrix_exit, bi);
    burmalda_set_dead_child_hook(ferrix_dead_child, bi);
    burmalda_set_reap_hook(ferrix_reap, bi);
    burmalda_set_terminate_hook(ferrix_terminate, bi);

    /* No calibrated time source is available (port I/O requires
     * CONFIG_IOPORT support); burmalda runs its clock uncalibrated
     * (1 TSC tick == 1 ns), which stays monotonic and good enough for
     * dasynq's timeout machinery. */
    burmalda_run(_fault_ep, reply_obj);

    /* UNREACHABLE */
    return 0;
}
