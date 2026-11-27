/*
 * elf_loader.h — ELF64 loader and per-process VSpace helpers for Ferrix
 *
 * Each POSIX process ("proc") owns a fresh PML4, a frame registry
 * (vaddr → {frame cap, alias cap}), paging-structure bookkeeping, and a
 * brk/mmap heap.  Data is copied through two root-side scratch windows:
 * a seL4 frame cap carries a single mapping, so pages are filled or
 * read via their unmapped alias caps.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef FERRIX_ELF_LOADER_H
#define FERRIX_ELF_LOADER_H

#include <sel4/sel4.h>
#include <sel4/bootinfo.h>
#include <stdint.h>
#include <stdbool.h>

/* Child address-space layout (x86_64, below USER_TOP 0x7fffffffffff). */
#define FERRIX_CHILD_STACK_TOP      0x7ffffffff000UL
#define FERRIX_CHILD_STACK_PAGES    4                /* 16 KiB */
#define FERRIX_CHILD_IPC_BUF_VADDR  0x7fffffffa000UL

/* Root-side scratch windows used to fill/read child frames. */
#define FERRIX_SCRATCH_A            0x30000000UL
#define FERRIX_SCRATCH_B            0x30001000UL

/* mmap bump window; brk window lives in main.c. */
#define FERRIX_CHILD_HEAP_BASE      0x20000000UL
#define FERRIX_CHILD_HEAP_LIMIT     0x30000000UL

#define FERRIX_MAX_CHILD_FRAMES     2048
#define FERRIX_MAX_PROCS            8
#define MAX_REGIONS_EL              256

/* ---------------------------------------------------------------------
 * ELF64 structures (minimal subset for loading)
 * --------------------------------------------------------------------- */

#define EI_NIDENT 16

typedef struct {
    unsigned char e_ident[EI_NIDENT];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
} Elf64_Ehdr;

typedef struct {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
} Elf64_Phdr;

#define PT_LOAD    1
#define PT_DYNAMIC 2
#define PT_INTERP  3

#define PF_X 0x1
#define PF_W 0x2
#define PF_R 0x4

#define ET_EXEC 2
#define ET_DYN  3

#define EM_X86_64 62

#define ELFMAG0 0x7f
#define ELFMAG1 'E'
#define ELFMAG2 'L'
#define ELFMAG3 'F'

#define ELFCLASS64    2
#define ELFDATA2LSB   1

/* Loader error codes (negative ints). */
enum {
    ELF_OK          = 0,
    ELF_E_TOOSMALL  = -1,
    ELF_E_MAGIC     = -2,
    ELF_E_TYPE      = -3,
    ELF_E_ARCH      = -4,
    ELF_E_PHDR      = -5,
    ELF_E_INTERP    = -6,
    ELF_E_NOLOAD    = -7,
    ELF_E_BOUNDS    = -8,
    ELF_E_ALIGN     = -9,
    ELF_E_OVERFLOW  = -10,
    ELF_E_ENTRY     = -11,
    ELF_E_NOMEM     = -12,
    ELF_E_MAP       = -13,
    ELF_E_REGISTRY  = -14,
    ELF_E_ALLOC     = -15,
};

const char *elf_strerror(int error);

/* Map an already-retyped frame into the ROOT vspace (root paging is
 * created on demand).  Used by vga.c for the framebuffer window. */
seL4_Error elf_root_map_frame(seL4_BootInfo *bi, seL4_CPtr frame,
                              seL4_Word vaddr, seL4_CapRights_t rights,
                              seL4_X86_VMAttributes attr);

/* 2 MiB large-page variant (no PT may exist for the region). */
seL4_Error elf_root_map_large_frame(seL4_BootInfo *bi, seL4_CPtr frame,
                                    seL4_Word vaddr, seL4_CapRights_t rights,
                                    seL4_X86_VMAttributes attr);

/* Debug: stage tag of the last failed mapping step and its raw seL4
 * error code ('p' PDPT, 'd' PD, 't' PT, 'c' copy, 's' scratch map,
 * 'm' child map, 'f' fork copy, 'a' ASID, '?' none). */
extern char elf_last_stage;
extern seL4_Error elf_last_seL4_err;

/* ---------------------------------------------------------------------
 * Per-process state
 * --------------------------------------------------------------------- */

typedef struct ferrix_proc {
    bool        used;
    seL4_Word   badge;              /* = POSIX pid                    */
    seL4_Word   parent_badge;       /* 0 for the root process         */
    seL4_CPtr   vspace;             /* PML4 cap                       */
    seL4_CPtr   tcb;
    seL4_CPtr   ep;                 /* badged fault endpoint cap      */
    seL4_CPtr   ipc_frame;          /* cap of the TCB IPC buffer page */
    seL4_Word   fs_base;            /* TLS base, 0 until ARCH_SET_FS  */
    seL4_Word   heap_top;           /* mmap bump pointer              */
    seL4_Word   brk;                /* current break (burmalda owns)  */
    bool        exited;
    bool        reaped;
    long        exit_status;

    /* vaddr -> {frame, alias} registry */
    struct {
        seL4_Word vaddr;
        seL4_CPtr frame;
        seL4_CPtr alias;
    } reg[FERRIX_MAX_CHILD_FRAMES];
    int reg_count;

    /* paging-structure coverage tags (keyed by region) */
    seL4_Word have_pdpt[MAX_REGIONS_EL]; int n_pdpt;
    seL4_Word have_pd[MAX_REGIONS_EL];   int n_pd;
    seL4_Word have_pt[MAX_REGIONS_EL];   int n_pt;
} ferrix_proc_t;

/* ---------------------------------------------------------------------
 * Capability helpers (shared with main.c)
 * --------------------------------------------------------------------- */

seL4_CPtr ferrix_alloc_slot(seL4_BootInfo *bi);
void ferrix_free_slot(seL4_CPtr slot);
seL4_CPtr ferrix_retype(seL4_BootInfo *bi, seL4_Word type, seL4_Word size_bits);

/* ---------------------------------------------------------------------
 * Process lifecycle
 * --------------------------------------------------------------------- */

/* Look up a proc by badge; NULL if unknown. */
ferrix_proc_t *ferrix_proc_find(seL4_Word badge);

/* Indexed access for iteration; NULL past the table. */
ferrix_proc_t *ferrix_proc_at(int index);

/* Allocate a fresh proc record (badge assigned by caller). */
ferrix_proc_t *ferrix_proc_alloc(seL4_Word badge, seL4_Word parent_badge);

/* Create a usable VSpace root (PML4 + ASID assignment) for a proc. */
seL4_CPtr elf_create_vspace(seL4_BootInfo *bi, ferrix_proc_t *p);

/* Map zeroed RW pages ending at `top_vaddr` (exclusive). */
int elf_map_zero_pages(seL4_BootInfo *bi, ferrix_proc_t *p,
                       seL4_Word top_vaddr, seL4_Word num_pages);

/* Map a single zeroed page at `vaddr`; returns its frame cap. */
seL4_CPtr elf_map_ipc_buffer(seL4_BootInfo *bi, ferrix_proc_t *p,
                             seL4_Word vaddr);

/* Load a static ELF64 ET_EXEC image into the proc's (fresh) VSpace. */
typedef struct {
    seL4_Word entry;
    seL4_Word max_vaddr;
} elf_load_result_t;

int elf_load(seL4_BootInfo *bi, ferrix_proc_t *p,
             const void *elf_data, seL4_Word elf_size,
             elf_load_result_t *out);

/* Copy every registered frame from `parent` into the fresh VSpace of
 * `child` (fork).  Both procs' registries end up identical. */
int elf_fork_vspace(seL4_BootInfo *bi, ferrix_proc_t *parent,
                    ferrix_proc_t *child);

/* Release a proc's pages and recycle their slots (execve). */
void elf_proc_clear(ferrix_proc_t *p);

/* Full teardown of a dead process; the proc slot becomes reusable. */
void elf_proc_destroy(ferrix_proc_t *p);

/* Build a Linux-style initial stack; returns rsp or 0. */
seL4_Word ferrix_setup_initial_stack(seL4_BootInfo *bi, ferrix_proc_t *p,
                                     seL4_Word stack_top,
                                     const char *const *argv,
                                     const char *const *envp);

/* ---------------------------------------------------------------------
 * Child memory access
 * --------------------------------------------------------------------- */

bool ferrix_read_child_memory(ferrix_proc_t *p, void *dest,
                              seL4_Word child_vaddr, seL4_Word len);
bool ferrix_write_child_memory(ferrix_proc_t *p, seL4_Word child_vaddr,
                               const void *src, seL4_Word len);

/* Bootinfo shared by all procs; set once at startup. */
void elf_set_bootinfo(seL4_BootInfo *bi);

/* Frame cap of a registered page (e.g. the IPC buffer). */
seL4_CPtr elf_proc_frame(ferrix_proc_t *p, seL4_Word vaddr);

#endif /* FERRIX_ELF_LOADER_H */
