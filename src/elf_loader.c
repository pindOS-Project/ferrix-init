/*
 * elf_loader.c — ELF64 loader implementation for Ferrix (multi-process)
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "elf_loader.h"
#include <string.h>

#define PAGE_BITS   12
#define PAGE_SIZE   (1UL << PAGE_BITS)
#define PAGE_MASK   (PAGE_SIZE - 1)
#define LP_BITS     21
#define LP_SIZE     (1UL << LP_BITS)
#define LP_MASK     (LP_SIZE - 1)

/* seL4 has no execute right on x86: every mapped page is executable. */
#define RIGHTS_RW   seL4_ReadWrite
#define RIGHTS_RO   seL4_CanRead

/* Debug: last failing stage tag and raw seL4 error. */
char elf_last_stage = '?';
seL4_Error elf_last_seL4_err = seL4_NoError;

/* Bootinfo shared by all procs; set once at startup. */
static seL4_BootInfo *_g_bi = NULL;

void elf_set_bootinfo(seL4_BootInfo *bi)
{
    _g_bi = bi;
}

/* ---------------------------------------------------------------------
 * Capability allocation (shared with main.c)
 * --------------------------------------------------------------------- */

/* Slot allocation with a free list: the root CNode has 4096 slots and
 * a long-lived process manager recycles them as processes die. */
static seL4_Word _slot_offset = 0;

/* Large-page registry (2 MiB frames), reset on proc clear. */
static struct {
    seL4_Word vaddr;
    seL4_CPtr frame;
    seL4_CPtr alias;
} _lp_registry[256];
static int _lp_registry_count = 0;
static seL4_CPtr _free_slots[4096];
static int _free_count = 0;

seL4_CPtr ferrix_alloc_slot(seL4_BootInfo *bi)
{
    if (_free_count > 0) {
        return _free_slots[--_free_count];
    }
    return bi->empty.start + _slot_offset++;
}

void ferrix_free_slot(seL4_CPtr slot)
{
    seL4_CNode_Delete(seL4_CapInitThreadCNode, slot, seL4_WordBits);
    if (_free_count < 4096) _free_slots[_free_count++] = slot;
}

seL4_CPtr ferrix_retype(seL4_BootInfo *bi, seL4_Word type, seL4_Word size_bits)
{
    seL4_Word count = bi->untyped.end - bi->untyped.start;
    seL4_CPtr slot  = ferrix_alloc_slot(bi);

    for (seL4_Word i = 0; i < count; i++) {
        if (bi->untypedList[i].isDevice)              continue;
        if (bi->untypedList[i].sizeBits < size_bits)  continue;

        seL4_Error err = seL4_Untyped_Retype(
            bi->untyped.start + i, type, size_bits,
            seL4_CapInitThreadCNode, 0, 0,
            slot, 1
        );
        if (err == seL4_NoError) return slot;
    }
    return seL4_CapNull;
}

const char *elf_strerror(int error)
{
    switch (error) {
    case ELF_OK:          return "ok";
    case ELF_E_TOOSMALL:  return "file smaller than ELF header";
    case ELF_E_MAGIC:     return "bad ELF magic/class/endianness";
    case ELF_E_TYPE:      return "not a static ET_EXEC binary";
    case ELF_E_ARCH:      return "not an x86-64 binary";
    case ELF_E_PHDR:      return "program header table out of bounds";
    case ELF_E_INTERP:    return "PT_INTERP/PT_DYNAMIC not supported";
    case ELF_E_NOLOAD:    return "no PT_LOAD segments";
    case ELF_E_BOUNDS:    return "segment data exceeds file size";
    case ELF_E_ALIGN:     return "incongruent p_vaddr/p_offset alignment";
    case ELF_E_OVERFLOW:  return "segment crosses USER_TOP";
    case ELF_E_ENTRY:     return "entry point outside loaded segments";
    case ELF_E_NOMEM:     return "out of untyped memory or CNode slots";
    case ELF_E_MAP:       return "seL4 mapping invocation failed";
    case ELF_E_REGISTRY:  return "child frame registry exhausted";
    case ELF_E_ALLOC:     return "address window exhausted";
    default:              return "unknown error";
    }
}

/* Map an already-retyped frame cap into the ROOT vspace at vaddr
 * (creating PDPT/PD/PT as needed).  Shared with vga.c. */
static int ensure_root_paging(seL4_BootInfo *bi, seL4_Word vaddr);
static int ensure_root_paging_nopt(seL4_BootInfo *bi, seL4_Word vaddr,
                                   int no_pt);
seL4_Error elf_root_map_frame(seL4_BootInfo *bi, seL4_CPtr frame,
                              seL4_Word vaddr, seL4_CapRights_t rights,
                              seL4_X86_VMAttributes attr)
{
    int rc = ensure_root_paging(bi, vaddr);
    if (rc != ELF_OK) return seL4_InvalidCapability;
    return seL4_X86_Page_Map(frame, seL4_CapInitThreadVSpace, vaddr,
                             rights, attr);
}

/* Like elf_root_map_frame but for 2 MiB large pages: the PT for the
 * region must NOT exist (a PDE large-page mapping conflicts with it). */
seL4_Error elf_root_map_large_frame(seL4_BootInfo *bi, seL4_CPtr frame,
                                    seL4_Word vaddr, seL4_CapRights_t rights,
                                    seL4_X86_VMAttributes attr)
{
    int rc = ensure_root_paging_nopt(bi, vaddr, true);
    if (rc != ELF_OK) return seL4_InvalidCapability;
    return seL4_X86_Page_Map(frame, seL4_CapInitThreadVSpace, vaddr,
                             rights, attr);
}

/* ---------------------------------------------------------------------
 * Process table
 * --------------------------------------------------------------------- */

static ferrix_proc_t _procs[FERRIX_MAX_PROCS];

ferrix_proc_t *ferrix_proc_find(seL4_Word badge)
{
    for (int i = 0; i < FERRIX_MAX_PROCS; i++) {
        if (_procs[i].used && _procs[i].badge == badge) return &_procs[i];
    }
    return NULL;
}

ferrix_proc_t *ferrix_proc_alloc(seL4_Word badge, seL4_Word parent_badge)
{
    for (int i = 0; i < FERRIX_MAX_PROCS; i++) {
        if (!_procs[i].used) {
            ferrix_proc_t *p = &_procs[i];
            memset(p, 0, sizeof(*p));
            p->used = true;
            p->badge = badge;
            p->parent_badge = parent_badge;
            return p;
        }
    }
    return NULL;
}

ferrix_proc_t *ferrix_proc_at(int index)
{
    if (index < 0 || index >= FERRIX_MAX_PROCS) return NULL;
    return &_procs[index];
}

/* Release every registered frame (unmap from the proc's VSpace, then
 * delete both caps) and recycle their CNode slots. */
void elf_proc_clear(ferrix_proc_t *p)
{
    for (int i = 0; i < p->reg_count; i++) {
        seL4_X86_Page_Unmap(p->reg[i].frame);
        ferrix_free_slot(p->reg[i].frame);
        ferrix_free_slot(p->reg[i].alias);
    }
    p->reg_count = 0;
    p->n_pdpt = p->n_pd = p->n_pt = 0;
    p->heap_top = 0;
    _lp_registry_count = 0;
}

/* Full teardown of a dead process (exit): clear pages, then drop the
 * TCB and badged endpoint caps too.  The proc slot becomes reusable. */
void elf_proc_destroy(ferrix_proc_t *p)
{
    elf_proc_clear(p);
    if (p->tcb != seL4_CapNull) { ferrix_free_slot(p->tcb); p->tcb = 0; }
    if (p->ep != seL4_CapNull)   { ferrix_free_slot(p->ep);   p->ep = 0; }
    if (p->vspace != seL4_CapNull) { ferrix_free_slot(p->vspace); p->vspace = 0; }
    p->used = false;
}

/* ---------------------------------------------------------------------
 * Frame registry
 * --------------------------------------------------------------------- */

static int registry_find(ferrix_proc_t *p, seL4_Word page_vaddr,
                         seL4_CPtr *frame, seL4_CPtr *alias)
{
    for (int i = 0; i < p->reg_count; i++) {
        if (p->reg[i].vaddr == page_vaddr) {
            *frame = p->reg[i].frame;
            if (alias != NULL) *alias = p->reg[i].alias;
            return ELF_OK;
        }
    }
    return ELF_E_REGISTRY;
}

static int registry_add(ferrix_proc_t *p, seL4_Word page_vaddr,
                        seL4_CPtr frame, seL4_CPtr alias)
{
    seL4_CPtr dummy;
    if (registry_find(p, page_vaddr, &dummy, NULL) == ELF_OK) return ELF_E_MAP;
    if (p->reg_count >= FERRIX_MAX_CHILD_FRAMES) return ELF_E_REGISTRY;
    p->reg[p->reg_count].vaddr = page_vaddr;
    p->reg[p->reg_count].frame = frame;
    p->reg[p->reg_count].alias = alias;
    p->reg_count++;
    return ELF_OK;
}

static seL4_CPtr registry_frame_of(ferrix_proc_t *p, seL4_Word page_vaddr)
{
    seL4_CPtr f = seL4_CapNull, a;
    if (registry_find(p, page_vaddr, &f, &a) == ELF_OK) return f;
    return seL4_CapNull;
}

seL4_CPtr elf_proc_frame(ferrix_proc_t *p, seL4_Word vaddr)
{
    return registry_frame_of(p, vaddr);
}

/* ---------------------------------------------------------------------
 * Intermediate paging structures (per proc)
 * --------------------------------------------------------------------- */

static bool region_seen(seL4_Word *seen, int *n, seL4_Word key)
{
    for (int i = 0; i < *n; i++) {
        if (seen[i] == key) return true;
    }
    if (*n >= MAX_REGIONS_EL) return true;
    seen[(*n)++] = key;
    return false;
}

static int ensure_paging(seL4_BootInfo *bi, ferrix_proc_t *p, seL4_Word vaddr)
{
    seL4_CPtr obj;
    seL4_Error err;

    if (!region_seen(p->have_pdpt, &p->n_pdpt, vaddr >> 39)) {
        obj = ferrix_retype(bi, seL4_X86_PDPTObject, seL4_PDPTBits);
        if (obj == seL4_CapNull) return ELF_E_NOMEM;
        err = seL4_X86_PDPT_Map(obj, p->vspace, vaddr, seL4_X86_Default_VMAttributes);
        if (err != seL4_NoError && err != seL4_DeleteFirst) {
            elf_last_stage = 'p'; elf_last_seL4_err = err;
            return ELF_E_MAP;
        }
    }
    if (!region_seen(p->have_pd, &p->n_pd, vaddr >> 30)) {
        obj = ferrix_retype(bi, seL4_X86_PageDirectoryObject, seL4_PageDirBits);
        if (obj == seL4_CapNull) return ELF_E_NOMEM;
        err = seL4_X86_PageDirectory_Map(obj, p->vspace, vaddr, seL4_X86_Default_VMAttributes);
        if (err != seL4_NoError && err != seL4_DeleteFirst) {
            elf_last_stage = 'd'; elf_last_seL4_err = err;
            return ELF_E_MAP;
        }
    }
    if (!region_seen(p->have_pt, &p->n_pt, vaddr >> 21)) {
        obj = ferrix_retype(bi, seL4_X86_PageTableObject, seL4_PageTableBits);
        if (obj == seL4_CapNull) return ELF_E_NOMEM;
        err = seL4_X86_PageTable_Map(obj, p->vspace, vaddr, seL4_X86_Default_VMAttributes);
        if (err != seL4_NoError && err != seL4_DeleteFirst) {
            elf_last_stage = 't'; elf_last_seL4_err = err;
            return ELF_E_MAP;
        }
    }
    return ELF_OK;
}

/* Paging bookkeeping for the ROOT vspace (scratch windows). */
static seL4_Word _root_have_pdpt[MAX_REGIONS_EL]; static int _root_n_pdpt;
static seL4_Word _root_have_pd[MAX_REGIONS_EL];   static int _root_n_pd;
static seL4_Word _root_have_pt[MAX_REGIONS_EL];   static int _root_n_pt;

static int ensure_root_paging_nopt(seL4_BootInfo *bi, seL4_Word vaddr,
                                   int no_pt)
{
    seL4_CPtr obj;
    seL4_Error err;

    if (!region_seen(_root_have_pdpt, &_root_n_pdpt, vaddr >> 39)) {
        obj = ferrix_retype(bi, seL4_X86_PDPTObject, seL4_PDPTBits);
        if (obj == seL4_CapNull) return ELF_E_NOMEM;
        err = seL4_X86_PDPT_Map(obj, seL4_CapInitThreadVSpace, vaddr, seL4_X86_Default_VMAttributes);
        if (err != seL4_NoError && err != seL4_DeleteFirst) {
            elf_last_stage = 'p'; elf_last_seL4_err = err;
            return ELF_E_MAP;
        }
    }
    if (!region_seen(_root_have_pd, &_root_n_pd, vaddr >> 30)) {
        obj = ferrix_retype(bi, seL4_X86_PageDirectoryObject, seL4_PageDirBits);
        if (obj == seL4_CapNull) return ELF_E_NOMEM;
        err = seL4_X86_PageDirectory_Map(obj, seL4_CapInitThreadVSpace, vaddr, seL4_X86_Default_VMAttributes);
        if (err != seL4_NoError && err != seL4_DeleteFirst) {
            elf_last_stage = 'd'; elf_last_seL4_err = err;
            return ELF_E_MAP;
        }
    }
    if (!no_pt && !region_seen(_root_have_pt, &_root_n_pt, vaddr >> 21)) {
        obj = ferrix_retype(bi, seL4_X86_PageTableObject, seL4_PageTableBits);
        if (obj == seL4_CapNull) return ELF_E_NOMEM;
        err = seL4_X86_PageTable_Map(obj, seL4_CapInitThreadVSpace, vaddr, seL4_X86_Default_VMAttributes);
        if (err != seL4_NoError && err != seL4_DeleteFirst) {
            elf_last_stage = 't'; elf_last_seL4_err = err;
            return ELF_E_MAP;
        }
    }
    return ELF_OK;
}

static int ensure_root_paging(seL4_BootInfo *bi, seL4_Word vaddr)
{
    return ensure_root_paging_nopt(bi, vaddr, false);
}

/* ---------------------------------------------------------------------
 * Frame plumbing
 * --------------------------------------------------------------------- */

/* Retype a frame + alias; map the alias at a scratch window with the
 * given rights; return both caps.  The original cap stays unmapped. */
static int scratch_map_new(seL4_BootInfo *bi, seL4_Word scratch_vaddr,
                           seL4_CapRights_t rights,
                           seL4_CPtr *out_frame, seL4_CPtr *out_alias)
{
    seL4_CPtr frame = ferrix_retype(bi, seL4_X86_4K, PAGE_BITS);
    if (frame == seL4_CapNull) return ELF_E_NOMEM;

    seL4_CPtr alias = ferrix_alloc_slot(bi);
    seL4_Error err = seL4_CNode_Copy(
        seL4_CapInitThreadCNode, alias, seL4_WordBits,
        seL4_CapInitThreadCNode, frame, seL4_WordBits, seL4_AllRights);
    if (err != seL4_NoError) {
        elf_last_stage = 'c'; elf_last_seL4_err = err;
        return ELF_E_MAP;
    }

    int rc = ensure_root_paging(bi, scratch_vaddr);
    if (rc != ELF_OK) return rc;

    err = seL4_X86_Page_Map(frame, seL4_CapInitThreadVSpace, scratch_vaddr,
                            rights, seL4_X86_Default_VMAttributes);
    if (err != seL4_NoError) {
        elf_last_stage = 's'; elf_last_seL4_err = err;
        return ELF_E_MAP;
    }

    *out_frame = frame;
    *out_alias = alias;
    return ELF_OK;
}

/* Allocate a fresh zeroed page for proc p at page_vaddr; fill the
 * scratch-window copy with [src+0 .. len) at dst_off before mapping. */
static int map_frame_fill(seL4_BootInfo *bi, ferrix_proc_t *p,
                          seL4_Word page_vaddr, seL4_CapRights_t rights,
                          const void *src, seL4_Word len, seL4_Word dst_off)
{
    if (len > PAGE_SIZE || dst_off + len > PAGE_SIZE) return ELF_E_BOUNDS;

    seL4_CPtr frame, alias;
    int rc = scratch_map_new(bi, FERRIX_SCRATCH_A, RIGHTS_RW, &frame, &alias);
    if (rc != ELF_OK) return rc;

    uint8_t *win = (uint8_t *)FERRIX_SCRATCH_A;
    memset(win, 0, PAGE_SIZE);
    if (src != NULL && len > 0) memcpy(win + dst_off, src, len);

    seL4_X86_Page_Unmap(frame);

    rc = ensure_paging(bi, p, page_vaddr);
    if (rc != ELF_OK) return rc;

    seL4_Error map_err = seL4_X86_Page_Map(
        frame, p->vspace, page_vaddr, rights, seL4_X86_Default_VMAttributes);
    if (map_err != seL4_NoError) {
        elf_last_stage = 'm'; elf_last_seL4_err = map_err;
        return ELF_E_MAP;
    }

    return registry_add(p, page_vaddr, frame, alias);
}

/* Large-page variant: 2 MiB frames, separate registry. */
static int lp_registry_add(seL4_Word vaddr, seL4_CPtr frame, seL4_CPtr alias)
{
    if (_lp_registry_count >= 256) return ELF_E_REGISTRY;
    _lp_registry[_lp_registry_count].vaddr = vaddr;
    _lp_registry[_lp_registry_count].frame = frame;
    _lp_registry[_lp_registry_count].alias = alias;
    _lp_registry_count++;
    return ELF_OK;
}

static int map_frame_fill_lp(seL4_BootInfo *bi, ferrix_proc_t *p,
                             seL4_Word page_vaddr, seL4_CapRights_t rights,
                             const void *src, seL4_Word len, seL4_Word dst_off)
{
    if (len > LP_SIZE || dst_off + len > LP_SIZE) return ELF_E_BOUNDS;

    seL4_CPtr frame = ferrix_retype(bi, seL4_X86_LargePageObject, LP_BITS);
    if (frame == seL4_CapNull) return ELF_E_NOMEM;

    seL4_CPtr alias = ferrix_alloc_slot(bi);
    seL4_Error err = seL4_CNode_Copy(
        seL4_CapInitThreadCNode, alias, seL4_WordBits,
        seL4_CapInitThreadCNode, frame, seL4_WordBits, seL4_AllRights);
    if (err != seL4_NoError) {
        elf_last_stage = 'c'; elf_last_seL4_err = err;
        return ELF_E_MAP;
    }

    int rc = ensure_root_paging(bi, FERRIX_SCRATCH_A);
    if (rc != ELF_OK) return rc;

    err = seL4_X86_Page_Map(
        frame, seL4_CapInitThreadVSpace, FERRIX_SCRATCH_A,
        RIGHTS_RW, seL4_X86_Default_VMAttributes);
    if (err != seL4_NoError) {
        elf_last_stage = 's'; elf_last_seL4_err = err;
        return ELF_E_MAP;
    }

    uint8_t *win = (uint8_t *)FERRIX_SCRATCH_A;
    memset(win, 0, LP_SIZE);
    if (src != NULL && len > 0) memcpy(win + dst_off, src, len);

    seL4_X86_Page_Unmap(frame);

    rc = ensure_paging(bi, p, page_vaddr);
    if (rc != ELF_OK) return rc;

    err = seL4_X86_Page_Map(
        frame, p->vspace, page_vaddr, rights, seL4_X86_Default_VMAttributes);
    if (err != seL4_NoError) {
        elf_last_stage = 'm'; elf_last_seL4_err = err;
        return ELF_E_MAP;
    }

    return lp_registry_add(page_vaddr, frame, alias);
}

/* ---------------------------------------------------------------------
 * Public API
 * --------------------------------------------------------------------- */

seL4_CPtr elf_create_vspace(seL4_BootInfo *bi, ferrix_proc_t *p)
{
    seL4_CPtr pml4 = ferrix_retype(bi, seL4_X64_PML4Object, seL4_VSpaceBits);
    if (pml4 == seL4_CapNull) return seL4_CapNull;

    /* A freshly retyped PML4 is inert until it gets an ASID. */
    seL4_Error err = seL4_X86_ASIDPool_Assign(seL4_CapInitThreadASIDPool, pml4);
    if (err != seL4_NoError) {
        elf_last_stage = 'a'; elf_last_seL4_err = err;
        return seL4_CapNull;
    }
    p->vspace = pml4;
    return pml4;
}

int elf_map_zero_pages(seL4_BootInfo *bi, ferrix_proc_t *p,
                       seL4_Word top_vaddr, seL4_Word num_pages)
{
    for (seL4_Word i = 0; i < num_pages; i++) {
        seL4_Word vaddr = top_vaddr - (i + 1) * PAGE_SIZE;
        int err = map_frame_fill(bi, p, vaddr, RIGHTS_RW, NULL, 0, 0);
        if (err != ELF_OK) return err;
    }
    return ELF_OK;
}

seL4_CPtr elf_map_ipc_buffer(seL4_BootInfo *bi, ferrix_proc_t *p,
                             seL4_Word vaddr)
{
    if (vaddr & PAGE_MASK) return seL4_CapNull;

    int err = map_frame_fill(bi, p, vaddr, RIGHTS_RW, NULL, 0, 0);
    if (err != ELF_OK) return seL4_CapNull;

    return registry_frame_of(p, vaddr);
}

int elf_fork_vspace(seL4_BootInfo *bi, ferrix_proc_t *parent,
                    ferrix_proc_t *child)
{
    /* Rebuild the paging structures for the child first. */
    for (int i = 0; i < parent->reg_count; i++) {
        seL4_Word page = parent->reg[i].vaddr;
        int rc = ensure_paging(bi, child, page);
        if (rc != ELF_OK) return rc;

        seL4_CPtr nframe, nalias;
        rc = scratch_map_new(bi, FERRIX_SCRATCH_B, RIGHTS_RW, &nframe, &nalias);
        if (rc != ELF_OK) return rc;

        /* Map the parent's alias RO at scratch A and copy. */
        rc = ensure_root_paging(bi, FERRIX_SCRATCH_A);
        if (rc != ELF_OK) return rc;
        seL4_Error err = seL4_X86_Page_Map(
            parent->reg[i].alias, seL4_CapInitThreadVSpace, FERRIX_SCRATCH_A,
            RIGHTS_RO, seL4_X86_Default_VMAttributes);
        if (err != seL4_NoError) {
            elf_last_stage = 'f'; elf_last_seL4_err = err;
            return ELF_E_MAP;
        }

        memcpy((void *)FERRIX_SCRATCH_B, (const void *)FERRIX_SCRATCH_A, PAGE_SIZE);

        seL4_X86_Page_Unmap(parent->reg[i].alias);
        seL4_X86_Page_Unmap(nframe);

        err = seL4_X86_Page_Map(
            nframe, child->vspace, page, RIGHTS_RW, seL4_X86_Default_VMAttributes);
        if (err != seL4_NoError) {
            elf_last_stage = 'm'; elf_last_seL4_err = err;
            return ELF_E_MAP;
        }

        rc = registry_add(child, page, nframe, nalias);
        if (rc != ELF_OK) return rc;
    }
    return ELF_OK;
}

int elf_load(seL4_BootInfo *bi, ferrix_proc_t *p,
             const void *elf_data, seL4_Word elf_size,
             elf_load_result_t *out)
{
    if (elf_size < sizeof(Elf64_Ehdr)) return ELF_E_TOOSMALL;

    const Elf64_Ehdr *ehdr = (const Elf64_Ehdr *)elf_data;

    if (ehdr->e_ident[0] != ELFMAG0 || ehdr->e_ident[1] != ELFMAG1 ||
        ehdr->e_ident[2] != ELFMAG2 || ehdr->e_ident[3] != ELFMAG3 ||
        ehdr->e_ident[4] != ELFCLASS64 || ehdr->e_ident[5] != ELFDATA2LSB) {
        return ELF_E_MAGIC;
    }
    if (ehdr->e_type != ET_EXEC) return ELF_E_TYPE;
    if (ehdr->e_machine != EM_X86_64) return ELF_E_ARCH;
    if (ehdr->e_phentsize != sizeof(Elf64_Phdr)) return ELF_E_PHDR;
    if (ehdr->e_phoff > elf_size ||
        ehdr->e_phnum > (elf_size - ehdr->e_phoff) / sizeof(Elf64_Phdr)) {
        return ELF_E_PHDR;
    }

    const Elf64_Phdr *phdrs = (const Elf64_Phdr *)
        ((const char *)elf_data + ehdr->e_phoff);

    bool has_load = false;
    for (uint16_t i = 0; i < ehdr->e_phnum; i++) {
        if (phdrs[i].p_type == PT_INTERP || phdrs[i].p_type == PT_DYNAMIC) {
            return ELF_E_INTERP;
        }
        if (phdrs[i].p_type == PT_LOAD) has_load = true;
    }
    if (!has_load) return ELF_E_NOLOAD;

    seL4_Word min_vaddr = ~(seL4_Word)0;
    seL4_Word max_vaddr = 0;

    for (uint16_t i = 0; i < ehdr->e_phnum; i++) {
        const Elf64_Phdr *ph = &phdrs[i];
        if (ph->p_type != PT_LOAD) continue;

        if (ph->p_align > 1 &&
            (ph->p_vaddr % ph->p_align) != (ph->p_offset % ph->p_align)) {
            return ELF_E_ALIGN;
        }
        if (ph->p_memsz < ph->p_filesz) return ELF_E_BOUNDS;
        /* A segment may start past EOF when p_filesz == 0 (pure BSS). */
        if (ph->p_filesz > 0 &&
            (ph->p_offset >= elf_size || ph->p_filesz > elf_size - ph->p_offset)) {
            return ELF_E_BOUNDS;
        }
        if (ph->p_vaddr < PAGE_SIZE) return ELF_E_ALIGN;
        if (ph->p_vaddr + ph->p_memsz < ph->p_vaddr) return ELF_E_OVERFLOW;

        seL4_Word seg_end = ph->p_vaddr + ph->p_memsz;
        if (seg_end > 0x7fffffffffffUL) return ELF_E_OVERFLOW;

        seL4_CapRights_t rights = (ph->p_flags & PF_W) ? RIGHTS_RW : RIGHTS_RO;

        /* Large pages (2 MiB) when the segment is 2 MiB-aligned: one
         * retype + one map instead of 512 — critical for CNode slot
         * budget and TCG exec speed. */
        const bool big = (ph->p_vaddr & (LP_SIZE - 1)) == 0 &&
                         (ph->p_offset & (LP_SIZE - 1)) == 0 &&
                         (seg_end - ph->p_vaddr) >= LP_SIZE;

        if (big) {
            seL4_Word first_lp = ph->p_vaddr & ~(LP_SIZE - 1);
            seL4_Word last_lp  = (seg_end + LP_SIZE - 1) & ~(LP_SIZE - 1);

            for (seL4_Word lp = first_lp; lp < last_lp; lp += LP_SIZE) {
                int64_t lo = (int64_t)lp - (int64_t)ph->p_vaddr;
                int64_t hi = lo + (int64_t)LP_SIZE;
                if (lo < 0) lo = 0;
                if (hi > (int64_t)ph->p_filesz) hi = ph->p_filesz;

                const void *src = NULL;
                seL4_Word copy = 0;
                seL4_Word dst_off = 0;
                if (hi > lo) {
                    copy = (seL4_Word)(hi - lo);
                    src  = (const char *)elf_data + ph->p_offset + (seL4_Word)lo;
                    dst_off = (seL4_Word)(((int64_t)ph->p_vaddr + lo) - (int64_t)lp);
                }

                int err = map_frame_fill_lp(bi, p, lp, rights, src, copy, dst_off);
                if (err != ELF_OK) return err;
            }
            if (ph->p_vaddr < min_vaddr) min_vaddr = ph->p_vaddr;
            if (seg_end > max_vaddr)     max_vaddr = seg_end;
            continue;
        }

        seL4_Word first_page = ph->p_vaddr & ~PAGE_MASK;
        seL4_Word last_page  = (seg_end + PAGE_MASK) & ~PAGE_MASK;

        for (seL4_Word page = first_page; page < last_page; page += PAGE_SIZE) {
            int64_t lo = (int64_t)page - (int64_t)ph->p_vaddr;
            int64_t hi = lo + (int64_t)PAGE_SIZE;
            if (lo < 0) lo = 0;
            if (hi > (int64_t)ph->p_filesz) hi = ph->p_filesz;

            const void *src = NULL;
            seL4_Word copy = 0;
            seL4_Word dst_off = 0;
            if (hi > lo) {
                copy = (seL4_Word)(hi - lo);
                src  = (const char *)elf_data + ph->p_offset + (seL4_Word)lo;
                dst_off = (seL4_Word)(((int64_t)ph->p_vaddr + lo) - (int64_t)page);
            }

            int err = map_frame_fill(bi, p, page, rights, src, copy, dst_off);
            if (err != ELF_OK) return err;
        }

        if (ph->p_vaddr < min_vaddr) min_vaddr = ph->p_vaddr;
        if (seg_end > max_vaddr)     max_vaddr = seg_end;
    }

    if (ehdr->e_entry < min_vaddr || ehdr->e_entry >= max_vaddr) {
        return ELF_E_ENTRY;
    }

    out->entry     = ehdr->e_entry;
    out->max_vaddr = (max_vaddr + PAGE_MASK) & ~PAGE_MASK;
    return ELF_OK;
}

bool ferrix_read_child_memory(ferrix_proc_t *p, void *dest,
                              seL4_Word child_vaddr, seL4_Word len)
{
    uint8_t *d = (uint8_t *)dest;

    while (len > 0) {
        seL4_Word page = child_vaddr & ~PAGE_MASK;
        seL4_CPtr frame, alias;
        if (registry_find(p, page, &frame, &alias) != ELF_OK) return false;

        int rc = ensure_root_paging(_g_bi, FERRIX_SCRATCH_A);
        if (rc != ELF_OK) return false;
        seL4_Error err = seL4_X86_Page_Map(
            alias, seL4_CapInitThreadVSpace, FERRIX_SCRATCH_A,
            RIGHTS_RO, seL4_X86_Default_VMAttributes);
        if (err != seL4_NoError) return false;

        seL4_Word off = child_vaddr & PAGE_MASK;
        seL4_Word n   = PAGE_SIZE - off;
        if (n > len) n = len;
        memcpy(d, (const void *)(FERRIX_SCRATCH_A + off), n);

        seL4_X86_Page_Unmap(alias);

        d += n;
        child_vaddr += n;
        len -= n;
    }
    return true;
}

bool ferrix_write_child_memory(ferrix_proc_t *p, seL4_Word child_vaddr,
                               const void *src, seL4_Word len)
{
    const uint8_t *s = (const uint8_t *)src;

    while (len > 0) {
        seL4_Word page = child_vaddr & ~PAGE_MASK;
        seL4_CPtr frame, alias;
        if (registry_find(p, page, &frame, &alias) != ELF_OK) return false;

        int rc = ensure_root_paging(NULL, FERRIX_SCRATCH_A);
        if (rc != ELF_OK) return false;
        seL4_Error err = seL4_X86_Page_Map(
            alias, seL4_CapInitThreadVSpace, FERRIX_SCRATCH_A,
            RIGHTS_RW, seL4_X86_Default_VMAttributes);
        if (err != seL4_NoError) return false;

        seL4_Word off = child_vaddr & PAGE_MASK;
        seL4_Word n   = PAGE_SIZE - off;
        if (n > len) n = len;
        memcpy((void *)(FERRIX_SCRATCH_A + off), s, n);

        seL4_X86_Page_Unmap(alias);

        s += n;
        child_vaddr += n;
        len -= n;
    }
    return true;
}

seL4_Word ferrix_setup_initial_stack(seL4_BootInfo *bi, ferrix_proc_t *p,
                                     seL4_Word stack_top,
                                     const char *const *argv,
                                     const char *const *envp)
{
    /* Linux x86_64 AT_* tags used on the initial stack. */
    enum { AT_NULL = 0, AT_PAGESZ = 6, AT_CLKTCK = 17,
           AT_UID = 11, AT_EUID = 12, AT_GID = 13, AT_EGID = 14,
           AT_SECURE = 23, AT_RANDOM = 25 };

    seL4_Word argc = 0, envc = 0;
    while (argv != NULL && argv[argc] != NULL) argc++;
    while (envp != NULL && envp[envc] != NULL) envc++;

    seL4_Word str_size = 16;
    for (seL4_Word i = 0; i < argc; i++) str_size += strlen(argv[i]) + 1;
    for (seL4_Word i = 0; i < envc; i++) str_size += strlen(envp[i]) + 1;

    seL4_Word block_words = 1 + (argc + 1) + (envc + 1) + (2 * 9 + 1);
    seL4_Word block_size  = block_words * sizeof(seL4_Word);

    if (str_size + block_size + 16 > PAGE_SIZE) return 0;

    seL4_Word str_top  = (stack_top - 16) & ~0xfUL;
    seL4_Word str_base = str_top - str_size;
    seL4_Word rsp      = (str_base - block_size) & ~0xfUL;

    /* Copy argv/envp strings, remembering their child addresses. */
    seL4_Word pos = str_base;
    seL4_Word *str_addrs = __builtin_alloca((argc + envc) * sizeof(seL4_Word));
    for (seL4_Word i = 0; i < argc + envc; i++) {
        const char *s = (i < argc) ? argv[i] : envp[i - argc];
        seL4_Word slen = strlen(s) + 1;
        if (!ferrix_write_child_memory(p, pos, s, slen)) return 0;
        str_addrs[i] = pos;
        pos += slen;
    }
    uint8_t rnd[16] = {0x9e, 0x37, 0x79, 0xb9, 0x7f, 0x4a, 0x7c, 0x15,
                       0x94, 0xd0, 0x04, 0x2d, 0x3f, 0x8b, 0x1c, 0x66};
    if (!ferrix_write_child_memory(p, pos, rnd, sizeof(rnd))) return 0;
    seL4_Word rnd_addr = pos;

    seL4_Word block[64];
    seL4_Word k = 0;
    block[k++] = argc;
    for (seL4_Word i = 0; i < argc; i++) block[k++] = str_addrs[i];
    block[k++] = 0;
    for (seL4_Word i = 0; i < envc; i++) block[k++] = str_addrs[argc + i];
    block[k++] = 0;
    block[k++] = AT_PAGESZ; block[k++] = 4096;
    block[k++] = AT_CLKTCK; block[k++] = 100;
    block[k++] = AT_UID;    block[k++] = 0;
    block[k++] = AT_EUID;   block[k++] = 0;
    block[k++] = AT_GID;    block[k++] = 0;
    block[k++] = AT_EGID;   block[k++] = 0;
    block[k++] = AT_SECURE; block[k++] = 0;
    block[k++] = AT_RANDOM; block[k++] = rnd_addr;
    block[k++] = AT_NULL;   block[k++] = 0;
    if (k > block_words) return 0;

    if (!ferrix_write_child_memory(p, rsp, block, k * sizeof(seL4_Word))) {
        return 0;
    }
    return rsp;
}
