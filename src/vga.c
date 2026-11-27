/*
 * ferrix-init — VGA framebuffer discovery and mapping.
 *
 * Parses the seL4 extra bootinfo for the GRUB multiboot framebuffer
 * header (SEL4_BOOTINFO_HEADER_X86_FRAMEBUFFER), maps the framebuffer
 * memory into the root task's address space (device untypeds + 2 MiB
 * large pages, 4 KiB fallback) and hands it to the burmalda console
 * renderer.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <sel4/sel4.h>
#include <sel4/bootinfo.h>
#include <sel4/types.h>
#include <sel4/arch/bootinfo_types.h>

#include <burmalda/vgaconsole.h>

#include "elf_loader.h"
#include "vga.h"

/* Root-vspace window for the framebuffer (well clear of userland
 * 0x20000000-0x30000000 and scratch 0x30000000). */
#define VGA_VADDR       0x48000000UL
#define VGA_MAX_BYTES   (8u * 1024 * 1024)
#define VGA_LP_SIZE     (1UL << 21)
#define VGA_PAGE_SIZE   (1UL << 12)

/* Layout of the multiboot2 framebuffer tag as passed by the kernel in
 * the SEL4_BOOTINFO_HEADER_X86_FRAMEBUFFER bootinfo chunk (the
 * seL4_X86_BootInfo_fb_t typedef is incomplete in libsel4). */
typedef struct {
    uint64_t addr;
    uint32_t pitch;
    uint32_t width;
    uint32_t height;
    uint8_t  bpp;
    uint8_t  type;
} __attribute__((packed)) ferrix_fb_info_t;

/* Root paging helpers are static in elf_loader.c; this thin wrapper is
 * implemented there (exported via vga.h). */

static void put(const char *s)
{
    while (*s) seL4_DebugPutChar(*s++);
}

static void put_hex(seL4_Word v)
{
    static const char d[] = "0123456789abcdef";
    for (int i = (int)(sizeof(v) * 2) - 1; i >= 0; i--) {
        seL4_DebugPutChar(d[(v >> (i * 4)) & 0xf]);
    }
}

/* Find a device untyped whose region contains [paddr, paddr+size).
 * Returns the untyped cap slot (bi-relative index into untyped.start)
 * via *out_ut, the byte offset within it via *out_off. */
static bool find_device_untyped(seL4_BootInfo *bi, seL4_Word paddr,
                                seL4_Word size, seL4_CPtr *out_ut,
                                seL4_Word *out_off)
{
    seL4_Word count = bi->untyped.end - bi->untyped.start;
    for (seL4_Word i = 0; i < count; i++) {
        const seL4_UntypedDesc *d = &bi->untypedList[i];
        if (!d->isDevice) continue;
        seL4_Word up = d->paddr;
        seL4_Word us = (seL4_Word)1 << d->sizeBits;
        if (paddr >= up && paddr + size <= up + us) {
            *out_ut = bi->untyped.start + i;
            *out_off = paddr - up;
            return true;
        }
    }
    return false;
}

/* Map the framebuffer [paddr, paddr+total) from a device untyped into
 * the root-vspace window at VGA_VADDR.  The kernel hands out device
 * memory sequentially, so bytes between the untyped region start and
 * paddr are consumed once (as throwaway 4K pages) before the real
 * mappings.  Prefers 2 MiB large pages; falls back to 4K pages. */
static bool map_fb(seL4_BootInfo *bi, seL4_Word paddr, seL4_Word total)
{
    seL4_CPtr ut;
    seL4_Word base_off;
    if (!find_device_untyped(bi, paddr, total, &ut, &base_off)) {
        put("vga: no device untyped covers 0x");
        put_hex(paddr);
        put("\n");
        return false;
    }
    put("vga: device untyped idx=0x");
    put_hex(ut - bi->untyped.start);
    put(" paddr=0x");
    put_hex(bi->untypedList[ut - bi->untyped.start].paddr);
    put(" size=2^");
    put_hex(bi->untypedList[ut - bi->untyped.start].sizeBits);
    put(" gap=0x");
    put_hex(base_off);
    put("\n");

    /* Consume the gap between the untyped region start and paddr.
     * The gap caps must stay ALIVE: deleting them would leave the
     * untyped without children, and the next retype would reset its
     * free offset back to the region start.  Binary-decompose the gap
     * into untyped objects (device memory propagates). */
    seL4_Word gap = base_off;
    for (int k = 40; k >= 12 && gap > 0; k--) {
        if ((gap & (seL4_Word)1 << k) == 0) continue;
        seL4_CPtr slot = ferrix_alloc_slot(bi);
        if (slot == seL4_CapNull) return false;
        seL4_Error err = seL4_Untyped_Retype(
            ut, seL4_UntypedObject, (seL4_Word)k,
            seL4_CapInitThreadCNode, 0, 0, slot, 1);
        if (err != seL4_NoError) {
            ferrix_free_slot(slot);
            return false;
        }
        /* keep the cap: leaked deliberately to pin the untyped offset */
        gap -= (seL4_Word)1 << k;
    }
    if (gap != 0) {
        put("vga: gap 0x");
        put_hex(gap);
        put(" not page-aligned\n");
        return false;
    }

    seL4_Word mapped_bytes = 0;

    /* Large-page attempt: whole framebuffer from 2MiB-aligned paddr. */
    if ((paddr & (VGA_LP_SIZE - 1)) == 0) {
        seL4_Word n_lp = (total + VGA_LP_SIZE - 1) >> 21;
        bool lp_ok = true;
        for (seL4_Word k = 0; k < n_lp && lp_ok; k++) {
            seL4_CPtr slot = ferrix_alloc_slot(bi);
            if (slot == seL4_CapNull) { lp_ok = false; break; }
            seL4_Error err = seL4_Untyped_Retype(
                ut, seL4_X86_LargePageObject, 21,
                seL4_CapInitThreadCNode, 0, 0, slot, 1);
            if (err != seL4_NoError) {
                ferrix_free_slot(slot);
                put("vga: LP retype err=");
                put_hex(err);
                put("\n");
                lp_ok = false;
                break;
            }
            seL4_Word va = VGA_VADDR + k * VGA_LP_SIZE;
            err = elf_root_map_large_frame(bi, slot, va, seL4_ReadWrite,
                                           seL4_X86_Default_VMAttributes);
            if (err != seL4_NoError) {
                ferrix_free_slot(slot);
                put("vga: LP map err=");
                put_hex(err);
                put("\n");
                lp_ok = false;
                break;
            }
        }
        if (lp_ok) {
            mapped_bytes = n_lp * VGA_LP_SIZE;
            put("vga: used ");
            put_hex(n_lp);
            put(" large pages\n");
        }
        /* On failure the untyped free offset is unchanged (retype of
         * the large page itself failed after the skip), so the 4K
         * fallback below continues from paddr. */
    }

    if (mapped_bytes < total) {
        seL4_Word n_4k = (total - mapped_bytes + VGA_PAGE_SIZE - 1) >> 12;
        for (seL4_Word k = 0; k < n_4k; k++) {
            seL4_CPtr slot = ferrix_alloc_slot(bi);
            if (slot == seL4_CapNull) return false;
            seL4_Error err = seL4_Untyped_Retype(
                ut, seL4_X86_4K, 12, seL4_CapInitThreadCNode, 0, 0, slot, 1);
            if (err != seL4_NoError) {
                ferrix_free_slot(slot);
                put("vga: 4K retype err=");
                put_hex(err);
                put("\n");
                return false;
            }
            seL4_Word va = VGA_VADDR + mapped_bytes + k * VGA_PAGE_SIZE;
            err = elf_root_map_frame(bi, slot, va, seL4_ReadWrite,
                                     seL4_X86_Default_VMAttributes);
            if (err != seL4_NoError) {
                ferrix_free_slot(slot);
                put("vga: 4K map err=");
                put_hex(err);
                put("\n");
                return false;
            }
        }
        put("vga: used ");
        put_hex(n_4k);
        put(" 4K pages\n");
    }
    return true;
}

int ferrix_vga_init(seL4_BootInfo *bi)
{
    seL4_Word base = (seL4_Word)bi + seL4_BootInfoFrameSize;
    seL4_Word end  = base + bi->extraLen;

    ferrix_fb_info_t fb = { 0 };
    bool have = false;
    for (seL4_Word p = base; p + sizeof(seL4_BootInfoHeader) <= end; ) {
        seL4_BootInfoHeader *h = (seL4_BootInfoHeader *)p;
        if (h->len < sizeof(seL4_BootInfoHeader) || p + h->len > end) break;
        if (h->id == SEL4_BOOTINFO_HEADER_X86_FRAMEBUFFER) {
            memcpy(&fb, (void *)(p + sizeof(seL4_BootInfoHeader)),
                   sizeof(fb));
            have = true;
        } else if (h->id == SEL4_BOOTINFO_HEADER_X86_VBE) {
            /* multiboot1 path: GRUB set a VBE linear mode per the
             * kernel's mb1 graphics header; extract the framebuffer
             * parameters from the passed VBE mode info block. */
            seL4_X86_BootInfo_VBE *vbe = (seL4_X86_BootInfo_VBE *)p;
            if (vbe->vbeMode != (seL4_Uint32)-1 &&
                vbe->vbeModeInfoBlock.vbe20.physBasePtr != 0) {
                fb.addr   = vbe->vbeModeInfoBlock.vbe20.physBasePtr;
                fb.pitch  = vbe->vbeModeInfoBlock.vbe_common.bytesPerScanLine;
                fb.width  = vbe->vbeModeInfoBlock.vbe12_part1.xRes;
                fb.height = vbe->vbeModeInfoBlock.vbe12_part1.yRes;
                fb.bpp    = vbe->vbeModeInfoBlock.vbe12_part1.bitsPerPixel;
                fb.type   = 1;                     /* direct color */
                have = true;
            }
        }
        if (h->id == 0) break;                    /* padding = end */
        p += h->len;
    }

    if (!have || fb.addr == 0 || fb.bpp != 32) {
        put("vga: no framebuffer in bootinfo (");
        if (have) {
            put("addr=0x"); put_hex(fb.addr);
            put(" bpp=");   put_hex(fb.bpp);
            put(" type=");  put_hex(fb.type);
        } else {
            put("header absent");
        }
        put(")\n");
        return -1;
    }

    seL4_Word total = (seL4_Word)fb.pitch * fb.height;
    if (total > VGA_MAX_BYTES) total = VGA_MAX_BYTES;

    if (!map_fb(bi, fb.addr, total)) {
        put("vga: FAILED to map framebuffer at 0x");
        put_hex(fb.addr);
        put("\n");
        return -1;
    }
    put("vga: mapped 0x");
    put_hex(fb.addr);
    put(" -> 0x");
    put_hex(VGA_VADDR);
    put("\n");

    /* Mapping self-test: write and read back through the window. */
    volatile uint32_t *probe = (volatile uint32_t *)VGA_VADDR;
    probe[0] = 0xA5A51234;
    put("vga: probe readback 0x");
    put_hex(probe[0]);
    put(" (expect 0xa5a51234)\n");

    burmalda_vga_configure((uint32_t *)VGA_VADDR, fb.width, fb.height,
                           fb.pitch, fb.bpp);
    put("vga: console ready ");
    put_hex(fb.width);
    put("x");
    put_hex(fb.height);
    put("@");
    put_hex(fb.bpp);
    put("\n");
    return 0;
}
