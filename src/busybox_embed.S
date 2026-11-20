/*
 * busybox_embed.S — embeds the static busybox binary
 * (tools/busybox-1.36.1-ferrix/busybox).  BUSYBOX_ELF_PATH is set by
 * CMake.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

    .section .rodata.busyboxelf, "a"
    .balign 8
    .globl busybox_elf_start
busybox_elf_start:
    .incbin BUSYBOX_ELF_PATH
    .globl busybox_elf_end
busybox_elf_end:
