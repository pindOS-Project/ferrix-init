/*
 * halt_embed.S — embeds the static "halt" ELF (test-elf/halt.elf) into
 * the ferrix_init image.  HALT_ELF_PATH is set by CMake.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

    .section .rodata.haltelf, "a"
    .balign 8
    .globl halt_elf_start
halt_elf_start:
    .incbin HALT_ELF_PATH
    .globl halt_elf_end
halt_elf_end:
