/*
 * idle_embed.S — embeds the static "idle" ELF (test-elf/idle.elf) into
 * the ferrix_init image.  IDLE_ELF_PATH is set by CMake.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

    .section .rodata.idleelf, "a"
    .balign 8
    .globl idle_elf_start
idle_elf_start:
    .incbin IDLE_ELF_PATH
    .globl idle_elf_end
idle_elf_end:
