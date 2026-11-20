/*
 * dinit_embed.S — embeds the statically linked dinit ELF
 * (built with the musl cross toolchain) into the ferrix_init image.
 * DINIT_ELF_PATH is set by CMake.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

    .section .rodata.dinitelf, "a"
    .balign 8
    .globl dinit_elf_start
dinit_elf_start:
    .incbin DINIT_ELF_PATH
    .globl dinit_elf_end
dinit_elf_end:
