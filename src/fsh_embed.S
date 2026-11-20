/*
 * fsh_embed.S — embeds the interactive shell (test-elf/fsh.elf) into
 * the ferrix_init image.  FSH_ELF_PATH is set by CMake.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

    .section .rodata.fshelf, "a"
    .balign 8
    .globl fsh_elf_start
fsh_elf_start:
    .incbin FSH_ELF_PATH
    .globl fsh_elf_end
fsh_elf_end:
