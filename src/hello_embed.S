/*
 * hello_embed.S — embeds the static test ELF (test-elf/hello.elf) into
 * the ferrix_init image.  TEST_ELF_PATH is set by CMake; the assembler
 * runs through the C preprocessor (.S), so it expands to a string.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

    .section .rodata.helloelf, "a"
    .balign 8
    .globl hello_elf_start
hello_elf_start:
    .incbin TEST_ELF_PATH
    .globl hello_elf_end
hello_elf_end:
