/*
 * rootfs_embed.S — embeds the RAM-FS seed archive (newc cpio) built
 * from ramfs-src/ by tools/mkcpio.py.  CPIO_PATH is set by CMake.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

    .section .rodata.rootfscpio, "a"
    .balign 8
    .globl rootfs_cpio_start
rootfs_cpio_start:
    .incbin CPIO_PATH
    .globl rootfs_cpio_end
rootfs_cpio_end:
