/*
 * ferrix-init — VGA framebuffer discovery and mapping.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <sel4/sel4.h>
#include <sel4/bootinfo.h>

/* Parse the framebuffer bootinfo header, map it into the root task's
 * address space and configure the burmalda VGA console.  Returns 0 on
 * success, -1 if no usable framebuffer is available (serial-only). */
int ferrix_vga_init(seL4_BootInfo *bi);
