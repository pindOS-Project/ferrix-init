/*
 * ferrix-init — Ferrix root task / PID 0
 *
 * This is the first userspace code that runs on the Ferrix microkernel.
 * It acts as the seL4 root task and bootstraps the POSIX environment:
 *
 *   1. Allocates kernel objects (endpoint, TCB, SC/Reply for MCS).
 *   2. Starts the burmalda POSIX personality on the fault endpoint.
 *   3. [M3+] Loads dinit as the first POSIX ELF process (PID 1).
 *      dinit then manages all subsequent services including FreeBSD
 *      userland components.
 *
 * For now (K2 milestone) burmalda_run() handles all POSIX syscalls
 * from any thread that has seL4_TCBFlag_posixSyscalls set.
 *
 * Platform: x86_64 / pc99 / QEMU.
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sel4/sel4.h>
#include <sel4/bootinfo.h>
#include <stdio.h>

#include <burmalda/protocol.h>  /* burmalda_run() */

/* ---------------------------------------------------------------------------
 * Object allocation from bootinfo free slots.
 * seL4_Untyped_Retype with node_depth=0 targets the root CNode directly.
 * --------------------------------------------------------------------------- */

static seL4_Word _next_slot_offset = 0;

static seL4_CPtr alloc_slot(seL4_BootInfo *bi)
{
    return bi->empty.start + _next_slot_offset++;
}

static seL4_CPtr retype(seL4_BootInfo *bi, seL4_Word type, seL4_Word size_bits)
{
    seL4_Word count = bi->untyped.end - bi->untyped.start;
    seL4_CPtr slot  = alloc_slot(bi);

    for (seL4_Word i = 0; i < count; i++) {
        if (bi->untypedList[i].isDevice)              continue;
        if (bi->untypedList[i].sizeBits < size_bits)  continue;

        seL4_Error err = seL4_Untyped_Retype(
            bi->untyped.start + i,  /* untyped cap  */
            type, size_bits,
            seL4_CapInitThreadCNode, /* node_root   */
            0,                       /* node_index  */
            0,                       /* node_depth=0 → root CNode */
            slot,                    /* node_offset  */
            1                        /* num_objects  */
        );
        if (err == seL4_NoError) return slot;
    }
    return seL4_CapNull;
}

static int fail(const char *msg, seL4_Error err)
{
    printf("ferrix-init: FATAL: %s (%d)\n", msg, (int)err);
    return 1;
}

/* ---------------------------------------------------------------------------
 * main
 * --------------------------------------------------------------------------- */

int main(void)
{
    seL4_BootInfo *bi = seL4_GetBootInfo();

    printf("ferrix-init: starting (Ferrix microkernel, x86_64)\n");

    /* --- Allocate the POSIX fault endpoint -------------------------------- */
    seL4_CPtr ep = retype(bi, seL4_EndpointObject, seL4_EndpointBits);
    if (ep == seL4_CapNull) return fail("endpoint retype", seL4_NotEnoughMemory);

#ifdef CONFIG_KERNEL_MCS
    /* MCS: allocate a reply object for burmalda's receive loop */
    seL4_CPtr reply_obj = retype(bi, seL4_ReplyObject, seL4_ReplyBits);
    if (reply_obj == seL4_CapNull) return fail("reply retype", seL4_NotEnoughMemory);
#else
    seL4_CPtr reply_obj = seL4_CapNull; /* unused in non-MCS */
#endif

    printf("ferrix-init: fault endpoint at slot %lu\n", (unsigned long)ep);
    printf("ferrix-init: handing off to burmalda POSIX personality\n");

    /*
     * TODO (M3): before calling burmalda_run(), load dinit as a POSIX ELF
     * process and assign it this fault endpoint, so dinit's syscalls are
     * served by burmalda.  Steps:
     *   1. Parse the dinit ELF embedded in the boot image.
     *   2. Allocate VSpace, map ELF segments.
     *   3. Create TCB, set seL4_TCBFlag_posixSyscalls, set fault EP = ep.
     *   4. Start dinit thread.
     * burmalda_run() then processes its syscalls as they arrive.
     */

    /* Hand control to burmalda.  This call never returns. */
    burmalda_run(ep, reply_obj);

    /* UNREACHABLE */
    return 0;
}
