cmake_minimum_required(VERSION 3.16)
project(ferrix_init C)

# ferrix-init — Ferrix root task
#
# This is the first process that runs on the Ferrix kernel. It bootstraps
# the POSIX environment by starting the burmalda personality server, which
# handles all POSIX syscalls from flagged threads.
#
# Later (M3+) it will load dinit as the first ELF process (POSIX PID 1).
#
# Dependencies (all standard seL4 project scaffolding):
#   sel4        — kernel IPC stubs and headers
#   sel4runtime — root-task _start, seL4_GetBootInfo
#   muslc       — libc (printf, etc.)
#   burmalda    — POSIX personality dispatch loop

# burmalda is a sibling directory; find it relative to this file.
if(NOT TARGET burmalda)
    add_subdirectory(
        ${CMAKE_CURRENT_LIST_DIR}/../burmalda
        ${CMAKE_CURRENT_BINARY_DIR}/burmalda
    )
endif()

add_executable(ferrix_init src/main.c)

target_link_libraries(ferrix_init
    burmalda     # POSIX personality (links sel4 transitively)
    sel4runtime  # root-task entry point + seL4_GetBootInfo
    muslc        # libc
)

# Install / image target is handled by the top-level seL4 project CMake.
