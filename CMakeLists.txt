cmake_minimum_required(VERSION 3.16)
project(ferrix_init C ASM)

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

add_executable(ferrix_init
    src/main.c
    src/elf_loader.c
    src/hello_embed.S
    src/dinit_embed.S
    src/halt_embed.S
    src/idle_embed.S
    src/fsh_embed.S
    src/rootfs_embed.S
    src/busybox_embed.S
)

# hello_embed.S embeds the static test ELF via .incbin; give the
# assembler the file path as a preprocessor macro.
set(TEST_ELF_FILE "${CMAKE_CURRENT_LIST_DIR}/../test-elf/hello.elf")
if(NOT EXISTS "${TEST_ELF_FILE}")
    message(FATAL_ERROR "Test ELF not found: ${TEST_ELF_FILE} (build test-elf/hello.elf first)")
endif()
set_source_files_properties(src/hello_embed.S PROPERTIES
    COMPILE_DEFINITIONS "TEST_ELF_PATH=\"${TEST_ELF_FILE}\""
)

# dinit_embed.S embeds the statically linked dinit (musl cross build).
set(DINIT_ELF_FILE "${CMAKE_CURRENT_LIST_DIR}/../build/dinit-build/src/dinit-static")
set_source_files_properties(src/dinit_embed.S PROPERTIES
    COMPILE_DEFINITIONS "DINIT_ELF_PATH=\"${DINIT_ELF_FILE}\""
)

# halt_embed.S embeds the static "halt" binary for execve("/sbin/halt").
set(HALT_ELF_FILE "${CMAKE_CURRENT_LIST_DIR}/../test-elf/halt.elf")
set_source_files_properties(src/halt_embed.S PROPERTIES
    COMPILE_DEFINITIONS "HALT_ELF_PATH=\"${HALT_ELF_FILE}\""
)

# idle_embed.S embeds the static "idle" service binary.
set(IDLE_ELF_FILE "${CMAKE_CURRENT_LIST_DIR}/../test-elf/idle.elf")
set_source_files_properties(src/idle_embed.S PROPERTIES
    COMPILE_DEFINITIONS "IDLE_ELF_PATH=\"${IDLE_ELF_FILE}\""
)

# fsh_embed.S embeds the interactive shell.
set(FSH_ELF_FILE "${CMAKE_CURRENT_LIST_DIR}/../test-elf/fsh.elf")
set_source_files_properties(src/fsh_embed.S PROPERTIES
    COMPILE_DEFINITIONS "FSH_ELF_PATH=\"${FSH_ELF_FILE}\""
)

# rootfs_embed.S embeds the RAM-FS seed archive (newc cpio) built from
# ramfs-src/ by tools/mkcpio.py; regenerated on any source file change.
set(RAMFS_SRC_DIR "${CMAKE_CURRENT_LIST_DIR}/../ramfs-src")
set(RAMFS_CPIO "${CMAKE_CURRENT_BINARY_DIR}/ramfs.cpio")
file(GLOB_RECURSE RAMFS_DEPS CONFIGURE_DEPENDS "${RAMFS_SRC_DIR}/*")
add_custom_command(
    OUTPUT "${RAMFS_CPIO}"
    COMMAND python3 "${CMAKE_CURRENT_LIST_DIR}/../tools/mkcpio.py" "${RAMFS_SRC_DIR}" "${RAMFS_CPIO}"
    DEPENDS ${RAMFS_DEPS} "${CMAKE_CURRENT_LIST_DIR}/../tools/mkcpio.py"
    COMMENT "Building ramfs.cpio"
    VERBATIM
)
add_custom_target(ramfs_cpio DEPENDS "${RAMFS_CPIO}")
add_dependencies(ferrix_init ramfs_cpio)
set_source_files_properties(src/rootfs_embed.S PROPERTIES
    COMPILE_DEFINITIONS "CPIO_PATH=\"${RAMFS_CPIO}\""
    OBJECT_DEPENDS "${RAMFS_CPIO}"
)

# busybox_embed.S embeds the static busybox (applets + ash shell).
set(BUSYBOX_ELF_FILE "/home/enexis/felixos/tools/busybox-1.36.1-ferrix/busybox")
set_source_files_properties(src/busybox_embed.S PROPERTIES
    COMPILE_DEFINITIONS "BUSYBOX_ELF_PATH=\"${BUSYBOX_ELF_FILE}\""
)

target_include_directories(ferrix_init PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

target_link_libraries(ferrix_init
    PRIVATE
        burmalda      # POSIX personality (links sel4 transitively)
        sel4runtime   # root-task entry point + seL4_GetBootInfo
        muslc         # libc
        sel4_autoconf
        sel4_Config
        kernel_Config
)

# Install / image target is handled by the top-level seL4 project CMake.

