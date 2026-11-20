# ferrix-init

The Ferrix root task — first userspace process on the Ferrix microkernel.

## Role

```
seL4 kernel boots
  └─ ferrix-init (root task / seL4 "PID 0")
       ├─ allocates fault endpoint
       ├─ starts burmalda POSIX personality loop
       │    └─ handles UnknownSyscall faults from all POSIX threads
       └─ [M3] loads dinit as first ELF process → PID 1 in POSIX space
              └─ dinit manages services, FreeBSD userland, etc.
```

## Milestones

| Milestone | ferrix-init does |
|-----------|-----------------|
| **K2 (now)** | Allocates EP, calls `burmalda_run()`. No POSIX processes yet. |
| **M2** | Serial driver stub in burmalda; `write` works end-to-end |
| **M3** | ELF loader: maps dinit into a new VSpace, starts it as POSIX thread |
| **M4** | dinit manages service start order; `fork`/`exec` stubs in burmalda |
| **M5** | rump kernel for real FS/net; dinit services fully functional |

## Building

ferrix-init is built as part of the Ferrix project. It depends on
`burmalda` (sibling directory) and the standard seL4 cmake scaffolding.

**Project layout expected:**

```
felixOS/
  seL4/          ← Ferrix kernel fork
  seL4_tools/    ← cmake-tool, elfloader-tool
  sel4runtime/
  musllibc/
  burmalda/      ← POSIX personality library
  ferrix-init/   ← this repo (root task)
  dinit/         ← future PID 1 (M3+)
```

**Top-level CMakeLists.txt** must include:
```cmake
add_subdirectory(burmalda)
add_subdirectory(ferrix-init)
```

**Configure (Linux/WSL, non-MCS):**
```sh
mkdir build && cd build
cmake -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE=../seL4_tools/gcc-11.cmake \
  -DKernelPlatform=pc99 \
  -DKernelSel4Arch=x86_64 \
  -DKernelIsMCS=OFF \
  -DKernelRootCNodeSizeBits=12 \
  ..
ninja && ./simulate
```

## Expected boot output

```
ferrix-init: starting (Ferrix microkernel, x86_64)
ferrix-init: fault endpoint at slot <N>
ferrix-init: handing off to burmalda POSIX personality
burmalda: dispatch loop running
```

## dinit integration plan (M3)

dinit requires these syscalls from burmalda before it can start:
- `open`, `read`, `write`, `close` — service config files
- `fork`, `execve` — launching services  
- `waitid` / `waitpid` — reaping children
- `kqueue` (FreeBSD) or `epoll` (Linux) — event loop
- `socket`, `bind`, `accept` — `dinitctl` control socket

These are implemented progressively in burmalda across M2–M5.
dinit itself needs **no seL4-specific changes** — it only sees a
standard POSIX/FreeBSD interface delivered by burmalda.

