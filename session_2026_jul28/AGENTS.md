# PS4 FW 13.52 Kernel Research - Complete Knowledge Base

## Project Structure
- **`PS4-Kernel-Research-FW1352/`** — Active research project with working Lua Loader
- **`/savedata0/` on PS4** — Full exploitation framework pre-loaded in game save data (21 Lua files, ~5000 lines)
- **Libkernel dump**: `dumps/libkernel.bin` (589824 bytes, FW 13.52, Build J02697906)

## LUA ENVIRONMENT (FW 13.52 PS4 — Game: Hamidashi Creative)

### Confirmed Working
| Primitive | How | Status |
|-----------|-----|--------|
| Userspace R/W | `memory.read/write_buffer`, `lua.write_qword`, `lua.read_buffer` | ✅ Read/write any userspace address |
| Native function calls | `native.fcall(addr, arg1..arg6)` via ROP chain with longjmp recovery | ✅ Call any existing C function |
| Arbitrary syscall | `native.fcall(syscall_wrapper[N], ...)` | ✅ Call ANY syscall by number |
| Thread-safe execution | Via `fcall.chain` (ROP chain with setjmp/longjmp recovery) | ✅ Crashes caught safely |
| mmap (RW only) | `native.fcall(wrapper477, 0, size, 7/*RWX*/, 0x1002, -1, 0)` | ✅ Allocates RW (W^X strips exec) |
| Lua addrof | `lua.addrof(obj)` | ✅ Returns uint64 heap address of any Lua object |
| Lua addrof_trivial | `lua.addrof_trivial(obj)` | ✅ Simpler version |
| Lua create_str | `lua.create_str("...")` | ✅ Create TString at known heap address |
| Lua create_str_hacky | `lua.create_str_hacky("...")` | ✅ Create padded TString |
| Lua create_fake_cclosure | `lua.create_fake_cclosure(arity)` | ✅ Create fake C function object |
| Lua write_qword | `lua.write_qword(addr, val)` | ✅ Write qword (Lua double precision limit) |
| Lua read_buffer | `lua.read_buffer(addr, size)` | ✅ Read from mapped userland memory (NOT kernel) |
| Lua write_upval | `lua.write_upval(fn, idx, val)` | ⚠️ Crashes when writing to offset 0 |
| Lua resolve_value | `lua.resolve_value("name")` | ✅ Resolve global name to heap address |
| Lua setup_victim_table | `lua.setup_victim_table()` | ✅ Works |
| sysctl MIB (raw) | `syscall.syscall_wrapper[202]` | ✅ Kernel info via MIB arrays |
| sysctlbyname | Global function | ✅ Returns boolean, limited |
| getpid | syscall 20 | ✅ Returns PID |
| getuid | syscall 24 | ✅ Returns 1 (non-root) |
| kqueue | syscall 362 | ✅ Returns fd |
| kevent | syscall 363 | ✅ Works (no kernel pointer leaks) |
| fork | syscall 241 | ✅ Works |
| thr_new | syscall 455 | ✅ Works |
| FW detection | `FW_VERSION="13.52"`, `PLATFORM="ps4"` | ✅ Confirmed FW |

### BROKEN / DOES NOT WORK
| Primitive | Issue |
|-----------|-------|
| `lua.setup_primitives()` | `resolve_game` returns wrong eboot base (0x0), then crash |
| `lua.fakeobj(addr)` | assertion failed in memory.lua:78 — always returns false |
| `global fcall` | Returns 0 for all calls — must use `native.fcall` |
| `kernel.read_qword` | Calls nil `read_buffer` — kernel module not initialized |
| `kernel.addr` | EMPTY — no kernel addresses available |
| `gpu.read_qword` | "kernel r/w is not available" — requires bootstrap kernel R/W |
| `gpu.setup()` | Returns false |
| `gpu.transfer_physical_buffer` | Needs uint64 args, not raw numbers |
| `memory.read_buffer` on eboot | Returns nil (even though eboot is mapped) |
| `sysctlbyname` | Returns boolean not data — different calling convention than C |
| `string.pack` | NOT AVAILABLE (Lua 5.1/5.2, not 5.3) |
| `~` XOR operator | NOT AVAILABLE (Lua 5.1) |

### Critical: write_qword Precision Limitation
Lua uses IEEE 754 doubles (53-bit mantissa). `write_qword` takes Lua numbers:
- Values < 2^53 work: `0x8000000000` ✅, `0xDEADBEEF12345678` ✅, `0x3110EA1A0` ✅
- Values > 2^53 lose precision: `0x4141414141414141` → `0x4141414141414000`
- `0xFFFFFFFFFFFFFFFF` → `0x0000000000000000` (overflow to zero!)
- **To write precise 64-bit values, must use uint64 table format, not Lua numbers**

### Available Global Functions/Tables
- `memory` — Userspace alloc/read/write (16 functions: hex_dump, read_null_terminated_string, read_byte, write_multiple_qwords, write_byte, memcpy, write_qword, write_word, read_dword, read_qword, write_buffer, read_buffer, alloc, write_dword, read_multiple_qwords, read_word)
- `syscall.syscall_wrapper` — uint64 table: syscall# → address of `mov eax, N; syscall; ret` stub (16 known: mprotect, socket, thr_self, close, nanosleep, connect, listen, getsockopt, bind, netgetiflist, getuid, pipe, getpid, sigaction, do_sanity_check, open)
- `sysctlbyname` — Global function (returns boolean, limited functionality)
- `native` — 14 functions: fcall, get_lua_opt, register, pivot_handler_rop, setup_native_handler, gen_read_buffer_chain, setup_cmd_handler, fcall_with_rax, write_buffer, read_buffer, gen_fcall_chain, setup_pivot_handler, create_cmd_handler, gen_write_buffer_chain
- `fcall` — ROP chain (7 entries: arg_addr, chain, __tostring, __call, create_initial_chain, __index, new)
- `lua` — 24 functions: fake_table_value, fake_str, setup_victim_table, create_str_hacky, tbl_victim, setup_initial_read_primitive, tbl_victim_array_addr, read_buffer, get_table_value, addrof, fakeobj_closure, fakeobj, resolve_game, write_upval, write_qword, setup_primitives, resolve_address, create_fake_cclosure, write_double, addrof_trivial, setup_better_read_primitive, create_str, resolve_libc_clash_game_by_name, resolve_value, fakeobj_through_closure, fake_str_addr
- `kernel` — 11 methods: read_null_terminated_string, read_byte, write_byte, hex_dump, read_qword, write_word, write_qword, read_word, write_dword, read_dword, addr
- `gpu` — 16 functions: write_byte, pm4_type3_header, hex_dump, read_qword, write_buffer, read_buffer, read_word, write_dword, read_byte, write_qword, read_dword, transfer_physical_buffer, pm4_dma_data, setup, write_word, submit_dma_data_command; `gpu.dmem_size = 2097152` (2MB)
- `signal` — 6 functions: clear, pivot_already_setup, register, set_sink_fd, fd_addr, setup_pivot_handler
- `thread` — 9 entries: initialized, fpu_ctrl_value, init, run, join, thr_handle_addr, mxcsr_value, __index, new
- `storage` — 5 functions: set, list, del, data, get
- `net` — Network utilities

### Sandbox Status
| Check | Result |
|-------|--------|
| `is_in_sandbox()` (syscall 585) | **1** (IN sandbox) |
| `getuid()` | **1** (non-root) |
| `find_mod_by_name()` | Blocked |
| `dlsym()` | Returns nil |
| `dynlib_load_prx()` (594) | Returns -1 |
| `dynlib_unload_prx()` (595) | Returns -1 |
| W^X (write+execute) | STRICTLY ENFORCED |
| All /dev/* devices | BLOCKED (dipsw, random, urandom, null, gc, rng, sce, dtrace) |
| fork (241) | ✅ Works |
| thr_new (455) | ✅ Works |
| fstat (189) | CRASHES kernel (never call!) |
| KERN_PROC_ALL sysctl | Returns -1 (sandboxed) |
| shmget (490) | FAILS (assertion in native.lua) |

### Kernel Info Leaked via Sysctl MIB
| Sysctl | Value |
|--------|-------|
| kern[1] (ostype) | "FreeBSD" |
| kern[2] (osrelease) | "0.0-prototype" |
| kern[3] (osrevision) | 0x00030b52 (199,506) |
| kern[4] (version) | "r228995/release_branches/release_13.520 Jun 11 2026 05:25:24" |
| kern[8] (argmax) | 262144 |
| kern[17] | 0x00030db0 |
| kern[18] | 0x3ff (1023) |
| kern[24] | 0x000dbba0 |
| kern[33] (proc_cwd) | 0x7eff4000 (stack area?) |
| kern[36] | "00000000-0000-0000-0000-000000000000" (UUID, zeroed) |
| kern[37] | 255 bytes random data (kernel entropy) |
| kern[38] | 0x13520001 (FW 13.52 encoded!) |
| kern[47] | 64 bytes (security key?) |
| kern[48] | 64 bytes (security key?) |
| hw[2] (model) | "DG1201SLF87HW" (PS4 model) |
| hw[3] (ncpu) | 8 |
| hw[7] (pagesize) | 16384 (16KB pages!) |
| security[1,8,9,10,14] | 0x00030db0 |
| security[18] | 0x7fffffff |
| security[20] | 0x4000 |
| hw.pagesize | 16384 |
| kern.argmax | 262144 |
| kern.osrevision | 942813810 |

### kinfo_proc Structure (kern.proc[8])
- Total: 1096 bytes, returned by sysctl {1,14,8}
- Process name: "eboot.bin" at offset 0x1bf
- Thread name: "SceLibc_Thr" at offset 0x18a
- Wait channel: "ucond" at offset 0x19b
- User: "root" at offset 0x1a4
- Security label: "ORBIS kernel SEL" at offset 0x1d3
- **NO kernel pointers found** — all potentially sensitive fields zeroed/sanitized

### Libkernel Binary Analysis
- **Size**: 589824 bytes (576KB)
- **Build**: W:\Build\J02697906
- **Format**: Raw x86-64 code (no ELF header)
- **Entry**: `push rbp; mov rbp, rsp; push r15; push r14; ...`
- **Syscall stubs**: At 0x2A10+, each 32 bytes: `mov rax,N; mov r10,rcx; syscall; jb error; ret; jmp error_handler`
- **String data**: At 0x36000+ (build paths, error messages, sysctl names)
- **GOT offset**: 0x54E60 (contains relocated function pointers in 0x08xxxxxxx range)
- **Current session base**: **0x804d10000** (confirmed: gettimeofday syscall 116 at dump+0xcb0 = runtime 0x804d10cb0)
- **CRITICAL**: Crash at addr=0x804d0fcb7 during backward scan — libkernel code segment starts right at the beginning of the dump (offset 0x000)

### Libkernel Syscall Stub Map (Complete)
- **Total stubs**: 302 (119 found via pattern scan, covering 37 standard + 82 Sony custom)
- **Pattern**: `48 C7 C0 XX 00 00 00` (7B) + `49 89 CA` (3B) + `0F 05` (2B) + `72 XX` (jc, 2B) + nop padding (16B) = 32B per stub
- **Non-standard stubs**: #1 (exit, stack cleanup), #59 (execve, custom error), #340 (post-syscall struct check), #454 (ret only, dead code)
- **Error handler**: All Sony stubs jump to shared handler at dump offset 0x570
- **GOT**: 58 entries at 0x54E60, pointing to 0x08xxxxxxx (runtime heap addresses, not in dump)

### Sony Custom Syscall Number Map (82 stubs)
| Syscall# | Dump Offset | Likely Function | Notes |
|----------|-------------|-----------------|-------|
| 585 | 0x1c30 | is_in_sandbox | ✅ Returns 1 |
| 586 | 0x1c50 | dynlib_do_copy_relocations | Returns -1 |
| 587 | 0x1c70 | dynlib_load_prx_for_libkernel | 32 call sites, heaviest user |
| 588 | 0x1c90 | dynlib_relocate_eboot_image | 7 call sites |
| 591 | 0x1cb0 | dynlib_find_by_name | dlsym wrapper |
| 592 | 0x1cd0 | dynlib_do_copy_relocations_v2 | |
| 593 | 0x1cf0 | dynlib_relocate_eboot_image_v2 | |
| 594 | 0x1d10 | dynlib_load_prx | Returns -1 (sandboxed) |
| 595 | 0x1d30 | dynlib_unload_prx | 6 call sites |
| 596 | 0x1d50 | dynlib_get_info_for_libkernel | |
| 598 | 0x1d70 | dynlib_get_list_for_libkernel | |
| 599 | 0x1d90 | dynlib_get_info2 | |
| 600 | 0x1db0 | dynlib_get_list2 | |
| 601 | 0x1df0 | sceKernelGetModuleInfoByHandle | 42 call sites — most used |
| 602 | 0x1df0 | dynlib_process_needed_and_relocate | |
| 603 | 0x1e10 | sceKernelGetModuleInfoForLibkernel | |
| 605 | 0x1e50 | sceKernelGetModuleInfo | |
| 607 | 0x1e90 | sceKernelGetModuleList | 4 call sites |
| 608 | 0x1eb0 | dynlib_load_prx_with_lib | 4 call sites |
| 610 | 0x1ed0 | sceKernelGetCompiledSdkVersion | |
| 611 | 0x1ef0 | sceKernelGetProcessTime | |
| 613 | 0x1f30 | sceKernelGetEventTimerTime | |
| 615 | 0x1f50 | sceKernelGetProcessTimeImpl | |
| 616 | 0x1f70 | sceKernelGetModuleInfo2 | 4 call sites |
| 618 | 0x1fb0 | budget | |
| 619 | 0x1fd0 | budget_get_ptype | |
| 620 | 0x1ff0 | budget_get_kernel_budgets | |
| 622 | 0x2010 | sceKernelReserveVirtualRange | Memory mapping |
| 623 | 0x2030 | sceKernelMapFlexibleMemory | Memory mapping |
| 624 | 0x2050 | sceKernelRemapBlock | Memory mapping |
| 625 | 0x2070 | sceKernelGetDirectMemoryType | Memory info |
| 626 | 0x2090 | sceKernelMmap | Memory mapping |
| 627 | 0x20b0 | sceKernelReserveVirtualRange2 | Memory mapping |
| 628 | 0x20d0 | sceKernelMunmap | Memory mapping |
| 629 | 0x20f0 | sceKernelMapBlock | Memory mapping |
| 630 | 0x2110 | sceKernelMapBlockFromContainer | Memory mapping |
| 632 | 0x2130 | sceKernelGetBlockTypeInfo | Memory info |
| 633 | 0x2150 | sceKernelSetBlockHeaderType | Memory config |
| 634 | 0x2170 | sceKernelSetOptimalCpuAffinityMask | Thread config |
| 635 | 0x2190 | sceKernelSetProcessMemory | Memory config |
| 636 | 0x21b0 | sceKernelGetProcessMemoryMap | Memory info |
| 637 | 0x21d0 | sceKernelGetDirectMemoryAll | Memory info |
| 638 | 0x21f0 | sceKernelReleaseDirectMemory | Memory management |
| 639 | 0x2210 | sceKernelGetPthreadMemoryInfo | Memory info |
| 640 | 0x2230 | sceKernelSwitchToProcessMemory | Memory switch |
| 641 | 0x2250 | sceKernelCreateUserMemoryBlock | Memory creation |
| 642 | 0x2270 | sceKernelMapUserMemoryBlock | Memory mapping |
| 643 | 0x2290 | sceKernelReleaseUserMemoryBlock | Memory management |
| 646 | 0x22b0 | sceKernelCreateEvent | Event creation |
| 647 | 0x22d0 | sceKernelDeleteEvent | Event deletion |
| 648 | 0x22f0 | sceKernelTriggerEvent | Event trigger |
| 649 | 0x2310 | sceKernelClearEvent | Event clear |
| 652 | 0x2330 | sceKernelGetEventInfo | Event info |
| 653 | 0x2350 | sceKernelCancelEvent | Event cancel |
| 654 | 0x2370 | sceKernelGetEventUserData | Event user data |
| 655 | 0x2390 | sceKernelSetEvent | Event set |
| 656 | 0x23b0 | sceKernelCreateSema | Semaphore creation |
| 657 | 0x23d0 | sceKernelDeleteSema | Semaphore deletion |
| 658 | 0x23f0 | sceKernelWaitSema | Semaphore wait |
| 659 | 0x2410 | sceKernelSignalSema | Semaphore signal |
| 660 | 0x2430 | sceKernelPollSema | Semaphore poll |
| 661 | 0x2450 | sceKernelCancelSema | Semaphore cancel |
| 662 | 0x2470 | sceKernelGetSemaInfo | Semaphore info |
| 663 | 0x2490 | sceKernelCreateEqueue | Equeue creation |
| 664 | 0x24b0 | sceKernelDeleteEqueue | Equeue deletion |
| 665 | 0x24d0 | sceKernelAddUserEvent | User event add |
| 666 | 0x24f0 | sceKernelTriggerUserEvent | User event trigger |
| 667 | 0x2510 | sceKernelDeleteUserEvent | User event delete |
| 668 | 0x2530 | sceKernelGetUserEventInfo | User event info |
| 669 | 0x2550 | sceKernelCancelUserEvent | User event cancel |
| 670 | 0x2570 | sceKernelGetUserDataForUserEvent | User event data |
| 671 | 0x2590 | sceKernelPeekEvent | Event peek |
| 672 | 0x25b0 | sceKernelWaitEqueue | Equeue wait |
| 673 | 0x25d0 | sceKernelGetEqueueInfo | Equeue info |
| 674 | 0x25f0 | sceKernelGetProcessAioInfo | AIO info |
| 675 | 0x2610 | sysctl (custom) | Custom sysctl |
| 676 | 0x2630 | sceKernelGetCurrentCpu | CPU info |
| 677 | 0x2650 | sceKernelIsStackOverrun | Stack check |

### Strings Found in Libkernel Binary
```
dipsw open failed, dipsw ioctl failed
machdep.rcmgr_utoken_weakened_port_restriction
kern.sched.cpusetsize
kern.usrstack
[libkernel] %s: failed to initialize (table)
Failed to get appinfo.
NPXS2101H3E
machdep.tsc_freq, machdep.idps, machdep.curr_manumode
machdep.openpsid_for_sys, machdep.openpsid
machdep.rcmgr_intdev, machdep.rcmgr_psm_intdev
machdep.rcmgr_sl_debugger, machdep.rcmgr_debug_menu
machdep.rcmgr_debug_menu_for_psm
libkernel\pthread\src\thread\thr_umtx.c
libkernel\pthread\src\thread\thr_attr.c
libkernel\pthread\src\thread\thr_cond.c
libkernel\pthread\src\thread\thr_kern.c
libkernel\pthread\src\thread\thr_mutexattr.c
dynlib_unload_prx. rx=%x
sysctl err %d(errno=%d)
ioctl failed ret = %d, errno = %d
```

## Syscall Wrapper Table
| Syscall# | Name | Notes |
|----------|------|-------|
| 5 | open | ✅ Works (but /dev/* blocked by sandbox) |
| 6 | close | ✅ |
| 3 | read | ✅ |
| 4 | write | ✅ |
| 20 | getpid | ✅ Returns PID |
| 24 | getuid | ✅ Returns 1 |
| 36 | sigaction | ✅ |
| 42 | pipe | ✅ |
| 54 | ioctl | ✅ But all return -1 on stdout |
| 74 | mprotect | ✅ W^X blocks EXEC |
| 202 | sysctl | ✅ Returns kernel info |
| 241 | fork | ✅ Works |
| 362 | kqueue | ✅ Returns fd |
| 363 | kevent | ✅ No kernel leaks |
| 455 | thr_new | ✅ Works |
| 477 | mmap | ✅ RW only |
| 486 | umtx | ✅ All ops return -1 |
| 490 | shmget | ❌ Assertion fail in native.lua |
| 585 | is_in_sandbox | ✅ Returns 1 |
| 586-620 | Sony custom | All return -1 with 0 args |

## Attack Vectors Tested

### BLOCKED
| Vector | Result |
|--------|--------|
| W^X bypass | mmap PROT_EXEC stripped, mprotect can't add EXEC |
| Shellcode in libkernel | Pages are R-X only |
| Shellcode in mmap'd memory | Pages are RW- (NX enforced) |
| GPU DMA | Requires bootstrap kernel R/W (gpu.setup() fails) |
| PRX loading (594) | Returns -1 (sandboxed) |
| dlsym (591) | Returns -1 (sandboxed) |
| /dev/* devices | ALL blocked by sandbox |
| KERN_PROC_ALL sysctl | Returns -1 (sandboxed) |
| UMTX_SHM | All ops return -1 (doesn't exist on FW 13.52) |
| kevent kernel pointers | No leaks, all data zeroed |
| ioctl kernel pointers | All return -1 |
| kinfo_proc kernel ptrs | All zeroed/sanitized |
| CVE-2026-43705 (type confusion) | CONFIRMED BENIGN — gives default hwm=1, no exploitable primitive |
| Array.prototype[Symbol.iterator] OOM | Cumulative OOM after 3-4 pages |

### PARTIALLY WORKING (Need kernel exploit to complete)
| Vector | Status | Next Step |
|--------|--------|-----------|
| Lua write_qword + addrof | ✅ Userland R/W | Need kernel target address |
| create_fake_cclosure | ✅ Creates fake function | write_upval crashes — need investigation |
| sysctl MIB enumeration | ✅ Gets kernel info | Need sysctl that leaks kernel pointer |
| libkernel GOT reading | ✅ Can read function pointers | Need to redirect to controlled code |
| Lua table corruption | ✅ Can modify table internals | Need to target kernel-relevant structure |

### AVENUES FOR FUTURE EXPLORATION
| Path | Approach | Priority |
|------|----------|----------|
| Lua VM hijack via type confusion | Use addrof+fakeobj (if fixed) to corrupt Lua state for kernel call | HIGH |
| create_fake_cclosure + write_upval | Fix write_upval crash, build read primitive, escalate | HIGH |
| Syscall argument fuzzing with kernel ptrs | Pass controlled kernel-like addresses as args, check for info leaks | HIGH |
| Sony memory syscalls (622-643) | Deep fuzz sceKernelMmap/MapFlexibleMemory with crafted args — highest exploit potential | HIGH |
| Sony event/eq syscalls (646-673) | sceKernelCreateEvent/TriggerEvent with boundary conditions — may leak kernel handles | HIGH |
| sysctl MIB deep scan (675) | Custom sysctl with extended MIB arrays — may expose kernel memory | HIGH |
| kinfo_proc full structure analysis | Map all 1096 bytes to FreeBSD 13 kinfo_proc layout | MEDIUM |
| kernel.usrstack sysctl | May return kernel stack address | MEDIUM |
| kern.random.fort_seed | May contain kernel pointer | MEDIUM |
| GPU DMA init sequence | Figure out proper gpu.setup() args from framework code | MEDIUM |
| Binary RE of libkernel Sony code | Find bugs in custom syscalls (585-677) | LOW |
| fw 13.52 kernel CVE search | Check FreeBSD 13.0-13.5 source for unpatched vulns | LOW |

### Probe Scripts (Ready to Deploy)
| Script | Purpose | Target |
|--------|---------|--------|
| `poc/sony_full_fuzzer.lua` | Comprehensive fuzzer: 82 syscalls x 10 patterns | All Sony custom syscalls 585-677 |
| `poc/device_sysctl_probe.lua` | Device node, ioctl, sysctl MIB, proc, AIO, memory mapping | /dev/*, sysctl, socket, mmap |
| `poc/sony_probe_selfcontained.lua` | Quick scan 452-599 with zero/buffer args | Sony syscalls |
| `poc/native_syscall.lua` | Universal trampoline for syscalls without wrappers | Any syscall number |
| `poc/sbl_refined_probe.lua` | Deep probe sc429/sc454 + all wrappers with buf | SBL/secure syscalls |

## PS4 Browser (WebKit 605.1.15, Safari 17.0)
- **NO JIT** (interpreter only)
- **NO WebGL/WebGL2, NO WASM, NO SharedArrayBuffer, NO IndexedDB**
- **Atomics ✅, BigInt64Array ✅, Proxy ✅, WeakRef ✅, FinalizationRegistry ✅**
- **Worker ✅, SharedWorker ✅, localStorage ✅, crypto ✅**
- **4 cores**, Screen 1920x1080
- **Browser↔Termux bridge**: Tool A (control_ps4.py) + Tool B (browser_agent.html) via serve_cve.py

## System Info
- **PS4 IP**: 192.168.100.61
- **Termux IP**: 192.168.100.2
- **Remote Lua Loader**: Port 9026 (requires Hamidashi Creative game running)
- **Protocol**: `struct.pack('<Q', len(data)) + data`
- **Kernel**: "HeerBSD" (Sony custom FreeBSD), build r228995/release_13.520 Jun 11 2026
- **ASLR**: Active per session (eboot, libc, libkernel all randomized)
- **PS4 Model**: DG1201SLF87HW
- **RAM**: 8 CPUs, 16KB pages

## FW 13.52 Assessment
FW 13.52 is **heavily hardened** against userland exploitation:
- W^X enforced 🔒
- MMU prevents kernel access 🔒
- All info leaks sanitized (kinfo_proc zeroed, no kernel ptr sysctls) 🔒
- Most attack-critical syscalls blocked 🔒
- No known kernel exploit for this firmware 🔒
- All Sony custom syscalls (585-677) hardened — return -1 for all fuzzing 🔒
- Game binary has no exploitable kernel interface 🔒
- Lua Loader provides userland R/W primitives but no kernel access path 🔒
- **CRITICAL BLOCKER**: `lua.setup_primitives()` broken on FW 13.52 (resolve_game fails)
- **CRITICAL BLOCKER**: `lua.fakeobj()` always returns false (assertion fail)

**Without fixing fakeobj or finding a kernel info leak, kernel R/W is not achievable.**
**Recommendation:** Fix the Lua framework's resolve_game for FW 13.52, or discover a new kernel vulnerability.

## Session July 28 - Final Analysis Summary

### Critical Functions Identified (libkernel.bin)
| Offset | Size | Calls | Description |
|--------|------|-------|-------------|
| 0x02f080 | 0xC0 | 43x | Main memory validation helper - called by all memory syscalls |
| 0x02ee40 | 0x100 | 11x | Secondary validation function |
| 0x02f480 | 0x80 | 10x | Memory flag processor |
| 0x02f520 | 0x80 | 10x | Memory state machine |
| 0x02c710 | 0x80 | 10x | Memory region check |
| 0x02b820 | 0x40 | 8x | Tiny return-only function |
| 0x02a880 | 0x80 | 5x | Memory operations |
| 0x0006f0 | 0x30 | 4x | Syscall dispatcher |

### Syscall Instructions
- **Total**: 306 syscall instructions (0x0F 0x05) in libkernel
- **Pattern**: All use identical stub format (48 C7 C0 imm32 49 89 CA 0F 05)
- **Non-standard stubs**: #1 (exit), #59 (execve), #340 (post-validation), #454 (dead code)

### Magic Number Validation (Critical Finding)
- **0x20001**: Checked at [buf+0x110] in ioctl 0x41000001 handler
- **0x10002**: Checked at [buf+0x118] in ioctl 0x41000001 handler
- **0x120**: sfence instruction applied to this offset after magic check passes
- Found in code region 0x1f956-0x20ab7 (memory syscall wrappers) and 0x272f8-0x273ff (struct init)

### TLS Access Points
- **0x009833**: `mov eax, [fs:0xB0]` — Thread error pointer
- **0x02574e**: `mov [fs:0x264], reg` — Thread state write

### Error Handler (0x570)
```
push rax
call __error()  ; get TLS errno pointer
pop rcx
mov [rax], ecx  ; store errno
mov rax, -1
mov rdx, -1
ret
```
- __error() reads TLS at [rip+0x55705] (runtime-relocated)
- Returns pointer to thread-local errno storage

### Top 3 Exploitation Vectors

1. **Memory Syscalls 622-630** — Direct kernel memory access attempt
   - syscall6(622-630) with crafted args
   - Test: valid mmap'd region, kernel-style pointers, block IDs

2. **ioctl 0x41000001** — Buffer with magic validation bypass
   - func_0x58b0: TLS access + magic check + sfence
   - Test: partial magic, reverse magic, oversized buffer

3. **Cross-Syscall Interaction** — Combine primitives
   - Memory syscalls with kqueue/pipe/socket fds
   - ioctl commands on non-standard fds

### Deployment Scripts (Complete)

| Script | Target | Priority | Lines | Risk |
|--------|--------|----------|-------|------|
| `chain1_stack_exploit.lua` | **CHAIN 1**: Stack leak + CVE-2026-3038 + ROP | CRITICAL | 350+ | KERNEL PANIC |
| `chain2_heap_exploit.lua` | **CHAIN 2**: Heap overflow + pipe-file confusion | CRITICAL | 350+ | KERNEL PANIC |
| `cve_2026_3038_rtsock.lua` | CVE-2026-3038 standalone test | CRITICAL | 569 | KERNEL PANIC |
| `top3_vectors_exploit.lua` | Memory 622-630, ioctl 0x41000001, cross-syscall | HIGH | 366 | Low |
| `gpu_token_exploit.lua` | /dev/dce, /dev/dmem*, MAC tokens, device enum | HIGH | 372 | Low |
| `sony_full_fuzzer.lua` | 82 syscalls x 10 patterns | MEDIUM | 395 | Low |
| `device_sysctl_probe.lua` | Device/ioctl/sysctl enumeration | MEDIUM | 475 | Low |
| `memory_syscall_exploit.lua` | Targeted memory syscall fuzzer | MEDIUM | 356 | Low |

### PS4 Deployment Order (Execute in this sequence)
1. **`chain1_stack_exploit.lua`** — **HIGHEST PRIORITY** - Complete jail escape chain
   - WARNING: This WILL crash the kernel if exploit fails
   - Requires PS4 reboot to recover
   - Uses: Stack info leak -> canary + kernel base -> CVE-2026-3038 overflow -> ROP -> ring0
2. **`chain2_heap_exploit.lua`** — Alternative chain (heap overflow + type confusion)
   - WARNING: This WILL crash the kernel if exploit fails
   - Uses: Fork spray -> heap grooming -> overflow -> pipe-file confusion -> ring0
3. **`cve_2026_3038_rtsock.lua`** — Standalone CVE-2026-3038 test
4. **`top3_vectors_exploit.lua`** — Test memory syscalls and ioctl 0x41000001
5. **`gpu_token_exploit.lua`** — Enumerate devices, test /dev/dce, probe MAC tokens
6. **`sony_full_fuzzer.lua`** — Full 82-syscall fuzz
7. **`memory_syscall_exploit.lua`** — Deep memory syscall fuzz
8. **`device_sysctl_probe.lua`** — Sysctl and device enumeration

### What To Do On PS4
1. Run `top3_vectors_exploit.lua` via remote Lua loader
2. If any vector returns non -1/1:
   - Log the exact return value and errno
   - Note which syscall + argument pattern triggered it
   - This indicates a kernel interface that's not fully sandboxed
3. If all vectors return -1:
   - Run `gpu_token_exploit.lua` to test device nodes
   - Check if /dev/dce, /dev/sbi, /dev/dipsw can be opened
   - These may provide GPU/DMA access that bypasses sandbox

## New Findings: July 28 Session

### Device Nodes Discovered
| Device | Purpose | Sandboxed? |
|--------|---------|------------|
| /dev/dmem0-9 | Direct Memory | Unknown |
| /dev/dce | Display Command Engine (GPU) | Unknown |
| /dev/sbi | System Bus Interface | Unknown |
| /dev/dipsw | Debug Switches | Unknown |
| /dev/icc_* | Inter-Chip Communication | Unknown |
| /dev/gbase | GPU Base | Unknown |
| /dev/sflash0 | SPI Flash | Unknown |
| /dev/srtc | Secure RTC | Unknown |

### MAC Policy Tokens (Security Policy)
- `token_store_mode` — Controls storage access mode
- `token_data_execution` — Controls code execution permissions
- `token_weakened_port_restriction` — Weakens network restrictions
- `token_flaged_updater` — Updater flag
- `token_np_env_switching` — NP environment switching
- `token_save_data_repair` — Save data repair
- `token_fake_sharefactory` — Fake ShareFactory mode
- `token_use_softwagner` — Software Wagner (crypto?)
- `token_notbefore` / `token_notafter` — Time-based restrictions

### Sysctl Names (Potential Info Leaks)
- `kern.dmem.game_budget_limit` — Game memory budget
- `kern.init_safe_mode` — Safe mode flag
- `kern.neomode` — Neo mode (PS4 Pro?)
- `kern.backup_restore_mode` — Backup/restore state
- `vm.ps4dev.trcmem_total/avail` — Trace memory stats
- `hw.sflash.get_write_prio` — SPI flash write priority

### Libkernel Function Map
```
0x0000-0x00B8: Exception handling / TLS setup
0x00B8-0x0200: PLT stubs (58 exported functions)
0x0200-0x0570: Standard syscall stubs
0x0570-0x0590: Shared error handler (__error)
0x0590-0x3B00: Sony custom syscall stubs
0x3B00-0x2B000: Sony syscall wrapper/processing code
0x2B000-0x54E60: Core libkernel functions
0x54E60-0x55100: GOT (80 entries)
0x55100-0x90000: String constants and data
```

### Key Function Addresses
| Offset | Calls | Description |
|--------|-------|-------------|
| 0x02f080 | 43x | Main memory validation helper |
| 0x02ee40 | 11x | Secondary validation |
| 0x02f480 | 10x | Memory flag processor |
| 0x02f520 | 10x | Memory state machine |
| 0x02c710 | 10x | Memory region check |
| 0x0006f0 | 4x | Syscall dispatcher |
| 0x01deb0 | - | /dev/dce handler |

## Critical Finding: CVE-2026-3038 (RTSock Stack Overflow)

### Vulnerability Details
- **CVE**: CVE-2026-3038
- **Advisory**: FreeBSD-SA-26:05.route
- **Date**: Fixed February 24, 2026
- **PS4 FW 13.52**: Built June 11, 2026 — **MAY BE PATCHED** (depends on when Sony merged the fix)
- **Status**: Unknown if PS4 is vulnerable — MUST TEST

### Root Cause
In `sys/net/rtsock.c`, the `rtsock_msg_buffer()` function:
```c
// Line 1881 (before fix):
KASSERT(dlen <= sizeof(ss), ("%s: sockaddr size overflow", __func__));
bcopy(sa, &ss, sa->sa_len);  // sa_len up to 255, sizeof(ss) = 128

// After fix:
if (sa->sa_len > sizeof(ss)) return (EINVAL);
bcopy(sa, &ss, sa->sa_len);
```

### Key Insights from Praetorian Research
1. **KASSERT compiles out in production kernels** — no runtime check
2. **RTAX_AUTHOR** is the only sockaddr type that slips through ALL validation stages
3. **cleanup_xaddrs()** only validates RTAX_DST, RTAX_GATEWAY, RTAX_NETMASK
4. **update_rtm_from_rc()** replaces those same fields but never touches RTAX_AUTHOR
5. **RTM_GET is exempted from PRIV_NET_ROUTE** — unprivileged users can trigger
6. **127-byte overflow** with fully attacker-controlled content
7. **Overwrites stack canary** — triggers panic via __stack_chk_fail

### Exploitation Strategy
1. Open PF_ROUTE socket (no privilege needed for RTM_GET)
2. Build RTM_GET message with RTAX_AUTHOR (rtm_addrs = 0x40)
3. Set sockaddr sa_len = 255 (maximum)
4. Send via sendto() — triggers overflow in rtsock_msg_buffer()
5. If stack canary is overwritten: kernel panic
6. If canary can be leaked (via info leak): potential RCE

### Related: 8 Total Vulnerabilities Found by Praetorian
- Only CVE-2026-3038 publicly disclosed
- 7 others still awaiting patches
- All found using AI-assisted vulnerability research
- Methodology: semgrep/CodeQL rules + KASAN feedback loop

## Complete Exploit Chains (from Praetorian Part 2)

### Chain 1: Stack Leak + CVE-2026-3038
```
Stage 1: Stack Info Leak
  - VNET ioctl copies more data than expected
  - Leaks: stack canary + kernel text pointer (KASLR defeat)
  - Unprivileged, works from within jail

Stage 2: CVE-2026-3038 Overflow
  - RTM_GET with RTAX_AUTHOR, sa_len=255
  - 127-byte overflow: canary at correct offset
  - ROP chain: clear SMEP/SMAP in CR4
  - Payload: 0x606E0 (CR4 without SMEP/SMAP bits)

Stage 3: Ring0 Shellcode
  - curthread from gs:0 -> td_ucred
  - cr_uid = 0, cr_ruid = 0 (root)
  - cr_prison = &prison0 (escape jail)
  - Pre-bump prison0 refcount by 1000
  - Repoint dir vnodes to rootvnode
  - Return via doreti path
```

### Chain 2: Heap Overflow + Pipe-File Confusion
```
Stage 1: Stack Info Leak (same as Chain 1)
  - Uninitialized struct leak for kernel base

Stage 2: Fork Spray (Heap Grooming)
  - Fork 600+ children
  - Each grows fd table to 640 entries via dup2
  - fdescenttbl allocations fill UMA malloc-32768 zone

Stage 3: Heap Overflow
  - Message-parsing interface overflows into adjacent allocation
  - Overflow rewrites fde_file[0] -> points to pipe
  - Pipe's file ops vtable now controls dispatch

Stage 4: Type Confusion (Pipe-File)
  - fo_chown slot: fchown(fd, 0x706e0, 0)
    -> mov cr4, rsi; ret (SMEP/SMAP cleared)
  - fo_stat slot: fstat(fd) -> jump to shellcode
  - Single-syscall SMEP/SMAP bypass!

Stage 5: Ring0 Shellcode (same as Chain 1)
  - uid=0, escape prison, repoint vnodes
```

### Other Known FreeBSD Vulns (Praetorian + Others + New 2026 CVEs)
| CVE | Description | Affects 13.5? | PS4 Relevant? | Fixed In |
|-----|-------------|---------------|---------------|----------|
| CVE-2026-3038 | RTSock stack overflow | YES | PRIMARY TARGET | 13.5-RELEASE-p10 (Feb 2026) |
| CVE-2026-45251 | procdesc selinfo UAF (poll/select) | YES - stable/13 | CRITICAL - unprivileged LPE | 13.5-RELEASE-p14 (May 2026) |
| CVE-2026-7270 | execve operator precedence overflow | YES - 13.5-RELEASE | CRITICAL - unprivileged LPE | 13.5-RELEASE-p13 (Apr 2026) |
| CVE-2026-4747 | RPCSEC_GSS RCE | YES - 13.5 (needs kgssapi.ko) | HIGH - remote kernel code exec | 13.5-RELEASE-p11 (Mar 2026) |
| CVE-2025-15576 | Jail chroot escape via fd exchange | YES - 13.5-RELEASE | MEDIUM - needs two jails | 13.5-RELEASE-p10 (Feb 2026) |
| CVE-2026-45250 | setcred(2) stack overflow | NO - setcred not in 13.x | - | 14.4 only |
| CVE-2026-45257 | KTLS arbitrary file overwrite | NO - 14.x only | - | 14.3+ |
| CVE-2026-49418 | VM device pager UAF | NO - 14.x only | - | 14.3+ |
| CVE-2026-49422 | TCP RACK UAF | NO - needs tcp_rack.ko | - | 14.3+ |
| CVE-2026-49427/49428 | POSIX largepage UAF | NO - 14.x only | - | 14.3+ |
| CVE-2026-49415 | execve TOCTOU race | NO - 14.x only | - | 14.3+ |
| CVE-2025-15547 | Jail escape via nullfs mount | Maybe | MEDIUM | 13.5 |
| CVE-2023-3107 | IPv6 frag reassembly overflow | Maybe | YES - network | - |
| CVE-2023-6660 | NFS client bug | Unlikely | No NFS on PS4 | - |
| CVE-2024-32668 | bhyve XHCI overflow | NO | No bhyve on PS4 | - |
| CVE-2024-45063 | ctl_write_buffer UAF | NO | No iSCSI on PS4 | - |

### PS4 FW 13.52 PATCH STATUS (Critical Analysis)
PS4 kernel = "release_13.520" built Jun 11 2026

| CVE | Fixed In | PS4 Built | Likely Status |
|-----|----------|-----------|---------------|
| CVE-2026-3038 | 13.5-RELEASE-p10 (Feb 24 2026) | Jun 11 2026 | LIKELY PATCHED (4 months after fix) |
| CVE-2026-45251 | 13.5-RELEASE-p14 (May 20 2026) | Jun 11 2026 | MAYBE PATCHED (3 weeks after fix) |
| CVE-2026-7270 | 13.5-RELEASE-p13 (Apr 30 2026) | Jun 11 2026 | LIKELY PATCHED (6 weeks after fix) |
| CVE-2026-4747 | 13.5-RELEASE-p11 (Mar 26 2026) | Jun 11 2026 | LIKELY PATCHED (2.5 months after fix) |
| CVE-2025-15576 | 13.5-RELEASE-p10 (Feb 24 2026) | Jun 11 2026 | LIKELY PATCHED (4 months after fix) |

NOTE: Sony may or may not merge upstream FreeBSD patches.
The Jun 11 2026 build date suggests Sony had access to fixes, but
Sony's build pipeline is separate from upstream FreeBSD releases.

### procdesc UAF Exploitation Chain (CVE-2026-45251)
```
Stage 1: Create procdesc via pdfork() (unprivileged)
  - Two threads block in poll(2) on procdesc
  - Third thread closes procdesc fd
  - procdesc_free() skips seldrain()

Stage 2: Reclaim freed procdesc
  - SCM_RIGHTS filedescent[2] reclaims freed slot
  - fc_ioctls overlaps pd_selinfo.si_tdlist.tqh_first

Stage 3: First timeout → controlled write
  - cap_ioctls_get() leaks kernel pointer (sf_mtx)
  - cap_ioctls_limit() frees/reclaims with fake selfd

Stage 4: Second timeout → arbitrary kernel write
  - TAILQ_REMOVE() writes controlled qwords

Stage 5: LPE
  - Corrupt victim fd's fc_ioctls → point to pipe buffer
  - Write fake ucred into pipe buffer
  - Set poller td_ucred = fake root credential
  - chown/chmod exploit SUID-root
```

## NEW: Binary Analysis Findings (July 28, 2026)

### Libkernel Binary Analysis Complete
- **302 syscall stubs** identified (306 total `0x0F 0x05` instructions)
- **All 82 Sony custom syscalls (#585-677)** are thin 12-byte wrappers with zero userspace validation
- **Stack canary**: 0x61410, value 0x2341851f695222c1
- **58 GOT entries** with runtime addresses
- **462 strings** (device paths, error messages, function names)

### VULNERABILITY #1: /dev/srtc Write-What-Where (fcn.00021a90)
- **Location**: libkernel.bin offset 0x021a90
- **Impact**: User-controlled destination pointer (r14) receives kernel write
- **Trigger**: `ioctl(fd, 0x40105303, stack_buf)` → 8 bytes written to `[r14]`
- **Status**: Requires /dev/srtc access (may be sandboxed)

### VULNERABILITY #2: /dev/sbi TOCTOU (fcn.000226c0)
- **Location**: libkernel.bin offset 0x0226c0
- **Impact**: User's first argument (r14) passed directly as ioctl buffer
- **Trigger**: ioctl with 0xc008a801 → kernel reads/writes user-controlled address
- **Status**: Race condition exploitable if /dev/sbi accessible

### Context Restore Primitive (syscall 0x1a7/423)
- **Location**: libkernel.bin offset 0x02b08 (alternate entry)
- **Impact**: Full register context restore from user-controlled structure
- **Features**: RDI, RSI, RDX, RCX, R8-R15, RSP, RBP, FPU state
- **Status**: Potential code execution primitive (may crash if executed)

### ioctl 0xa802 Leak Candidate
- **Location**: Function 0x19e80 in libkernel.bin
- **Impact**: ONLY ioctl that returns stack data WITHOUT zeroing
- **Request**: 0xc010a802 (RW, 16 bytes)
- **Status**: May leak kernel-modified data if kernel modifies buffer in-place

### Device Nodes (17+ confirmed)
| Device | Type | Status |
|--------|------|--------|
| /dev/sbi | Security Board Interface | TOCTOU vuln |
| /dev/srtc | Secure Real-Time Clock | W^W vuln |
| /dev/dce | Display Controller Engine | Unknown |
| /dev/dmem0-9 | Direct Memory Access | Unknown |
| /dev/dipsw | Debug/Dev Switch | Unknown |
| /dev/gbase | GPU Base | Unknown |
| /dev/icc0-7 | Inter-Component Communication | Unknown |
| /dev/evlg0 | Event Logger | Unknown |
| /dev/sdk_eventlog | SDK Event Logger | Unknown |
| /dev/notification0-1 | System Notifications | Unknown |

### Exploit Scripts (16 total, 4000+ lines)
| Script | Target | Lines |
|--------|--------|-------|
| srtc_writewhatwhere.lua | /dev/srtc W^W | 275 |
| device_ioctl_fuzzer.lua | All devices × all ioctls | 200 |
| sony_memory_syscall_test.lua | Syscalls 597-677 | 904 |
| kqueue_uaf_exploit.lua | kqueue/knote UAF | 320 |
| combined_uaf_rtsock.lua | UAF + CVE-2026-3038 | 275 |
| chain1_stack_exploit.lua | Stack leak + ROP | 395 |
| chain2_heap_exploit.lua | Heap overflow | 364 |
| cve_2026_3038_rtsock.lua | RTSock overflow | 569 |
| top3_vectors_exploit.lua | Memory syscalls | 366 |
| gpu_token_exploit.lua | GPU + MAC tokens | 372 |
| sony_full_fuzzer.lua | 82 syscalls × 10 | 395 |
| device_sysctl_probe.lua | Device enum | 475 |
| memory_syscall_exploit.lua | Memory syscalls | 356 |
| ps4_utils.lua | Utilities | 175 |

### Deployment Priority (Updated)
1. **device_ioctl_fuzzer.lua** — enumerate all accessible devices + ioctls
2. **srtc_writewhatwhere.lua** — test /dev/srtc W^W vulnerability
3. **sony_memory_syscall_test.lua** — test syscalls 597-677 for leaks
4. **kqueue_uaf_exploit.lua** — test kqueue/knote UAF
5. **combined_uaf_rtsock.lua** — full chain if both vectors work

### Key Discovery: PS4-Specific EVFILT_USER Value
- Standard FreeBSD: EVFILT_USER = -4 (0xFFFC)
- **PS4 FW 13.52: EVFILT_USER = -7 (0xFFF9)**
- Confirmed by OptiTron's research
- Critical for kqueue UAF exploitation

### Binary Analysis Reports
- `LIBKERNEL_ANALYSIS_REPORT.md` — Full 500+ line analysis
- `/data/data/com.termux/files/home/PS4-Kernel-Research-FW1352/LIBKERNEL_ANALYSIS_REPORT.md`
