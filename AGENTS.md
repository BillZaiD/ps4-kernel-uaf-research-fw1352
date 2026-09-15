# PS4 FW 13.52 Kernel Research - Complete Knowledge Base

## Project Structure
- **`PS4-Kernel-Research-FW1352/`** — Active research project with working Lua Loader
- **`/savedata0/` on PS4** — Full exploitation framework pre-loaded in game save data (21 Lua files, ~5000 lines)
- **Libkernel dump**: `dumps/libkernel.bin` (589824 bytes, FW 13.52, Build J02697906)

## System Info
- **PS4 IP**: 192.168.100.61 | **Termux IP**: 192.168.100.2
- **Remote Lua Loader**: Port 9026 (requires Hamidashi Creative game running)
- **Protocol**: `struct.pack('<Q', len(data)) + data`
- **Kernel**: "HeerBSD" (Sony custom FreeBSD), build r228995/release_13.520 Jun 11 2026
- **ASLR**: Active per session (eboot, libc, libkernel all randomized)
- **PS4 Model**: DG1201SLF87HW, 8 CPUs, 16KB pages
- **Lua**: 5.1 — NO string.pack, NO ~ XOR, NO & bitwise, NO ULL suffix
- **uint64**: Table with `.h` and `.l` fields. Lua numbers are IEEE754 doubles (53-bit precision limit)

## Working Primitives (CONFIRMED on real FW 13.52)

### Memory Operations
- `memory.read_byte/word/dword/qword(addr)` — Read userspace memory
- `memory.write_byte/word/dword/qword(addr, val)` — Write userspace memory (write_byte = 1 byte!)
- `memory.alloc(size)` — Allocate zeroed memory via calloc
- `memory.read_buffer(addr, len)` — Read N bytes as string (mapped pages only)
- `memory.write_buffer(addr, buf, len)` — Write buffer to address

### Native Code Execution
- `native.fcall(fn_addr, rdi, rsi, rdx, rcx, r8, r9)` — Call any function address via ROP with longjmp recovery
- `native.fcall_with_rax(addr, rax, rdi, rsi, rdx, rcx, r8, r9)` — Call with controlled RAX. ⚠️ USELESS for syscall-stub RAX forging: kernel RCX-12 stub validation kills the process unless RAX == the stub's baked-in imm32 (q26). Only works when entering a stub with its OWN number.
- `native.write_buffer(addr, buf, len)` — Write buffer via native handler
- `native.read_buffer(addr, len)` — Read buffer via native handler

### Lua VM Primitives
- `lua.addrof(obj)` / `lua.addrof_trivial(obj)` — Get heap address of Lua object
- `lua.create_str("...")` — Create TString at known heap address
- `lua.create_str_hacky(size, modify_fn)` — Create large string with header modification
- `lua.fake_table_value(addr)` — Type confusion: returns object via tbl_victim[3] (PARTIALLY WORKING)
- `lua.setup_victim_table()` — Initialize victim table for fake_table_value
- `lua.setup_primitives()` — Full primitive setup (SUCCEEDS at boot)
- `lua.read_buffer(addr)` — Read via Lua string mechanism (requires mapped page)
- `lua.create_fake_cclosure()` — Create fake C closure (write_upval CRASHES)
- `lua.resolve_value(name)` — Resolve Lua value from registry

### Named Syscall Wrappers (CORRECT FreeBSD 13 numbers)
| Wrapper | Syscall# | fn_addr range | Status |
|---------|----------|---------------|--------|
| syscall.socket | 97 | 0x805718870 | ✅ |
| syscall.bind | 104 | 0x805718c10 | ❌ Sandboxed |
| syscall.listen | 106 | 0x805718cd0 | - |
| syscall.accept | 30 | - | - |
| syscall.connect | 98 | - | - |
| syscall.getsockopt | 118 | - | ✅ Returns small ints only |
| syscall.setsockopt | 105 | - | ❌ IPv6 blocked, SO_BROADCAST works |
| syscall.close | 6 | - | ✅ |
| syscall.read | 3 | - | ✅ |
| syscall.write | 4 | - | ✅ |
| syscall.pipe | 42 | - | ✅ |
| syscall.sysctl | 202 | - | ✅ Returns kernel info (no kernel ptrs) |
| syscall.mmap | 477 | - | ✅ W^X strips EXEC |
| syscall.mprotect | 74 | - | ❌ Sandboxed |
| syscall.dlsym | - | - | - |
| syscall.dynlib_load_prx | - | - | ❌ Sandboxed |

### Eboot Stub Table (sc[N]) — CORRECTED 2026-07-31 (q26)
- 221 syscall wrapper entries in `syscall.syscall_wrapper`
- **LIVE EVIDENCE (q26)**: `syscall.syscall_wrapper[20]` resolved to **libkernel getpid stub** (`libk_base+0x6f0`), NOT eboot. The framework's `syscall.init` resolves wrappers to libkernel stub addresses at boot.
- Eboot code pages are **execute-only** (no reliable read via memory.read_byte/read_buffer; find_bytes on them returns garbage — q24 tramp_off=3 was bogus)
- Some work: sc[20]=getpid ✅, sc[24]=getuid ✅, sc[362]=kqueue ✅
- Some hang: sc[363]=kevent HANGS (eboot PLT issue)
- Some crash: sc[585+] Sony customs CRASH (unresolved PLT entries)
- Named wrappers use **libkernel addresses** (0x805xxxx) — more reliable

### Raw Syscall Execution via native.fcall
| Syscall | Number | Status |
|---------|--------|--------|
| getpid | 20 | ✅ Returns PID |
| getuid | 24 | ✅ Returns 1 |
| pipe | 42 | ✅ |
| read/write | 3/4 | ✅ |
| close | 6 | ✅ |
| kqueue | 362 | ✅ Via sc[362] eboot stub |
| kevent | 363 | ❌ CRASHES via sc[363] (eboot PLT bad) |
| fork | 241 | ❌ CRASHES (sandbox blocks, corrupts state) |
| mmap | 477 | ✅ RW only (W^X strips EXEC) |
| socket | 97 | ✅ Via named wrapper fn_addr |

### Libkernel Binary Analysis
- **Dump**: `dumps/libkernel.bin` (589824 bytes, raw x86-64, no ELF header)
- **Syscall stubs**: 302 stubs found at pattern `48 c7 c0 <imm32> 49 89 ca 0f 05`
- **Key stubs identified**: sc#362 (kqueue) @ dump+0x1390, sc#363 (kevent) @ dump+0x13b0
- **CRITICAL**: eboot stub addresses ≠ libkernel stub addresses (different PLT/GOT)
- **CRITICAL**: Cannot read eboot code pages (execute-only) or libkernel code (crashes)

### Kernel Information Retrieved
| Source | Data | Kernel Pointers? |
|--------|------|-------------------|
| sysctl kern[1-4] | "FreeBSD", "0.0-prototype", 0x30b52, build string | ❌ |
| sysctl kern[38] | 0x13520001 (FW version) | ❌ |
| sysctl kern[37] | 255 bytes random data | ❌ |
| sysctl kern[47/48] | 64 bytes security keys | ❌ |
| sysctl hw[2/3/7] | Model, ncpu, pagesize | ❌ |
| kinfo_proc (1096 bytes) | Process/thread info | ❌ ALL zeroed |
| kqueue kevent | Returns events | ❌ Data zeroed |
| getsockopt | Various options | ❌ Small ints only |
| sigaction oldact | Signal handler info | ❌ All zeros |

## BLOCKED Attack Vectors (confirmed FW 13.52)
| Vector | Result |
|--------|--------|
| W^X bypass | ENFORCED |
| Direct kernel R/W | MMU protects |
| setsockopt IPv6 (pktopts) | Sandboxed (returns -1) |
| bind(AF_INET) | Sandboxed |
| fork | CRASHES (corrupts loader state) |
| fork+ptrace+chroot | All blocked |
| /dev/* devices | ALL sandboxed — game-side `S.open` fds: ioctl all -1, no leaks; libkernel-INTERNAL fds (5/6/7) partially bypass: only dmem0 release ioctl + fixed 16MB writable kernel-dmap window, NO info leaks (probe_dev_r1..r12 + r9f..r9y, 2026-08-01) |
| kevent via eboot sc[363] | CRASHES (unresolved PLT) |
| Sony custom syscalls 585-677 | CRASH or return -1 |
| **Universal syscall trampoline (fcall_with_rax stub+7/+10)** | **BLOCKED — kernel RCX-12 stub validation kills on RAX mismatch (q24b/q25/q26)** |
| **Hidden-syscall scan (678+)** | **IMPOSSIBLE — no stub exists for them; each stub is one syscall (RCX-12 check)** |
| loadstring(bytecode) | Returns nil on FW 13.52 |
| fakeobj_through_closure | Broken (loadstring nil) |
| create_fake_cclosure | write_upval CRASHES at offset 0 |
| getsockopt kernel leak | Only small integer values |
| **CSSFontFace UAF (ntfargo/WebKitty) on 13.52** | **OUR PUBLIC-CHAIN ANALYSIS: ARCHITECTURALLY DEAD (2026-09-11, WebKit-616-1300 source): `featureSettings()` no longer returns `m_featureSettings.toString()` — now `properties().getPropertyValue(CSSPropertyFontFeatureSettings)` (CSSFontFace.cpp:396), so the 9.00 `m_buffer` redirect read-primitive has NO observable effect; ALL string getters go through `WTF::switchOn(m_propertiesOrCSSConnection)` (std::variant@0x10) = null `Ref<MutableStyleProperties>` → SIGSEGV. Only status()/ranges()/fontSelectionCapabilities() survive zeroing; none yield arbitrary read.** ⚠️ **SUPERSEDED BY SCENE (2026-09/10 coverage, MODDED WARFARE + Andrew2007): UFM42 found a WORKAROUND that makes the WebKit userland exploit reach 13.52 on PS4 (and ~13.40 on PS5) — the bug family lives on, a different gate/primitive bypasses the 616-1300 dead-end we proved. PS4 WebKit userland to 13.52 CONFIRMED in-scene; a kernel chain is still required for a jailbreak. Our "dead" verdict applies ONLY to the ORIGINAL 9.00-era chain, not to the workaround (which we have not seen).** |
| kevent kernel leak | Data zeroed |
| sigaction kernel leak | oldact all zeros |

## Framework Source (extracted from PS4 /savedata0/)
| File | Lines | Key Functions |
|------|-------|---------------|
| main.lua | ~319 | Bootstrap: setup_primitives→syscall.init→listener:9026 |
| memory.lua | ~101 | R/W wrapper, read_buffer via native when available |
| lua.lua | ~451 | fakeobj, create_str, setup_primitives, addrof, fake_table_value |
| native.lua | ~500 | ROP-based fcall with longjmp recovery |
| kernel.lua | ~470 | pktopts exploit: ipv6_kernel_rw.init(ofiles, kread8, kwrite8) |
| kernel_offset.lua | ~800 | PS4/PS5 offsets FW 1.00-12.02 (NOT 13.52) |
| offsets.lua | ~800 | games_identification, gadget_table per game |
| misc.lua | ~528 | sysctlbyname, load_prx, dlsym, load_bytecode |
| globals.lua | - | Constants: PROT_*, MAP_*, AF_*, syscall numbers |

### Key Framework Details
- `games_identification[0x420] = "HamidashiCreative"` — our game IS supported
- `luaB_auxwrap = 0x1a7420` — confirmed correct for Hamidashi Creative
- `setup_primitives()` SUCCEEDS at boot — all userland primitives work
- `kernel.lua` needs `ofiles` + `kread8` + `kwrite8` to init pktopts kernel R/W
- `fake_table_value` writes to `tbl_victim_array + 0x20` (slot 3), reads garbled object
- `lua.read_buffer` only reads mapped userland memory — returns nil for kernel/addrs

## Libkernel Code Page Permissions (FW 13.52) — CORRECTED
- **Readable (via read_buffer)**: only first ~0x1400 bytes; beyond that read_buffer CRASHES the loader.
- **Executable (via native.fcall)**: syscall STUBS are executable well beyond 0x1400 — confirmed working stubs at 0x16b0/0x1770/0x1810/0x18f0/0x1950/0x1b50/0x1c10. The "non-executable" zone only applies to large C functions (e.g. sceKernelLoadStartModule @ 0x2bb20 → SIGSEGV err=0x14). Exact exec boundary unknown; keep stub calls within ~0x2800.
- **CRITICAL**: `lua.read_buffer` on libkernel addresses CRASHES process if any byte falls outside readable range. NEVER scan libkernel with read_buffer loops — use only native.fcall.
- **CRITICAL**: Large loops (>50 iterations) with native.fcall cause timeouts. Keep all PS4-side loops under 30 iterations.

## Syscall Stub-Validation Mechanism (RCX-12 check) — CONFIRMED LIVE 2026-07-31 (q26)
**Arbitrary-syscall via `fcall_with_rax` is IMPOSSIBLE on FW 13.52.** Sony's kernel validates every `syscall` entry:
- The kernel reads the stub **12 bytes before the return RIP** (RCX-12; RCX = instruction after `syscall`) and compares the stub's baked-in `mov rax, imm32` against the RAX delivered to the syscall.
- **LIVE PROOF (q26)**: `fcall_with_rax(libk_getpid_stub+7, 20)` → **returns real PID 996** (RAX=20 == stub imm32=20 → MATCH). `fcall_with_rax(libk_getpid_stub+7, 24)` on the SAME stub → **process killed** (RAX=24 ≠ 20 → MISMATCH). Same crash at stub+10 (raw syscall byte).
- Only stubs whose baked number == requested syscall number survive. Each stub = exactly one syscall → **no universal trampoline, no hidden-syscall scan (678+) possible**.
- q23b (jump to `syscall; ret` @0x2baa) crashed for a SECOND reason: 0x2baa (sc#454 umtx_op dead stub, `syscall; ret` w/o jb, surrounded by ud2) is **past the ~0x2910 exec boundary** → SIGSEGV on instruction fetch.
- **Offline scan of all 306 `0f 05` sites in libkernel.bin**: EVERY syscall site is a fixed `48 c7 c0 <imm32> 49 89 ca 0f 05` stub. **No register-driven `mov eax,<reg>; syscall` gadget exists** in the executable region. The only non-stub syscalls are inside large C functions (0x21543/0x2156a use `movabs rax,...`) — past exec boundary.
- FINDINGS.md:84 ("Trampoline wrapper+7 BLOCKED — kernel reads RCX-12") is CORRECT; DEEP_REVIEW.md's "wrapper+7 works" only ever succeeded for calls where scno == the stub's own number (kqueue via kqueue stub, etc.).

## AF_UNIX Socket Primitives (NEW - NOT SANDBOXED)
| Operation | Status | Notes |
|-----------|--------|-------|
| socketpair(AF_UNIX, SOCK_STREAM, 0) | ✅ | Via libkernel sc#135 (dump+0x0e10) |
| setsockopt(SOL_SOCKET) on AF_UNIX | ✅ | NOT sandboxed! Returns 0 |
| getsockopt(SOL_SOCKET) on AF_UNIX | ✅ | Returns basic socket info |
| SO_TYPE | ✅ | Returns 1 (SOCK_STREAM) |
| SO_ERROR | ✅ | Returns 0 |
| SO_REUSEADDR | ✅ | Read/write works |
| SO_RCVBUF/SO_SNDBUF | ✅ | Returns 0x2000 (8KB) |
| LOCAL_PEERCRED (level=0, opt=7) | ❌ | Returns -1 |
| SO_DOMAIN/SO_PROTOCOL | ❌ | Returns -1 |

## Assessment — CORRECTED 2026-07-31
FW 13.52 is **heavily hardened at the GAME-SANDBOX level**, but the kernel itself is NOT unexploitable:
- Game sandbox: W^X enforced, MMU blocks kernel access, all info leaks sanitized, setsockopt IPv6 AND IPv4 IP_OPTIONS heap-writes blocked, kevent data sanitized, loadstring bytecode disabled
- **THE KERNEL IS VULNERABLE from the BD-J player app**: Gezine's Poopsploit 1.8/1.9 (in `BD-UN-JB`) ships full 13.52 offsets + shellcode and the SAME primitives that are sandboxed in-game (ucred triple-free via `__sys_netcontrol`, IPV6_RTHDR pktopts heap spray, kqueue struct leak, pipebuf corruption → arb R/W) work from the BD-J process, which is a Sony system app with full syscall access.
- **A working 13.52 jailbreak demonstrably exists**: `ps4-linux/ps4-linux-loader` **v25 (2026-07-25)** ships real 13.52 kexec offsets (`linux/fw_offsets.h:51`) and only runs on already-jailbroken consoles → someone has jailbroken 13.52 in the wild. Poopsploit via BD-JB is the only public 13.52 kernel exploit that can explain it.
- **Game-sandbox conclusion stands**: no kernel vuln is reachable from the Hamidashi Creative process. The vulns exist but require BD-J privileges.
- **Browser-sc#588 investigation (2026-09-14, fc2/fc2b/fc2c probes)**:
  - **Libkernel 0x30a00 REVEALED**: the real SceLibcMutexPoolForMonoVM pool-register path calls `mmap(hint=0x880000000, len=0x100000, prot=3, flags=0x3000, -1, 0)` then `sc#588(addr, len, rdx=&"SceLibcMutexPoolForMonoVM", rcx=outword)`. The "type" in rdx is actually a **name string pointer**, not an integer — passing int caused immediate kill.
  - **Browser accepts high mmap hints**: `mmap(hint=0x880000000)` returns `~0x880e7c000` (0x880000000+0xe7c000) successfully from WebKit uid=1. anon mmap flags 0x1002 work; real source uses 0x3000.
  - **sc#588 ALWAYS kills renderer from uid=1** (browser AND game): all 8 combinations tried (int rdx, name* rdx, missing rcx, valid rcx/outword, len 1MB/16MB) → renderer killed immediately at syscall entry. The `out` validation: `callAddr`+ROP engine itself is FINE (fc2c: `getpid rv=143`, `getuid rv=1`, `mmap(5args) rv=near-hint` all succeed). The kill is **syscall-filter-specific to Sony custom #588 at uid=1**.
  - **Root cause confirmed**: not ABI/rcx/outword — Sony's kernel sandbox kills the process on ANY Sony custom syscall (585–677) from uid=1 (WebKit or game). Only `sc#585` (is_in_sandbox, returns 1) survives; all others kill/crash.
  - **Verdict**: sc#588 dmem-registration path is architecturally dead from both game and browser. The path is only viable from BD-J (uid=0) via Poopsploit.
- **Offline PUP decryption CONFIRMED INFEASIBLE**: `PS4UPDATE_1352_SYS.PUP` is an `SLB2` container holding two AES-encrypted inner PUPs (PS4UPDATE1.PUP @0x9b766 size 177282367, PS4UPDATE2.PUP @0xa9ad4a5 size 325391707). Inner blobs show max entropy (7.95-7.96) throughout — fully encrypted, zero plaintext structure, no extractable kernel. Sony keys not public.

## Libkernel Base Computation (RUNTIME)
```
libk_base = syscall.socket.fn_addr - dump_offset_of_socket(0x0b70)
```
- socket.fn_addr is a uint64 table `{h=X, l=Y}`, convert to number: `h * 4294967296 + l`
- `make_addr(dump_offset)`: compute libkernel address from base + offset
- kevent via libkernel WORKS (eboot PLT was broken)
- **CRITICAL**: Addresses must be computed per-session (ASLR changes each boot)

## Sony Custom Syscall Results (tested via libkernel)
**True Sony customs**: 434, 435, 585-677 (434/435 NOT YET probed). 188/189/190/196/272/363/397/482 are vanilla COMPAT11/COMPAT12 stubs (NOT custom).
| Syscall | Return | Notes |
|---------|--------|-------|
| 585 | 1 | is_in_sandbox (always returns 1) |
| 596 | 0 | Unknown, no buffer write |
| 599 | 0 | Unknown, no buffer write |
| 602 | 0 | Unknown (returns -1 with buffer arg) |
| 606 | 0 | Unknown, no buffer write |
| 617 | 0 | Unknown, no buffer write |
| 620 | 0 | Unknown, no buffer write |
| 622 | CRASH | Kills loader process |
| 624 | 0xBCC-0xC21 | Changes per boot, NOT fd-dependent |
| 638 | 0 | Returns -1 with buffer arg |
| 639 | 0 | Unknown |
| 640 | 0 | Unknown |
| 643 | 0 | Unknown |
| 653 | 0x16 (fd0), -1 (others) | Possibly fpathconf-like |
| 656-662 | One CRASHES | Others return -1 |
| 663-670 | One CRASHES | Others return -1 |
| All others | -1 | Unknown/unsupported |

## Libkernel String References (device paths & sysctls)
| String | Offset | Used By |
|--------|--------|---------|
| `/dev/dmem0` | 0x37480 | Direct memory device |
| `/dev/dipsw` | 0x374d5, 0x37bcc, 0x3b6f3 | Debug DIP switch |
| `/dev/gbase` | 0x37c7f | GPU base (5 callers) |
| `/dev/icc_configuration` | 0x37d22 | ICC power management |
| `/dev/icc_power` | 0x37d59 | ICC power control |
| `/dev/icc_fan` | 0x37e65 | ICC fan control |
| `/dev/evlg0`, `/dev/evlg1` | 0x37eca, 0x37e90 | Event log devices |
| `/dev/sbi` | 0x37f12 | SBI device |
| `/dev/console` | 0x3bf33 | Console device |
| `machdep.rcmgr_utoken_data_execution` | 0x37906 | W^X token |
| `kern.dmem.game_budget_limit` | 0x374b9 | Memory budget |
| `machdep.openpsid` | 0x3776b | PS4 unique ID |
| `machdep.tsc_freq` | 0x37699 | TSC frequency |
| `kern.proc.ptc` | 0x376aa | Process time counter |

## Key Function Addresses in Dump
| Function | Dump Offset | Purpose |
|----------|-------------|---------|
| `_sceKernelLoadStartModule` | 0x2bb20 | Module loader (huge function, 18+ refs) |
| `sceKernelStopUnloadModule` | 0x2c3b0 | Module unloader |
| `__orbis_rtld__rtld_thread_init` | 0x2f930 | Thread init |
| `/dev/dmem0` opener | 0x18210 | Opens direct memory device |
| `/dev/dipsw` opener | 0x19810 | Opens debug DIP switch |
| `machdep.rcmgr_utoken_data_execution` reader | 0x1c950 | Reads W^X token |

## /dev Device Path — REOPENED 2026-08-01 (probe_dev_r9f..r9x) — DMEM0 BREAKTHROUGH
**CONCLUSION (OVERTURNED)**: Earlier probe_dev_r1..r12 used game-side `S.open` fds (fd=22) — those ioctls are FILTERED (-1) and the "crashes" came from calling ioctl/read/mmap on the sandbox-wrapped fd. The REAL story: **libkernel-INTERNAL device fds (cached in libkernel globals at init) bypass the game-sandbox ioctl filter** — they give working ioctls AND a working writable mmap that maps a **kernel dmap region**.
- Game-side `S.open` fd (22) → ioctl always -1 (sandbox wrapper filters). libkernel-internal fds are REAL.
- **fd=5 = /dev/dmem0 real fd** (dword 5 in global `libk+0x58038+8`); **fd=7 accepts ioctl 0x4010a802 → ret 0**. fd=6 also real. fds 23/24/29/30 transient.
- **`mmap(fd5, 0x1000000, PROT_RW, MAP_SHARED=0x0001)` SUCCEEDS** → writable persistent 16MB region (0x311xxxx000 VA).
- **KERNEL DMAP WRITE WINDOW CONFIRMED**: the mapped region IS kernel dmap RAM —
  - Descriptor table at map+0x0 (one-shot per boot but **re-obtainable**: `ioctl(5, 0x80108002, {aligned, size})` re-arms it, then next mmap returns it).
  - `+0x18 = 0xffffffff2ec48000` = **kernel dmap self-pointer** (this region's kernel VA; dmap base 0xffffffff00000000 → phys 0x2ec48000). FIXED across boots (dmap not ASLR-randomized).
  - `mmap(fd5, 1MB, offset=X)` returns VA=X (physical-identity) but content is always the SAME fixed 16MB dmem window (descriptor + zeros). **offset is NOT arbitrary phys**; window size is fixed 16MB.
  - **Writes PERSIST across ioctl re-arm + re-mmap** (wrote 0xABCD0000 at +0x20, survived) → the descriptor block is live kernel memory we can write without reset.
  - Full block: magic `0x80000000c0012800`, phys ptrs `0xc000120080000000`/`0xc005580000000000`, DMA entries `0x000000<off>c0027600` at +0x30..0xa0 (offs 0x8,0x48,0x88,0xc8,0x108,0x148,0x88,0x20c,0x218), and a stride-0x40 pair table `{0xc010760000000000, 0xc+N*0x40}` at +0xe0/+0x120/+0x180/+0x1c0. GPU phys base ≈0xc0027600/0xc0107600 (=CPU phys 0x2ec48000/0x2fc48000 via dmap).
- ioctl 0x80108002 = IOC_IN struct-set (264B read, only qw0/qw1 used; libkernel wrapper @0x17800). qw0 must be 0x40000-aligned (PASS: 0x100000, 0x10000000, 0x40000000, 0x80000000, 0x2ec48000; FAIL: 0x1000, 0xc0027600, 0xFFFFF). qw1 = size (ignored by window).
- **⚠️ CRASH (r9s)**: `ioctl{0x100000, 0x100000}` then mmap → loader killed (needed PS4 restart). Rule: keep ioctl args to known-safe aligned values; NEVER sweep IN/INOUT structs on unknown fds.
- **WHAT IT GIVES / LIMITS**: ✅ writable persistent kernel-dmap structure (descriptor block, ~0x100 bytes meaningful) + fixed 16MB dmem window + kernel dmap VA leak. ❌ NO arbitrary-phys mapping, NO window expansion, NO controlled DMA redirect (descriptor format = GPU DMA table; trigger = GPU rendering; editing blindly risks GPU crash). **This is NOT yet a kernel R/W primitive for exploitation** — the descriptor block is a GPU DMA structure, not a privilege-relevant struct. Fake-descriptor DMA redirect remains theoretical (needs kernel driver RE + DMA trigger knowledge, both unavailable).
- **FULL WINDOW DECODE (r9ai..r9am, 2026-08-01)**: window is a **frozen GPU-state snapshot** (not "descriptor + zeros"): +0x000 DMA descriptor list; **+0x2a0 GPU VM map table** (0xc0016900 bases w/ sizes 0x79000/0x80000/0x3f800000/0xcc0000, 0xc0017600, 0xc0002a00, 0xc0012600, 0xc0001300, 0xc0002f00, 0xc0012000, 0xc0004600; **+0x318/+0x3d8 = 0xffffffff00000000 dmap base**); **+0x800 Region A = GPU command-submission ring** (47×20B recs `{PM4 hdr 0xe0000c00 type3/count12, GPU base 0xc0038000, 0xf, 0x100, off}` offsets 0x2000→0xbc00 step 0x800); **+0xf000 Region B = resident PM4/GCN cmd buffer** (0xbf810000 NOP, 0xf800/0x7e02 GCN instrs, sig 0x0772646853627240). **LIVENESS (r9am)**: 2 consecutive re-arms → 0 changed qwords in 0x0-0x1000 AND 0xf000 → **window is STATIC, not refreshed by GPU (game idle), ring NOT consumed** → GPU-command-injection is INERT. Re-arm does NOT repopulate.
- **INFO-DRAIN COMPLETE (r9an/r9ao)**: sc#560 kevent STD = registers but never delivers (sc#363 COMPAT11 works, ext[4]=0 no leak); sc#551 fstat STD = -1 on ALL fds (syscall blocked); sc#563 getrandom = -1. Every untested AGENTS.md lead executed → game sandbox fully drained.
- Other devices via internal fds: dipsw open+ioctl works (ret 0); srtc/sbi/gbase/dce internal opens → 0x800f0513/0x80020002/0x80020013/0x80020001 (denied). leak-fn 0x19e80 (fd7, ioctl 0x4010a802) → ret 0 but 16B output SCRUBBED to zeros (Sony sanitizes it).
- libkernel C functions through 0x22700 ARE executable via native.fcall (libk_base = S.open.fn_addr - 0x2750).

### Browser DMEM0 Breakthrough (probe=dmem, 2026-09-12)
**The browser (WebKit) has a WIDER syscall surface than the game** — confirmed by chain: netcontrol + IPV6_RTHDR both work in-browser (blocked in-game). New finding: **`SYS.open("/dev/dmem0", O_RDWR)` succeeds from the browser → fd=9, err=0**. The game's `S.open` returned sandbox-wrapped fd (ioctl -1), but the browser's direct syscall open is NOT sandbox-filtered for `/dev/dmem0`.
- `ioctl(fd=9, 0x80108002, {qw0=0x100000,qw1=0x100000})` rearm → **rv=0** (succeeds)
- `ioctl(fd=9, 0x80288012, ...)` query → **rv=-1, EINVAL(22)** (still filtered)
- **`mmap(fd=9, 0x1000000, PROT_RW, MAP_SHARED)` FAILS** — returns 0xFFFFFFFF00000000 (error, not MAP_FAILED 0xFFFFFFFFFFFFFFFF). The fresh fd accepts rearm but kernel doesn't set up mmap state for it. Re-arm "succeeds" but the region is not mapped-able on a non-libkernel-opened fd.
- **Fallback path**: internal libkernel fds 5/6/7 (cached at `libk+0x58038+8`) — these are the fds that worked in the game for mmap. Browser probe now routes through [useFd, 5, 6, 7] trying each.
- **GAME vs BROWSER difference**: game = internal fd only, fresh open blocked; browser = fresh open succeeds but mmap needs internal fd. Both end up at fd 5 (libkernel's `/dev/dmem0` descriptor, set up at boot).
- **UPDATED 17:02 (2026-09-12)**: browser internal fds are NOT 5/6/7 — reading `libk+0x58038` → **dword 8** (browser's own fd table). But rearm on internal fd 8 → **ENOTTY(25)** (not dmem0 in browser). Every fd's mmap fails **EPERM(1)** (never succeeds in browser; game-only). `read()/write()` on re-armed dmem0 fd → **ENODEV(19)** — the kernel driver does NOT expose read/write on dmem0 at all. 
- **UPDATED 17:15 (2026-09-12)**: calling libkernel's INNER `/dev/dmem0` opener `@libk+0x18210` via callAddr ROP → **HANGS the renderer** (logged `calling libk dmem0 opener @0x...`, never returns `libk-opener rv=`). callAddr ROP works for syscall STUBS (all `sc()` calls) but NOT for C functions (0x18210) — it does not set up the stackframe/args a real C fn needs (game used native.fcall with longjmp, different path). **Dmem window FULLY CLOSED in-browser**: open✅ rearm✅ query EINVAL mmap EPERM read/write ENODEV inner-opener HANGS. Path ARCHITECTURALLY DEAD from the browser, bypassing its own forged-path and arg-setup limits is out of reach without native.fcall-style execution.
- **FINAL /dev SWEEP in browser REPLACING game tests (18:11-18:48, 2026-09-12, probes devopen/decioctl/dcedrv/gbase2)**: with the module-cache defeated (uniquely-named module file `chain_1352_dec.js` + v= query), a COMPLETE browser /dev surface is now proven TERMINALLY CLOSED:
  - `probe=devopen` — browser directly `SYS.open`s ALL 19 device paths found in libkernel.bin strings. Only **3 open**: `/dev/dmem0` (RDWR), `/dev/dipsw` (RDONLY), `/dev/dce` (RDWR). All 16 others (dmem, gbase, dce, icc_*, evlg*, sdk_eventlog, srtc, sbi, console, notification, icc_configuration...) → **ENOENT(2)** — absent from the browser/WebKit /dev namespace. `/dev/gbase` → **fd=-1 EBADF-ish (err=9)** — the WebKit process HAS the path string but the char-dev driver denies creation of the cdev from THIS process (only internal fds work, and only for dmem0 in the game).
  - `probe=decioctl` — targeted battery on the 3 openable devices with EXACT ioctl codes pulled from libkernel.bin openers (dmem0: 0x80108002/0x80288012/0xc0208004/0x80108015/0x80108017/0x40188009/0x4010a802; dipsw: 0x40048806/0x4008800a; dce: 0xc0308203/0xc0044507/0xc0044508/0xc0044511/0x40084516/0x80020016/0x80020001). Results: dmem0 rearm 0x80108002=0✅ + **0x80108015=0✅** (new, all-zero output; unknown cmd, no data leak), query 0x80288012=-1 **EACCES(13)** (NOT EINVAL — distinct filter path), everything else EINVAL(22)=sandbox filter. dipsw 0x40048806=**0✅** but returns all-zero DIP switch state (no leak), rest EINVAL. **dce 0xc0308203=-1 EFAULT(14)** — the ONE ioctl that was NOT EINVAL-filtered → reached the real driver.
  - `probe=dcedrv` — replicated libkernel's DCE opener byte-exact (struct{dword0=0x23, rest zero@0x40}, the SAME struct the real opener builds before calling 0xc0308203). Result: **rv=-1 err=1 (EPERM)** — changed from EFAULT with a zeroed struct, proving the driver IS reading our struct (struct-dependent error) but the DCE hardware-path is **PERMISSION-DENIED from the WebKit process**. All dce read ioctls (0x40084516, 0xc0044507) → EINVAL(22) sandbox-filtered. **No DCE register read/write primitive reachable from the browser.**
  - `probe=gbase2` — RE correction: the 0x1d400-0x1dc00 ioctl-family functions actually open **`/dev/gbase`** (GPU base), NOT dce (the `lea rdi,[rip+...]` strings at 0x1d42b/0x1d919/0x1d9c9/0x1da79 = `/dev/gbase`; 0x1d5e2/0x1d830 = `dev.cpu.0.freq`; 0x1db15 = `kern.init_safe_mode`). The r14=0xc0044507 + `rsi=r14+2..+7` sweep = **full NR family 0xc0044507,09,0a,0b,0c,0d,0e,0x11** (odd NRs we had never probed) with dword values 0x320/0x2a2/0x2c8/0x320/0x390/0x3d9/0x834/0x2d0. Result: **ALL fail with fd=-1 EBADF(9)** because **browser cannot even open /dev/gbase** — the GPU device node is not creatable from WebKit. 0x40084516 read-back also EBADF. **GPU surface fully closed in browser.**
  - **FINAL VERDICT**: every reachable /dev path from the browser is exhaustively enumerated and closed — dmem0 (mmap EPERM, query EACCES/EINVAL, rw ENODEV), gbase (cannot open EBADF), dce (opens but EPERM init + EINVAL reads), dipsw (opens but reads zeros). The sandbox wraps char-dev creation AND filters ioctl by family; the ONLY driver that answers (dce) refuses the WebKit uid-1 process. **No kernel R/W or info leak surface remains on /dev from the browser.** Module-cache lesson: PS4 WebKit caches imported modules by URL; `?v=` on the HTML import did NOT reliably bust it; only a NEWLY-NAMED module file (`chain_1352_dec.js`) reliably loads.

## kevent Filter Types Tested
| Filter | Value | Result |
|--------|-------|--------|
| EVFILT_READ | -1 (0xFFFF) | ✅ Works, returns data count, no kernel ptrs |
| EVFILT_USER | -7 (0xFFF9) | ✅ Works with NOTE_TRIGGER (0x80000000) |
| EVFILT_VNODE | -4 (0xFFFC) | ❌ Returns -1 (blocked or invalid on socket) |

## Libkernel Syscall Stub Map (from local dump, 298 stubs) — CORRECTED 2026-07-31
**IMPORTANT**: Previous map used FreeBSD-12-era names. Sony's syscall ABI = **vanilla FreeBSD 13.0 numbering** (verified against releng/13.0 syscalls.master). COMPAT11/COMPAT12 stubs also present. True Sony customs: **434, 435, 585-677**. 432 is `AUE_NULL` in vanilla but Sony repurposed it as `thr_self`.

Key stubs (dump offset):
- sc#1=exit(0x2a10? no—sc#2=fork(0x2a10)), sc#3=read(0x27d0), sc#4=write(0x2910), sc#5=open, sc#6=close(0x26b0)
- sc#20=getpid(0x6f0), sc#24=getuid(0x730), sc#25=geteuid(0x750), sc#39=getppid(0x870), sc#43=getegid(0x8d0), sc#47=getgid(0x910) [NOT getpgrp!]
- sc#27=recvmsg(0x2830), sc#28=sendmsg(0x2870), sc#29=recvfrom(0x2810), sc#30=accept(0x2670), sc#31=getpeername(0x770), sc#32=getsockname(0x790)
- sc#42=pipe(0x05f0), sc#54=ioctl(0x970), sc#92=fcntl(0xb30), sc#93=select
- sc#97=socket(0x0b70), sc#98=connect(0x26d0), sc#104=bind(0x0c10), sc#105=setsockopt(0x0c30), sc#106=listen(0x0c50), sc#118=getsockopt(0x0cf0)
- sc#133=sendto(0x2890), sc#134=shutdown(0xdf0), sc#135=socketpair(0x0e10), sc#141=getpeername(COMPAT11)
- sc#202=__sysctl(0x1010), sc#232=clock_gettime(0x1090), sc#251=rfork(0x479) [PRESENT!]
- sc#253=issetugid(0x1190) [NOT pdfork! returned 0 = correct issetugid result]
- sc#362=kqueue(0x1390), sc#363=kevent COMPAT11(0x13b0), sc#400=ksem_close(0x1410) [NOT kqueuex]
- sc#430=thr_create(0x1550), sc#431=thr_exit(0x1570), sc#432=thr_self SONY(0x1590), sc#433=thr_kill(0x15b0)
- sc#442=thr_suspend(0x1630), sc#443=thr_wake(0x1650), sc#454=_umtx_op(0x1690/0x2ba0), sc#455=thr_new(0x16b0), sc#456=sigqueue(0x16d0)
- sc#464=thr_set_name(0x16f0) [NOT memfd_create!], sc#466=rtprio_thread(0x1710) [NOT timerfd_create!]
- sc#477=mmap(0x2990), sc#483=shm_unlink(0x1770), sc#533=cap_rights_limit(0x1810) [NOT jail!]
- sc#534=cap_ioctls_limit(0x1830), sc#535=cap_ioctls_get(0x1850), sc#536=cap_fcntls_limit(0x1870)
- sc#541=accept4(0x18f0), sc#544=procctl(0x1950), sc#545=ppoll(0x1970)
- sc#551=fstat (stub@0x1a30, STD - BLOCKED -1), sc#560=kevent STD(0x1b50) [registers but NEVER delivers], sc#563=getrandom(0x1b70) [BLOCKED -1]
- sc#572=shm_rename(0x1c10)
- ABSENT (no stub): sc#26=ptrace, sc#46=sigaction (416 is present), sc#570=__sysctlbyname, sc#571=shm_open, sc#575=close_range, sc#577=__specialfd

## Syscall Stub Results (via native.fcall to libkernel stubs) — CORRECTED INTERPRETATION
| Stub@ | Actual syscall | Result | Notes |
|-------|----------------|--------|-------|
| sc#47 getgid | 47 | 1 | ✅ (was labeled "getpgrp"; game gid=1) |
| sc#116 gettimeofday | 116 | 0 | ✅ Works, need buffer |
| sc#117 getrusage | 117 | 0 | ✅ Works, 28 nonzero bytes |
| sc#202 __sysctl | 202 | varies | ✅ Works (kern.1-10 return data) |
| sc#362 kqueue | 362 | fd | ✅ Works |
| sc#363 kevent | 363 (COMPAT11) | 0 | ✅ Works (COMPAT path) |
| sc#560 kevent | 560 (STD) | 0 events | ❌ REGISTERS but NEVER delivers (instrumented/muted in sandbox); sc#363 COMPAT11 delivers same event. ext[4]=0, no leak (r9an) |
| sc#551 fstat | 551 (STD, stub@0x1a30) | -1 on ALL fds | ❌ fstat syscall itself sandbox-blocked (internal fds 5/6/7 + socketpair) (r9ao) |
| sc#563 getrandom | 563 (stub@0x1b70) | -1 | ❌ Blocked (r9ao) |
| sc#135 socketpair | 135 | 0 | ✅ Creates AF_UNIX pair |
| sc#232 clock_gettime | 232 | 0 | ✅ Works |
| sc#329 __getcwd | 329 | -1 | ❌ Returns error |
| sc#464 thr_set_name | 464 | -1 | ❌ (was "memfd_create" — wrong args) |
| sc#400 ksem_close | 400 | -1 | ❌ (was "kqueuex") |
| sc#89 getdtablesize | 89 | -1 | ❌ (was "fstat") |
| sc#30 accept | 30 | -1 | ❌ EBADF (was "getppid"; called with 0,0,0) |
| sc#31 getpeername | 31 | -1 | ❌ EBADF (was "geteuid") |
| sc#32 getsockname | 32 | -1 | ❌ EBADF (was "getegid") |
| sc#253 issetugid | 253 | 0 | ✅ Correct result (was "pdfork") |

## Critical Warnings
- **NEVER use `lua.read_buffer` on libkernel addresses** — crashes process (pages beyond ~0x1400 are not readable)
- **NEVER use loops >30 iterations with `native.fcall`** — too slow, causes timeouts
- **sceKernelLoadStartModule at dump+0x2bb20** is in NON-executable page — cannot call via native.fcall (SIGSEGV on instruction fetch, err=0x14)
- **Large C functions in libkernel** (beyond ~0x2800) are in non-executable data pages — syscall STUBS at offsets up to ~0x1c10 ARE callable (kevent560@0x1b50, getrandom@0x1b70, procctl@0x1950)

## AF_INET Socket Surface (NEW — q5/q6/q7, 2026-07-31) — EXHAUSTED
`socket(AF_INET, SOCK_STREAM)` **WORKS** on FW 13.52 (first socket family confirmed besides AF_UNIX). However the surface is fully hardened:
| Probe | Result |
|-------|--------|
| socket(AF_INET,STREAM/DGRAM) | ✅ Returns real fd |
| socket(AF_ROUTE=17, AF_LINK=18, AF_SYSTEM=32) | ❌ -1 (all families except INET/UNIX blocked) |
| bind(127.0.0.1:0) | ❌ -1 (sandboxed) |
| connect(127.0.0.1:80) | ❌ -1 (sandboxed) |
| SO_ERROR after failed connect | 0 — connect never reaches protocol layer |
| getsockopt IP_TTL(0,4) | ✅ 64 (REAL data, not zeroed) |
| getsockopt TCP_MAXSEG(6,2) | ✅ 536 (real default MSS) |
| getsockopt IP_TOS(0,3), PORTRANGE(0,19), RECVIF(0,20), TCP_NODELAY(6,1) | ✅ real small values |
| getsockopt IP opts 21-40, TCP opts 26-45 + 256..16387 | ❌ all -1 (incl. TCP_INFO 0x4002, TCP_FASTOPEN, TCP_FUNCTION_BLK) |
| getsockopt IPPROTO_IPV6(41) opts 1/2/3/27/48/49/51 on AF_INET socket | ❌ all -1 (pktopts path unreachable) |
| setsockopt(IP_OPTIONS,44-byte blob) | ❌ **-1 — the IPv4 analog of pktopts heap-write is BLOCKED** |
| setsockopt(IP_TTL=77) | ✅ readback 77 |
| setsockopt(SO_SNDBUF/RCVBUF 256K) | ✅ readback 262144 (full value, real accounting) |
| getsockname unconnected | ✅ len=16, all zeros (clean unnamed, no inpcb leak) |
| getpeername unconnected | ❌ -1 |

**CRITICAL**: Sony specifically hardened `ip_ctloutput` — both IPV6_PKTOPTIONS (in6p_outputopts) AND IPv4 IP_OPTIONS (inp_options) kernel-heap writes are blocked.

## net.* sysctl Tree (q8) — ENTIRELY BLOCKED
All `net.inet.*` / `net.inet6.*` sysctls return **-1** (not ENOMEM/EPERM data): tcp.pcblist(4,2,6,15), udp.pcblist(4,2,17,9), inet6 tcp.pcblist(4,41,6,15), raw.pcblist(4,2,255,9), tcp.stats(4,2,6,3), udp.stats(4,2,17,3). **No inpcb/xtcpcb kernel-pointer leak exists on this firmware** (would have been the classic KASLR bypass).

## AF_INET Probing Tooling
`probe_q1.lua` (read/write socketpair IPC — WORKS, full data channel), `probe_q2.lua` (getsockopt high-value: SO_LINGER/SO_RCVTIMEO zeroed structs, SO_LABEL/PEERLABEL/TS_CLOCK -1), `probe_q3.lua` (socket family probe — AF_INET works, others -1), `probe_q4.lua` (Sony customs 434/435 w/ buffers — both -1), `probe_q5.lua` (AF_INET bind/connect + IP 1-20/TCP 1-25 sweep), `probe_q6.lua` (IP 21-40/TCP 26-45/high const/IPV6-level sweep), `probe_q7.lua` (setters + readbacks + getsockname/peername), `probe_q8.lua` (net.inet sysctl sweep — ALL -1). All in `/data/data/com.termux/files/home/`.

## Public Scene Tracker (post-disclosure, checked 2026-07-31)
### Our publication
- **`OptiTronOffical/ps4-kernel-uaf-research-fw1352`** (GitHub, created 2026-07-24, MIT, ~3 stars/2 forks). ⚠️ Repo states "Kernel Base: FreeBSD 9" — INCORRECT per our verified ABI (vanilla FreeBSD 13.0 syscall numbering, HeerBSD build r228995).

### FreeBSD CVEs published around/after our disclosure — NONE reachable from PS4 13.52 sandbox
| CVE / Advisory | Date | Bug | Reachable on PS4 13.52? |
|----------------|------|-----|--------------------------|
| CVE-2026-58083 / SA-26:50.kqueue | 2026-07-29 | UAF in kqueue copy-on-fork (KQUEUE_CPONFORK, timer knote double-enqueue during fork) | ❌ KQUEUE_CPONFORK is FreeBSD 15-only (added ~2025-08); fork blocked anyway |
| CVE-2026-49422 / SA-26:43.tcp | 2026-06-30 | TCP RACK setsockopt lock-drop UAF | ❌ needs tcp_rack.ko + stack-switch; high TCP opts all -1 (tested) |
| CVE-2026-49412 / SA-26:29.ip6_multicast | 2026-06-09 | IPV6_MSFILTER UAF | ❌ IPv6 level blocked on AF_INET socket (tested q6) |
| CVE-2026-45251 / SA-26:19.file | 2026-05-21 | poll/select fd-close selfd UAF (missing seldrain) | ❌ needs 2 threads racing close-vs-poll; thr_create -1, ppoll -1 |
| CVE-2026-49418 / SA-26:37.vm | 2026-06-30 | device pager page-list UAF | ❌ no mmap'd device access from sandbox |
| CVE-2026-49427/28 / SA-26:44.posixshm | 2026-06-30 | POSIX largepage shm UAFs | ❌ shm_open (sc#571) absent, shm_unlink only |
| CVE-2026-7270 | 2026-05-09 | exec_args_adjust_args OOB memmove → LD_PRELOAD LPE vs sshd | ❌ no sshd/execv pattern reachable |
| CVE-2026-4747 | ~2026-06 | kgssapi.ko RPCSEC_GSS stack overflow (remote RCE) | ❌ NFS/kgssapi absent |
| CVE-2026-45250 | ~2026-05 | setcred(2) stack overflow (14.3+ syscall) | ❌ syscall absent on 13 |

### PS4/PS5 scene (post-disclosure)
- **Gezine "P2JB" (Patience to Jailbreak)** — `sys_kqueueex` ucred refcount leak → UAF (cr_ref wrap → fake ucred → double/triple free → arb R/W). **PS5-only: "PS4 kqueue does not hold ucred"** — confirms our kqueue findings on PS4. Patched at PS5 13.00. Gezine added PS4 13.52 kernel offsets to `BD-UN-JB` (commit 2026-06-19).
- **What Sony patched in 13.52** (zecoxao @notnotzecoxao + "Master", June 2026): `UVFAT_readupcasetable` integer-wrap → kernel heap corruption on 13.50; 13.52 adds pre-roundup overflow check. Gives a kernel write primitive but needs KASLR bypass to become a JB.
- **`tHefishsop/gezain_fsc2h_-0day_logic`** — speculative reconstruction of a race-induced UAF in Sony custom sc#597 (FSC2H ctrl) claimed for PS4 13.50 / PS5 13.20; unverified, third-party.
- **Vue exploit** (2026-05) — userland for PS4 12.50/12.52/13.00.
- **CSSFontFace WebKit exploit** (2026-07-29) — ufm42/DrYenyen/ntfargo/ArabPixel — PS4 ≤11.02 via built-in browser, ~20s jailbreak.
- **⚠️ SCENE UPDATE (2026-09/10, MODDED WARFARE + Andrew2007 coverage)**: **UFM42 found a WORKAROUND that makes the WebKit userland exploit reach PS4 13.52 (and PS5 ~13.40)**. The CSSFontFace bug family lives on past the 616-1300 dead-end WE proved for the original 9.00-era chain — a DIFFERENT gate/primitive bypasses it. In-scene reports confirm PS4 WebKit userland to 13.52. **A kernel exploit is still required for a jailbreak** (userland alone = no GoldHEN).
- **✅ VERIFIED LIVE (2026-09-14): WebKit userland on PS4 tops out at 13.00 in the newest public host (WebKitty @ArabPixel/WebKitty, last commit 2026-09-09).** The modern browser chain is **Slopkit** (userland, originally Jordy+Sonic-Iso for PS5, PS4 port by Raw Game) + **Netctrl** (kernel, TheFlow's Poopsploit, ported to slopkit by Egycnq) or **Lapse**: `Slopkit+Lapse 11.00-12.02`, `Slopkit+Netctrl 12.50-13.00`, `CSSFontFace+Lapse/Netctrl up to 11.02`. Local copy in `WebKitty/` (README table confirmed; `src/slopkit/ps4_offsets.js` carries `13.00` row with `k_jmp_rsi=0x47b31`, `k_sysent_661=0x110a760`, `k_kl_lock=0xe6c20` — **WebKitty 13.00 ≠ Poopsploit 13.52**: jmp_rsi differs 0x47b31 vs 0x4D6D0, so 13.52 is NOT in the public host yet).
- **⚠️ EMBARGOED BROWSER JB (user report, 2026-09-14)**: developers reportedly have a **browser-based PS4 13.52 jailbreak** that has been **privately reported to Sony** and is being **held back (not published) until Sony ships an update** — classic coordinated disclosure. Witnessed behavior: **black screen for a few seconds, then GoldHEN installs** — the known signature of userland+WebKit execution (renderer killed/restarted, then kernel payload loads). Consistent with the UFM42 workaround + a kernel payload; NOT yet public, so we cannot download/verify the exact chain. Timeline expectation: once Sony ships the next FW update, the embargo lifts and the chain becomes public.
- **🕐 SCENE MONITOR (added 2026-09-14)**: `tools/scene_monitor.sh` polls GitHub (ntfargo/CSSFontFace-Exploit, ArabPixel/WebKitty, TanKanT97/vue-after-free_TanKanTZBuild, Vuemony/vue-after-free, GoldHEN/GoldHEN, ps4-linux/ps4-linux-loader + release tags + r/ps4homebrew RSS) every pass and appends each change to `scene_watch.log` with timestamps. Run `--once` manually or `--loop` for hourly (Termux has no cron). First pass captured: WebKitty 2026-09-09, CSSFontFace-Exploit 2026-07-27, GoldHEN tag 2.3, ps4-linux-loader 2026-07-25. **Watch WebKitty first** — a "13.52" row in `ps4_offsets.js` is the public gating signal for the whole chain.
- **WebKit CSSFontFace UAF on 13.52 — ENTRY DEAD (our own 2026-08-01 investigation, parked)**: UAF + deterministic 0x100 reclaim + `m_status@0xa8` behaviorally confirmed, but `FontFaceSet::load` line 206 `wrapper()` → `FontFace::create` on the reclaimed fake B **wedges the renderer** for every non-Failure status (only Failure skips the wrapper). No `uaf_font` wrapper → `featureSettings` ARW read unreachable → 9.00 chain not portable to 616-1300. Details in FINDINGS.md "Session 3".
- **ConsoleMods Exploit Chart** (updated 2026-07-24): "13.52 or higher — no public kernel exploit exists" — **now CONTRADICTED** by the Poopsploit 13.52 offsets/shellcode in Gezine's `BD-UN-JB` (added 2026-06-19) and the working 13.52 jailbreak implied by `ps4-linux-loader` v25 (2026-07-25).

## Poopsploit 13.52 Analysis (verified 2026-07-31 from Gezine/BD-UN-JB source)
- **Poopsploit 1.8/1.9** (`payloads/poops/src/org/bdj/external/Poops.java`, 1456 lines) is a **BD-J Java app** kernel exploit (copyright Gezine + Andy Nguyen). Runs from the Blu-ray player process (BD-J), NOT the game sandbox — explains why its primitives work while our game probes failed.
- **Exploit chain**: `__sys_netcontrol` netevent ucred triple-free → IPV6_RTHDR (`pktopts` heap spray, twins/triplets overlap detection) → `kqueue` struct leak (`kq_fdp` → `fdt_ofiles`, `kl_lock` → KASLR base) → uio/iov struct reclaim (slow kread/kwrite) → pipebuf corruption (fast arb R/W) → ucred patch (uid/ruid/gid=0, `cr_sceCaps=0xFFFFFFFFFFFFFFFF`) + rootvnode → kernel code exec via `sysent[661]` hijack → `JMP_RSI_GADGET` → 13.52 shellcode.
- **13.52 offsets** (`PS4_KernelOffset.java:63`): `PRISON0=0x111fa18`, `ROOTVNODE=0x2136e90`, `SYSENT_661=0x110a760`, `JMP_RSI_GADGET=0x4D6D0`, `KL_LOCK=0xE6C60`. Kernel base computed as `kl_lock - 0xE6C60`.
- **13.52 shellcode** (`PS4_KernelOffset.java:95`): full 13.52-specific bytes (differs from 13.50), ~0x1D0 bytes, performs kernel patches (SYSENT661 kexec, permission/ACL bypass, SMAP/SMEP toggling).
- **⚠️ VERSION GATE BUG**: `Poops.java:294` rejects FW > 13.00 (`compareVersions(FW_VERSION,"13.00") > 0`) → as-shipped it would refuse 13.52 despite having the offsets. **PATCHED 2026-08-01**: upper bound changed to `"13.52"` in `/data/data/com.termux/files/usr/tmp/opencode/bd-un-jb/payloads/poops/src/org/bdj/external/Poops.java:294`. Verified `getFirmware()` yields exactly `"13.52"` (hex kern.sdk_version 0x0D.0x34) matching the `PS4_KernelOffset` 13.52 key (offsets `0x4D6D0`/`0xE6C60` + 13.52 shellcode already present). No other FW-dependent gates in the payload; PS5 gate (line 311) left unchanged (no PS5 13.x offsets). Build (`Makefile`) still requires bdj-sdk (jdk8 + enhanced-stubs/bdjstack/rt.jar + bdsigner/makefs) — not present in this environment; only the source patch is staged.
- **Cross-validation with `ps4-linux-loader` v25** (`linux/fw_offsets.h:51`): independent 13.52 kernel offsets (`printf=0x2E0510`, `kmem_alloc=0x466290`, `kernel_map=0x22D1D50`, `pstate=0x3A2B90`) — both teams have real 13.52 kernels; deltas from 13.50 (JMP_RSI +0x5b9f, KL_LOCK +0x40, printf +0xb0, kmem_alloc +0x400) confirm genuine new builds.
- **Hardware prerequisite (unmet)**: running this requires burning `BD-UN-JB` ISO to a **Blu-ray disc** (BD burner + blank BD-R) and inserting in the PS4 — the console must also be reachable on its BD-J app. No BD burner available → this path is BLOCKED on hardware, not on exploit availability.
- **In-sandbox reproduction (2026-09-11, `webkit/chain_1352.js?probe=mu`): DEFINITIVELY CLOSED — the `setuid(1)×2` dance cannot arm the netevent UAF at uid=1**. Live 2×2 matrix (slot -1 auto vs slot 1 forced × no-setuid vs `setuid(1)×2`): CLR **frees** the netevent slot with no setuid in BOTH slots (EXP2 + forced), and CLR **does NOT free** with `setuid(1)×2` in BOTH slots (attemptshape + forced) ⇒ `setuid(1)×2` at uid=1 is the **free-killer**: kernel skips the ucred refcount drop → no ucred free → no UAF → `sendmsg(0,msg,0)` iov-spray reclaims nothing → twins=0 across the whole log. This matches the reference's own gate: `chain_poops.js:1744-1750` only counts as jailbroken when `uidNow === 0` — the reference is environment-built for **BD-J uid 0**, unreachable from the uid=1 game sandbox.
- **Patch-gap sweep COMPLETE (2026-09-12, `chain_1352.js?probe=credswap&cs=<candidate>` single-candidate mode, genuine fresh boot uptsec=69): ALL setuid-family ucred-swap vectors at uid=1 are DEAD**. Fresh-boot single-candidate matrix (slot -1 armed OK, then swap attempted):
  | candidate | swap result | verdict |
  |-----------|-------------|---------|
  | `setegid(1)` | EINVAL(22) | Sony hard-blocks setegid even at same-gid |
  | `setregid(1,1)` | rv=0 | same-value no-op — no fresh ucred allocated |
  | `setgroups(1,{1})` | **EPERM(1)** | requires CAP_SETGID; refused even for owned groups |
  | `setuid(0)` | EPERM(1) | refused |
  | `setuid(1)` | rv=0 | same-value no-op |
  Netevent slot-freed oracle is unreliable across sequential candidates (each candidate's SET-again re-occupies the slot); only single-candidate mode on a fresh boot is valid. **No uid=1-capable syscall forces a fresh `crget()` → old-ucred release → netevent-held ucred free.** The netevent UAF entry requires the process to actually change uid/gid credentials, which the uid=1 sandbox cannot do. `?cs=` single-candidate + `?v=N` cache-bust (module import filename fingerprint) added to the probe for clean per-candidate testing.
- **NOCRED = `?cred=none` PURE/`?cred=reuid` — BOTH SPRAY-OK TWINS-ZERO (2026-09-14, `run_sb588b.html`), confirms Patch-gap sweep CLOSURE at the FULL-CHAIN level.** Live runs after fresh reboots with `chain_1352_live.log`: `?nosetuid=1` (20:29, pure fd-reuse path) and `?cred=reuid` (20:34, `setreuid(1,1)` swap — the ONE setuid-family member never in the 2×2) both produce: `CRED-REUID`/`NOSETUID` OK → `CLEAR-ERR5-COSMETIC` (rv=-1 errno=5 proceeds) → `UAF-ARMED` → `DOUBLE-FREE dup=276 closed` → **`TWINS-DIAGNOSTIC rounds=10 setRthdr ok=2560 fail=0 taggedReads=2560 opaq=256` = ZERO TWINS** (opaq=256 = all reads self-tagged, no foreign tag). The setRthdr/taggedReads counters prove the rthdr spray itself is 100% functional in-browser (2560/2560 sets OK, 2560 valid-tag reads); the zero `opaq<256` shows the double-free does NOT reclaim as a tag-conflicting rthdr twin. `setreuid(1,1)` at uid=1 = same-value no-op (like `setnetuid`, `setregid`): Sony's eroetbuf checks uid-change before allocating, so no fresh `crget()` → no freeable ucred → structurally identical to the `?cred=none` path. This empirically closes the CLASS of "cred-arg identical to current → forcegi ucred" swaps; the 3-decision full-chain now matches the Patch-gap sweep: **from uid=1, no userland-visible slot-free + ucred-free combination exists → ucred triple-free twins is UNREACHABLE from the browser on 13.52.** (The rthdr reclaim engine remains viable; it needs a working ucred/UAF source, which only BD-J uid-0 Poopsploit provides — see Poopsploit notes above.)
- **MISSING-PORT FOUND: pre-double-free iov-reclaim loop (`?rcl=1`, 2026-09-14).** Deep RE of `Poops.java triggerUcredTripleFree` (632-760) reveals the browser port was structurally WRONG, not just cred-gated: between `CLEAR` and `close(dup(uafSock))` the reference runs a **32× iov-reclaim loop** (`Poops.java:740-749`): `iovState.signalWork(0)` (4 IovThreads parked in `recvmsg(iovSs0, msg, 0)` with `msgIov={iov_base=1, iov_len=1}` — iov_base=1 interpreted as **`cr_refcnt`**) → `sched_yield()` → `write(iovSs1, 1 byte)` (unpark) → `waitForFinished()` → `read(iovSs0, 1 byte)`. Comment: "**Set cr_refcnt back to 1**" — this is what makes the later `close(dup())` hit a chunk whose refcount field reads 1 (refcount-driven-1), so the kernel actually frees it on the second fdrop → the chunk enters the freelist once per `dup+close` with tag-usable payload. **Our port had replaced this with a `sendmsg(sprayFd,...)×0x80` flood** (`chain_sb588.js:2483`), which does NOT park in the same iov/uio size-class allocation — hence twins=0 even when the slot/cred dance is mechanically done. FIX: added `?rcl=1` to `chain_sb588b.js` (sha `8c498a88…`) — when set, the sendmsg flood is skipped and the exact Poops 32× iov-reclaim loop runs (`fireParked` on iovWorkers pinning `recvmsg(iovSs[0], msgAddr, 0)`, `sched_yield`, `write(iovSs[1])`, `await`, `read(iovSs[0])`), logging `IOV-RECLAIM-PARKED n/4` + `IOV-RECLAIM-PRE done 32x`. This is a **new test axis**: `?rcl=1&cred=reuid` / `?rcl=1&nosetuid=1` / `?rcl=1&cred=setuid` (the free-killer default, control). NOT YET RUN (needs PS4 reboot — slots -1/1 saturated from the 20:34 run). If twins still come back zero with rcl on, THEN the Patch-gap-sweep ucred-free conclusion holds and the browser path is genuinely closed; rcl isolates the missing causal link.
- **FZERO probe correction (`chain_1352.js?probe=fd0`)**: the earlier `sendmsg(0,0,0) errno=14` line "proves fd0 is a socket" was **inverted and wrong**. FreeBSD `sys_sendmsg` copyin's the msghdr **BEFORE** fget/SO_TYPE, so `msg=NULL` returns EFAULT(14) for ANY fd. The probe was rewritten (2026-09-11) to the decisive cell: a **real msghdr** in the exact `chain_poops` reclaim shape (`msg_iov=23×` `struct iovec`, `iov[0]={base=1,len=1}` ref-replica + a clean valid-pointer shape) plus `getsockopt(0,SO_TYPE)` with real out-pointers, run on fd0 / fresh AF_UNIX stream / socketpair as controls. Readout: rv≥0 = connected socket (iov consumed), 57 ENOTCONN = unconnected socket (iov array allocated), 88 ENOTSOCK/9 EBADF = not a socket. Also fixed the `Can't find variable: SO_TYPE` crash (const out of reach in that block — literals `0xffff`/`0x3` now) and the undefined `addrOf(sp)` (replaced with a raw 8-byte buffer + `bufAddr`).

## 13.52 Shellcode Disassembly (RE done 2026-07-31, tools in `tools/`)
- **`tools/analyze_1352_shellcode.py`** — full capstone disasm of the 630-byte 13.52 shellcode; **`tools/rebuild_1352_cred_stub.py`** — byte-exact reconstruction of the embedded kernel stub; **`tools/compare_shellcode_fws.py`** — cross-FW (9.00→13.52) patch-offset matrix.
- **Kernel base derivation (CROSS-VALIDATED)**: prologue `mov ecx,0xc0000082; rdmsr; shl rdx,32; or rdx,rax; lea rcx,[rdx-0x1c0]` → `kernel_base = LSTAR − 0x1c0`. This is the SAME method as ps4-linux-loader's `get_syscall() - g_fw->xfast_syscall` (`xfast_syscall=0x1c0`) — two independent teams agree. No kl_lock leak needed for base once you have MSR read (kernel-mode only).
- **JMP_RSI encode**: `add rdx, 0x4d510` after rdx=LSTAR → `rdx = base + 0x1c0 + 0x4d510 = base + 0x4D6D0` = JMP_RSI_GADGET ✓ consistent with offset table.
- **Structure (5 parts)**: (1) base via MSR, (2) CR0.WP clear, (3) ~22 kernel .text patches (see matrix), (4) sysent-style entry `[base+0x1102d80]=2`, `[base+0x1102d88]=JMP_RSI_GADGET`, `[base+0x1102dac]=1` (stable since 12.00), (5) CR0.WP restore + `xor eax,eax; ret`.
- **⚠️ 13.00+ dropped the inline ucred self-patch**: 9.00 (0x415a43) and 12.00 (0x12555x) shellcodes embed a cred-patch stub (`cmp [r15+0x4a0],1; mov rax,[r15+0x4d0]...`); 13.00–13.52 shellcodes do NOT — the ucred is patched earlier via the kread/kwrite primitives, and the shellcode only fixes .text + sysent + returns. Reconstructed 13.52 stub in `tools/rebuild_1352_cred_stub.py` (legacy, 9.00-era layout).
- **13.52 patch cluster movement vs 13.50** (all relative to kernel base; = Sony code insertions): 0x1b7XXX family +0xa0, 0x2bdXXX family +0xa0, 0x391XXX +0x400, 0x628XXX +0x400, JMP_RSI +0x5b9f, KL_LOCK +0x40, printf +0xb0, kmem_alloc +0x400. Non-uniform deltas = multiple real code changes, not relabeling.
- **Stable-across-everything (9.00→13.52)**: security-check patches at 0x490, 0x4b5, 0x4b9, 0x4c2, 0xacd (never moved in 6 years of FWs).
- **27 patches in 13.52**: 14× `0xeb` (branch→`jmp +0/+4` always-taken, neuters permission checks), 2× `0x37` bytes, 1× `xor eax,eax; ret` stub @0x3be110 (`48 31 c0 c3`), 4× `0x4eb` words, sysent triple, misc data writes (incl. dword `0x13ce990` @0x1b7818 — purpose unknown without kernel dump).

## Next Steps — CORRECTED ASSESSMENT (2026-08-01, FINAL)
Live probing is **comprehensive and complete** for the GAME sandbox: sysctl (kern/hw/machdep/vm sanitized, net.* blocked), kevent (STD#560 registers but NEVER delivers, COMPAT11 delivers with data sanitized + ext[4]=0), fstat STD#551 (blocked on ALL fds), getrandom #563 (blocked), AF_UNIX socketpair (IPC only, SCM_RIGHTS/bind/listen blocked), AF_INET socket (basics only, IP_OPTIONS/IPV6_PKTOPTIONS heap-writes blocked), threads (thr_create -1), procctl/ppoll/cap_* (all -1), Sony customs 434/435/585-677 (-1 or crash), mmap W^X (enforced), **/dev external fds** (game-side open: ioctls all -1, no leaks) + **/dev internal fds** (libkernel-cached fds 5/6/7: only `release_direct_memory` 0x80108002 + a fixed 16MB writable kernel-dmap DMA-descriptor window work; all query/leak ioctls -1; window = frozen GPU state snapshot, not a privilege-relevant struct). **CONCLUSION: no reachable kernel vulnerability from the game process; but the SAME vulns are reachable from BD-J (Poopsploit 1.8/1.9), which is confirmed working for 13.52.** Remaining options:
1. **BD-J route** — patch Poopsploit version gate + build `poops.jar` with bdj-sdk + assemble BD-UN-JB ISO → requires a Blu-ray burner (hardware not available). If obtained: full kernel R/W on 13.52, then dump kernel + RE Sony customs.
2. **Offline research** — 13.52 PUP is fully AES-encrypted (SLB2 container, no extractable kernel, keys not public). Parallel: RE the new Poopsploit 13.52 shellcode + offsets, match kernel source r228995, libkernel diffing, or a different entry point (save-data format, boot chain). WebKit CSSFontFace entry is **closed** (parked 2026-08-01, see FINDINGS.md Session 3).
3. **⚠️ EMBARGOED BROWSER JB — NOW THE LEADING HOPE (2026-09-14, user report + scene confirmation)**: a **browser/userland WebKit chain for 13.52 reportedly EXISTS but is privately held (reported to Sony, to be published after next FW)**. Our `?rcl=1` (2026-09-14) proves *userland triple-free via netevent ucred* is still UNREACHABLE from the browser at uid=1 — but the UFM42 CSSFontFace WORKAROUND reaches **WebKit userland (ARW + ROP) on 13.52**, which is the RENDERER-level primitive that the embargoed chain uses before a kernel payload loads (black screen = renderer killed/restarted → GoldHEN). Practical plan: (a) keep unpublished—cannot download; (b) when the embargo lifts after Sony's next FW, validate/port the workaround; (c) meanwhile, our libkernel/syscall/ASLR tooling map cleanly onto any userland ROP that needs syscall access (socket, AF_UNIX, mmap, native fcall).
4. **Monitor the public chain weekly (NEW, 2026-09-14)**: run `tools/scene_monitor.sh --once` on each session (or `--loop` hourly) and read `scene_watch.log`. The **gating signal is WebKitty's `ps4_offsets.js` gaining a `"13.52"` row** — slopkit/WebKitty already reaches 13.00 and the kernel offsets for 13.52 are known (Poopsploit 0x4D6D0); the missing piece is the UFM42 WebKit WORKAROUND in a public file. The moment a 13.52 row lands, we can verify the chain end-to-end offline and via our live probes.

## Browser netevent Command Surface (NEW, 2026-09-14) — evscan + short links
- **KEY FACT from `WebKitty/src/slopkit/chain_poops.js:842-859`**: the browser chain (working to 13.00) arms the ucred UAF with EXACTLY the same `netevent(dummy, SET_QUEUE) → close → setuid(1) → socket-reclaim → setuid(1) → CLEAR` sequence as Poops. **⚠️ REVISED READING (2026-09-14 after user pushback): the 13.00-working browser chain at uid=1 uses `setuid(1)×2` UNCONDITIONALLY and reaches twins — therefore `setuid(1)` at uid=1 is NOT a no-op free-killer by itself, and our "13.52 hardened setuid" attribution is CONTESTED. The 2×2/credswap/rcl closure results may reflect a PORT DIVERGENCE (e.g. `setreuid(1,1)` vs reference `setuid(1)`; `spraySockpair` vs reference `sendmsg(fd0)`; slot-1 fallback vs reference auto-slot -1), NOT a firmware change. Do NOT treat the netevent browser path as closed until `?probe=verbatim` (below) is run on a fresh boot. ⚠️ **fd0-BINDING RESOLVED (2026-09-14 live)**: fd0 was NEVER special — `chain_poops.js:866` sprays `sendmsg(iovSs[0],…)` and fd0 was 0 only because that webview's first socketpair landed at 0/1. In OUR renderer fd0 is an unclosable non-socket (`close(0)=-1`), but `iovSs[0]` IS the same connected socketpair the reference uses — so verbatim now sprays `iovSs[0]` directly. The 2×2/credswap 'closure' narrative was fd-space-blind and is NOT re-proved until this runs.**
- **`?probe=evscan` (added to `chain_sb588d_rcl.js`, 2026-09-14)**: sweeps netcontrol events `0x20000000..0x2000003F` × first-arg slots `{-1,0,1,2}` on fresh AF_UNIX sockets, logging any `rv==0` (live undocumented cmd) vs -1. A mid-scan renderer kill itself pinpoints the lethal event. Rationale: if any event pins/frees a socket+ucred ref WITHOUT requiring the setuid(1)x2 no-op, the 13.52 browser chain re-opens. **`rebootRequired=live.length>0`** — a success dirties the netevent slot.
- **`?probe=verbatim` (2026-09-14, chain_sb588f.js via short link `/v`)**: BYTE-EXACT REPLICA of `chain_poops.js:840-880` with NONE of our port substitutions — `netcontrol(-1,…)` auto-slot (no slot-1 fallback), `setuid(1)×2` unconditionally (no CRED variant), `sendmsg(0,msgAddr,0)×0x80` on fd0, then `dup/close` + `findTwins`. **⚠️ 22:44 RUN RESULT — INVALIDATED BY fd0**: `VB start fd0IsSocket=0` → `sendmsg(0,…)` failed **128/128** (`SPRAY fd0 first=-1 fail=128/0x80`) → the reclaim spray allocated **nothing** (ENOTSOCK fails before uio/iov alloc), so `TWINS-DIAGNOSTIC opaq=256` (zero twins) is **structurally meaningless** regardless of whether the ucred UAF armed. **Root cause: the reference env (13.00-working) has fd0 = a real CONNECTED AF_UNIX socket (first socketpair takes 0/1 since stdio fds are closed in that webview); our 13.52 renderer has fd0 taken by a non-socket.** This is an fd-table layout difference, NOT proof of kernel hardening. This single fact also clears `spraySockpair` — it was a NECESSARY port adaptation (providing a real spray socket), not a divergence bug. **REVISED FIX (chain_sb588f.js)**: `close(0)` returned **-1** live — fd0 is NOT closable in our renderer, and a fresh socketpair lands at 274/275 (not 0), so "rebind fd0" was wrong-headed. The REAL reference mechanism is not fd0-specific at all: `chain_poops.js:866` is `sendmsg(iovSs[0], msgAddr, 0)` — fd0 was 0 ONLY because iovSs happened to land at 0/1 in that webview. The correct faithful port is to spray on **`iovSs[0]` directly** (same connected socketpair end the reference later parks recvmsg workers on at chain_poops.js:898, and that our port already uses at sb588f.js:2681+ for fireW). **Decisive readout on fresh boot**: `twins!=null` → port was never the issue, reference logic works at uid=1, and our prior 2×2/credswap closure narrative was fd-space-blind; `twins==null` with a WORKING spray → arming genuinely fails at 13.52 uid=1.** ⚠️ **23:13 RUN (spray=iovSs[0]=fd9, fresh boot)**: `SPRAY fd=9 first=-1 fail=128/0x80` — the reclaim spray **failed ENTIRELY even on the real connected socketpair end** `iovSs[0]`. So the failure is NOT fd-space: `sendmsg` on a genuine AF_UNIX stream socket returns error. This implicates `msgAddr` itself (msghdr/iov shape) or the sendmsg PATH being blocked, not the fd. Next probe logs `SO_TYPE` + `sendmsg#0 errno` to pin the exact errno.** ⚠️ **23:27 RUN (chain_sb588h.js)**: reached `spray fd=9` but crashed on the SO_TYPE diagnostic — `STEP10-FAILED Out of bounds access` (the `argDv.getUint32(8)` on a `new ArrayBuffer(8)` — `argAb`/`fdAb` are only 8 bytes, offset+8 reads past). Diag moved to a local 16-byte `sotAb` buffer (`chain_sb588i.js`, `/v` now serves this). Still awaiting the `SO_TYPE + sendmsg#0 errno` decisive readout.** ⚠️ **23:34 RUN (chain_sb588i.js, confirmed served fresh)**: STILL `STEP10-FAILED Out of bounds access` AFTER `[VB] spray fd=9` with NO `DIAG`/`SO_TYPE`/`sendmsg#0` lines logged — so the crash is inside the SO_TYPE block itself, not the buffer size (16-byte `sotAb` is structurally fine). Candidates: `sc(get-getsockopt)` ROP path, `bufAddr(sotAb)` leakval, or `errno()`. **chain_sb588j.js** adds granular `DIAG` markers (sotAb/keepAlive, sotAddr/bufAddr, post-SO_TYPE, sendmsg#0 try/catch) to pin the exact throwing line.** ⚠️ SERVER RESTART GOTCHA (2026-09-14): `kill $(pgrep -f serve_chain.py | head -1)` can kill the WRONG pid or the `pgrep` itself; the old server stays on 8080 and `setsid` fails silently to bind (timeout). Do kill+verify (`pgrep ... || echo ALL-DEAD`) in a SEPARATE bash call, THEN `setsid nohup ...` in a fresh call.
- **EVENT-NAMESPACE RESULT (live, 2026-09-14, `evscan` + `ev10` probes)**: the netevent cmd space is now EXHAUSTED. `evscan` (0x20000000..0x3F × slots {-1,0,1,2}) + `ev10` (0x20000008..0x1F + groups 0x20010000/0x20020000/0x21000000/0x22000000/0x30000000/0x60000000 × slot 1, with ARG-WROTE leak detection) are complete: **only THREE cmds live — `0x20000003` (SET_QUEUE, known), `0x20000007` (CLEAR_QUEUE, known), and `0x20000010` (NEW, `rv=0 err=0`, NO arg write = NOT a leak)**. Every other event in the whole tested namespace → `err=22` EINVAL. **Verdict: the "undocumented netevent command that frees a ucred without setuid" HYPOTHESIS IS DEAD** — no such cmd exists; `0x20000010` is a silent queue-register (rv=0, no data out), and it does NOT bypass the setuid(1)x2 gate. **This verdict holds REGARDLESS of the port-divergence question above** — but the "netevent unreachable on 13.52" conclusion needs `?probe=verbatim` before it is treated as final; the reference path itself (slot -1 only, `setuid(1)` only, `sendmsg(fd0)` only) has NOT been replicated exactly until now.
- **SHORT LINKS for the PS4 address bar** (`serve_chain.py`, 302 table):
  | Key | Redirect | What it runs |
  |-----|----------|--------------|
  | `http://192.168.100.2:8080/e` | `run_sb588d.html?probe=evscan` | event-namespace scan |
  | `http://192.168.100.2:8080/x` | `run_sb588d.html?rcl=1&cred=reuid` | full chain, reuid path |
  | `http://192.168.100.2:8080/s` | `run_sb588d.html?stop=beforedouble` | arm-only + stop (observes CLEAR/slot) |
  | `http://192.168.100.2:8080/m` | `run_sb588d.html?probe=mu` | auto/forced slot matrix |
  | `http://192.168.100.2:8080/n` | `run_sb588d.html?probe=netevent` | slot-free decisive |
  | `http://192.168.100.2:8080/c` | `run_sb588d.html?probe=cs` | cred-swap sweep |
  | `http://192.168.100.2:8080/t` | `run_sb588d.html?probe=ev10` | live-event 0x20000010 |
  | `http://192.168.100.2:8080/v` | `run_sb588k.html?probe=verbatim` | verbatim chain, **spray=iovSs[0] + SO_TYPE/errno diag** (fresh module) |
  | `http://192.168.100.2:8080/g` | `/` | landing page |
  (All redirect to `run_sb588d.html`/`run_sb588i.html`; extra query params pass through.)

**CLOSED 2026-07-31 (q24-q26)**: the last remaining live avenue — a universal syscall trampoline via `fcall_with_rax` (stub+7/+10) to reach hidden syscalls 678+ — is **definitively dead**. Kernel RCX-12 stub-validation (confirmed live: matching-RAX getpid=996 works, mismatched getuid kills the process) plus the offline proof that all 306 `0f 05` sites in libkernel are fixed-imm32 stubs with zero register-driven syscall gadgets means every syscall number is only reachable through its own stub.

**CLOSED 2026-08-01 (probe_dev_r9f..r9ao)**: the /dev dmem0 path is **definitively closed after the internal-fd breakthrough was taken as far as it goes AND the window fully decoded**. The libkernel-internal dmem0 fd (fd=5) bypasses the game-sandbox ioctl filter for the `release_direct_memory` path only, giving a **persistent kernel-dmap write** into a fixed 16MB window (phys 0x2ec48000) plus fixed kernel dmap VA leaks (`0xffffffff2ec48000` self, `0xffffffff00000000` base ×2) — but no arbitrary-phys mapping, no window expansion, no DMA redirect (window = **frozen GPU-state snapshot**: descriptor + GPU VM table + 47-record command-submission ring + resident PM4/GCN code; liveness-tested = 0 changes across re-arms → GPU injection INERT), and all query/leak ioctls (`direct_memory_query` 0x80288012, `get_direct_memory_type` 0xc0208004) are filtered (-1). Remaining untested leads (kevent STD #560, fstat STD #551, getrandom #563) all executed → closed. **Not a privilege-escalation primitive. The game-sandbox live-probe phase is COMPLETE on every axis**; further progress requires either BD-J hardware (Poopsploit 1.8/1.9) or offline research.
