# PS4 FW 13.52 Exploit Research - FINDINGS.md

## Project Status: FULL LUA FRAMEWORK MAPPED — Kernel R/W not achieved

## Session 1 (2026-07-18): Discovery & Analysis

### Discovered: Pre-loaded PS4 Exploitation Framework
The game "Hamidashi Creative" on FW 13.52 has a full PS4 exploitation framework pre-loaded at `/savedata0/` — 21 Lua files (~5000 lines total) spanning multiple projects:
- **kernel_offset.lua** — FW-specific kernel data offsets (supports PS4 FW 9.00-12.02 only, NOT 13.52)
- **kernel.lua** — IPv6 pktopts exploit + kernel R/W class (470 lines)
- **gpu.lua** — GPU DMA via PM4 packets (400 lines, requires bootstrap kernel R/W)
- **lua.lua** — Fake string primitive userspace R/W via Lua internals
- **offsets.lua** — ROP gadgets for HamidashiCreative + other VNs (1302 lines)
- **native.lua** — ROP-based C function calling mechanism
- **syscall.lua** — Syscall wrapper table + dispatch functions
- **misc.lua** — Utility functions: file I/O, dlsym, crc32, storage (528 lines)

### Key Globals Available in Lua Environment
- `memory` — Allocate/read/write userspace memory
- `syscall.syscall_wrapper` — Table mapping syscall# → uint64 (function pointer to `mov eax, N; syscall; ret`)
- `sysctlbyname` — Call sysctl by name (works for basic sysctls)
- `native.fcall` — Call native C functions via ROP chains (with longjmp recovery)
- `lua` table — Lua VM exploit primitives (fakeobj, write_qword, read_buffer, etc.)
- `fcall` — Full ROP chain builder (sets rdi, rsi, rdx, rcx, r8, r9 before calling)
- `native.write_buffer` / `native.read_buffer` — Userspace memory R/W via ROP
- `eboot_base`, `libc_base`, `libkernel_base` — Base addresses (uint64)
- `PLATFORM = "ps4"`, `FW_VERSION = "13.52"`
- `find_mod_by_name`, `dlsym` — Present but blocked by sandbox

### Syscall Testing Results
| Syscall | Num | Result |
|---------|-----|--------|
| getpid  | 20  | ✓ Returns PID (varies per session) |
| getuid  | 24  | ✓ Returns 1 (non-root) |
| is_in_sandbox | 585 | ✓ Returns 1 (IN sandbox) |
| mmap (prot=7) | 477 | ✓ Allocates RW MEMORY (W^X strips exec) |
| mprotect | 74 | ✓ Callable, but W^X enforcement blocks RWX |
| dlsym | 591 | ✗ Returns -1 (sandboxed) |
| dynlib_load_prx | 594 | ✗ Returns -1 (sandboxed) |
| dynlib_unload_prx | 595 | ✗ Returns -1 |
| sysctl | 202 | ✓ Works (read basic sysctls) |
| 586-588, 592-593, 596-602 | — | ✓ Callable, return -1 with 0 args |

### Memory Security Analysis
- **W^X is STRICTLY ENFORCED**: mmap with PROT_EXEC returns non-executable pages (NX bit set)
- **mprotect cannot add PROT_EXEC**: W^X prevents adding execute to writable pages
- **mprotect cannot add PROT_WRITE to executable pages**: Cannot write to libkernel .text (SIGSEGV)
- **No W+X pages exist** in the process (JIT not available for game applications)

### Libkernel Binary Analysis (576KB dump)
- **Build path**: `W:\Build\J02697906\sys\internal\usermode\src\libkernel\`
- **Base address**: 0x813758000 (varies per session due to ASLR)
- **Content**: Pthread implementation, syscall wrappers, module loading, process init
- **Notable strings found**:
  - `machdep.rcmgr_utoken_weakened_port_restriction` — Security-sensitive sysctl
  - `NPXS2101H3E` — Module/SDK identifier
  - `dipsw` — Developer kit dip switch operations
  - `Failed to get appinfo` — Application info retrieval
  - `kern.sched.cpusetsize`, `kern.usrstack` — Sysctl names
  - `[ERR] initialization of sceKernelIcc* APIs failed` — Sony custom API
  - Title-specific workaround checks (201910, 210925)
- **NOP sleds found**: Multiple function alignment regions (0x464, 0x4b2, etc.)

### Shellcode Execution Attempts
1. ❌ mmap(RWX) → NX enforced at kernel level
2. ❌ Write to libkernel code pages → SIGSEGV (page not writable)
3. ❌ mprotect(RW) → Write shellcode → mprotect(RX) → W^X prevents cycle
4. ✅ ROP chains work via existing executable code (libc gadgets)

### Critical Observations
- `sysctlbyname()` works but `machdep.rcmgr_*` sysctls crash the process (kernel-level access only)
- `check_jailbroken()` throws Lua error "process is not jailbroken"
- `is_jailbroken()` returns false
- `is_kernel_rw_available()` returns false
- The framework's kernel exploits target FW 9.00-12.02 only — 13.52 is not supported
- GPU DMA requires bootstrap kernel R/W (chicken-and-egg)
- Game crashes frequently; each crash requires full PS4 restart

### Exploit Vectors Tested (ALL FAILED)
| Vector | Status | Reason |
|--------|--------|--------|
| FSC2H (SC597) | ❌ REMOVED | Wrapper + kernel handler removed in 13.52 |
| Sony anti-check bypass | ❌ BLOCKED | All 302 wrappers use `mov rax,imm32`; no `mov eax` exists |
| Trampoline (wrapper+7) | ❌ BLOCKED | Kernel reads RCX-12; RAX mismatch hangs |
| Syscall fuzzing (585-677) | ❌ NO RESULTS | All return -1; no buffer writes, crashes, or info leaks |
| Lapse (CVE-2020-7460) | ❌ N/A | No compat32 layer in PS4 kernel; no `int 0x80`/`sysenter` |
| Game binary exploit | ❌ NO RESULTS | Commercial VN; no custom kernel services |
| machdep.rcmgr sysctls | ❌ CRASH | Kernel-level only; crash on read |
| kern.cpumode write | ❌ READ-ONLY | Write returns false |
| dlsym/dynlib_load_prx | ❌ SANDBOXED | All return -1 |
| W^X bypass | ❌ ENFORCED | No shellcode execution possible |
| GPU DMA | ❌ BLOCKED | Requires bootstrap kernel R/W (chicken-and-egg) |
| WebKit CSSFontFace UAF | ⏳ PARTIAL | Gives userland only; kernel exploit still needed |

### Session 2 (2026-07-23): Syscall Probing & UMTX_SHM

#### CRITICAL: UMTX_SHM Does NOT Exist on PS4 FW 13.52
- **op=26 (PS5 convention) → EINVAL (22)**
- **op=1 returns constant 1** — this is stdout (fd=1), NOT a UMTX SHM handle
- **All previous "confirmed working" UMTX calls were WRONG** — used shifted args via `fcall_rax` (bug: rax arg gets overwritten by wrapper)
- **CVE-2024-43102 exploit path is DEAD for PS4 FW 13.52**

#### CRITICAL: fcall_with_rax Argument Shift Bug
- `native.fcall_with_rax(fn, rax, rdi, rsi, rdx, rcx, r8, r9)` — 8 args, 2nd is `rax`
- But the wrapper does `mov rax, imm32` which OVERWRITES rax
- Correct convention: `native.fcall(fn, rdi, rsi, rdx, rcx)` — 7 args, rax=nil→0→overwritten

#### Sony-Specific Syscalls (550-600)
- **~30 Sony syscalls exist**: 550-560, 563-567, 572, 585-588, 591-596, 598-600
- Most return -1 with zero args
- **sc=585**: Always returns 1 (capability flag or no-op)
- **sc=557**: Returns 8415 (0x20DF) — might be version/feature identifier
- **sc=592 (`sys_dynlib_get_list`)**: WORKS! Returns 39 module handles (small opaque IDs, NOT addresses)
- **sc=598 (`sys_dynlib_get_proc_param`)**: WORKS! Returns 96 bytes (mostly zeros)
- **sc=593 (`sys_dynlib_get_info`)**: Returns -1 for ALL prototype variations — cannot resolve module handles
- **sc=594 (`sys_dynlib_load_prx`)**: Returns -1 (sandboxed)
- Scanning 500-550 **crashes the PS4** — some syscalls in this range are dangerous

#### KERN_PROC_ALL (sysctl) — Kernel Pointers Scrubbed
- Returns 12056 bytes of process data (struct size = 1096 bytes per process)
- Process names: "SceLibc_Thr", "eboot.bin", "ORBIS kernel SEL.default", "SceVideoOutServi", "SceUserServiceEv"
- **Sony has scrubbed ALL kernel pointers** — only `0xffffffff00000000` placeholders remain
- KERN_PROC_PID, KERN_PROC_PATHNAME, kern.conftxt, kern.features, kern.boottime, kern.usrstack ALL fail (ret=-1)

#### Confirmed Syscall Numbers (PS4 FW 13.52)
| Syscall | Num | Result |
|---------|-----|--------|
| fork    | 241 | ✅ Returns 0 in child |
| thr_new | 455 | ✅ Returns 0, thread alive |
| sys_dynlib_get_list | 592 | ✅ Returns module handles |
| sys_dynlib_get_proc_param | 598 | ✅ Returns 96 bytes |
| sysctl  | 202 | ✅ KERN_PROC_ALL works |
| sched_yield | 331 | ✅ (NOT 330) |
| socket(AF_INET6,SOCK_RAW,UDP) | 97 | ✅ Only SOCK_RAW works |
| fstat  | 189 | ⚠️ CAUSES KERNEL CRASH |
| fork   | 241 | ✅ Works |

### Conclusion
**PS4 FW 13.52 has no publicly known kernel exploit.** UMTX_SHM doesn't exist, Lapse is patched, BPF is inaccessible, and KERN_PROC kernel pointers are scrubbed. A new vulnerability must be found in one of the ~30 Sony-specific syscalls (550-600 range) or through kevent/kqueue exploitation.

### Tools Created
- `/data/data/com.termux/files/home/PS4-Kernel-Research-FW1352/poc/` — Collection of Lua payloads
- `send_lua.py` — TCP-based payload sender to PS4 Remote Lua Loader
- `alive_check.lua` — Simple connectivity test
- `dump_small.lua` → `dump_progress.lua` → `send_binary.lua` — Libkernel dump pipeline
- `read_sysctls_final.lua` — Safe sysctl reader
- `test_native_fcall.lua` — Native function call tester
- `test_shellcode.lua` / `test_shellcode2.lua` — Shellcode execution attempts
- `test_mmap.lua` — mmap/mprotect tester
- `fuzz_fast.lua` — Basic syscall fuzzer
- `explore_*.lua` — Various environment exploration scripts

### Radare2 Setup
- Installed and configured in Termux
- Libkernel loaded as raw x86-64 binary (no ELF header)
- Full analysis (`aaaa`) identifies functions
- Strings extracted (4300 entries), function list available

Built on: W:\Build\J02697906
Remote Lua Loader port: 9026 (unstable, game must be running)

## NEW: /dev/dmem0 Direct-Memory Discovery (2026-08-01, probes r9f-r9s) — BREAKTHROUGH

### Critical discovery: libkernel-internal device fds bypass the game-sandbox ioctl filter
- Game-side `S.open("/dev/dmem0",2)` returns fd=22, but ioctl on it ALWAYS returns -1 (the
  loader's sandbox wrapper filters ioctls on fds opened through its own S.open).
- libkernel-internal device fds (cached in libkernel globals at init) are REAL: fd=5
  (dmem0, global @ libk+0x58038+8 = 5) and fd=6 accept ioctl 0x2000800b → ret 0, and **mmap works**.
- fd=14 → constant 0x8037F284 on all ioctls (fixed bogus error). fds 5/6 stable; 23/24/29/30 transient.
- **fd=7 accepts ioctl 0x4010a802 → ret 0** (the "leak" ioctl used by libkernel fn 0x19e80).

### Confirmed: libkernel C functions are EXECUTABLE via native.fcall (region up to 0x22700)
- `libk_base = S.open.fn_addr - 0x2750` (syscall-open stub offset). 0x82b504000 / 0x8196d4000 across boots.
- Device open-fns all callable: dmem0@0x18210, dipsw@0x19810, gbase@0x1d400, dce@0x1deb0,
  notification@0x1a470, icc@0x1f930, srtc@0x21a90, sbi@0x226c0, leak-fn@0x19e80.
- Internal-open results: dipsw = 0 (success!), srtc = 0x800f0513 (denied), sbi = 0x80020002,
  gbase = 0x80020013, dce/dmem0 = 0x80020001, notification = garbage string.
- leak-fn 0x19e80: ret=0 but 16B output SCRUBBED to zeros (kernel zeroes it for sandboxed procs).

### BREAKTHROUGH: /dev/dmem0 fd=5 gives a REAL persistent writable mmap + kernel pointer leak
- `mmap(fd5, 0x1000000, PROT_RW=3, MAP_SHARED=0x0001, offset=0)` succeeds (0x311xxxx000).
- Descriptor table at map+0x0 (ONE-SHOT per game boot — first 16MB mmap(s) only):
  - +0x00: `0x80000000c0012800`
  - +0x10: `0xc005580000000000`
  - +0x18: `0xffffffff2ec48000` ← **KERNEL DMAP-RANGE POINTER LEAK (kernel VA in 0xffffffff00000000 range)**
  - +0x30..+0xa0: descriptor entries `0x000000<len>c0027600` (len 0x8,0x48,0xc8,0x108,0x148,0x88,0x20c; +0xa0 `0x00000218c0017600`) — phys base ≈0xc0027600
  - +0xa8: `0xc010760000000000`; +0xb0: `0x0000000000000240`
- Structure IDENTICAL across boots (stable kernel-desc). Only first ~1MB non-zero; rest zeros.
- **Writes are PERSISTENT** (write→readback OK; two mmaps of same offset SHARE the same physical
  region — write via m1 visible via m2).
- **mmap offset ≠ physical address**: writing at offset 0x800000 map is NOT visible at map+0x800000.
  Offsets 0x1000000/0x40000000/0x2ec48000/0xc0027600 → all-zero content.
- ⚠️ Lua double-precision (53-bit) rounding corrupts 64-bit values > 2^53 on write AND read — NOT a
  hardware window truncation. Use uint64 {h,l} table format or byte writes for exact 64-bit.

### ioctl 0x80108002 = IOC_IN struct-set (264B read from user buffer, only qw0/qw1 used)
- libkernel wrapper @0x17800: `func(a1,a2) { ioctl(fd_global_0x58038, 0x80108002, {a1,a2}) }`.
- qw0/qw1 validation rule (empirically): qw0 must satisfy alignment-ish pattern —
  PASS: 0x100000, 0x10000000, 0x40000000, 0x80000000, 0x100000000, 0x2ec48000
  FAIL: 0xFFFFF, 0x100001, 0x3FFFFFFF, 0x7FFFFFFF, 0xBFFFFFFF, 0xFFFFFFFF, 0x1000, 0xc0027600
- **ioctl(5, 0x80108002, {0x2ec48000, 0x100000}) → ret 0** (safe), then mmap@0 → -1 (device state changed).
- **ioctl(5, 0x80108002, {0x100000, 0x100000}) → CRASHES the game** (r9s, loader died, needed PS4 restart).
- ⚠️ CRASH RULE confirmed again: only VOID(0x2xxxxxxx) and small OUT ioctls are safe; the IN struct
  ioctls with non-zero size args are LETHAL. dmem0 IN-ioctl surface = KILL SWITCH from game sandbox.
- OUT ioctls on fd5/6 (0x80108002-family "OUT" calls, 0x80108015) return 0 and write only the low
  16 bits of the buffer (0xd000/0xa800 = prefill-dependent, NOT a stable leak).

### Interpretation
- dmem0 is the "direct memory" device: maps a writable system-RAM region (phys base ≈0xc0027600)
  shared with the GPU/SoC, exposing a DMA descriptor table + kernel dmap pointer. Confirms the
  region IS kernel-managed RAM (dmap 0xffffffff2ec48000 → phys 0x2ec48000 at dmap base 0xffffffff00000000).
- The ioctl 0x80108002 with {base,size} changes the device mapping state (mmap subsequently fails /
  crashes) → NO reliable arbitrary-physical-mapping primitive obtained from the game sandbox; the
  ioctl is effectively a kill-switch. Descriptor-table DMA-redirection (fake DMA descriptors) is the
  remaining theoretical path but requires the one-shot descriptor + a DMA trigger (unknown, risky).
- **Bottom line**: the game process now has a confirmed kernel-VA leak (0xffffffff2ec48000) and a
  persistent writable device-RAM window, but no controllable physical-address primitive. Further
  escalation (fake descriptor DMA, ioctl struct reverse-engineering of the kernel driver) needs
  either the kernel driver dump (not available — PUP is AES-encrypted) or a different entry point.

### Probe scripts
- `probe_dev_r9f.lua`..`probe_dev_r9s.lua` (session_2026_jul28/) — full probe chain, r9s = final crash test.
- Rule: never ioctl IN/INOUT struct sweeps on unknown fds; keep loops ≤32; every crash costs a PS4 restart.
