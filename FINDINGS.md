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

### Session 3 (2026-07-31): WebKit CSSFontFace UAF (13.52) — ENTRY BLOCKED, CHAIN PARKED

**Objective**: Port the 9.00 CSSFontFace UAF chain (`CSSFontFace-Exploit` reference, WebKit-616 source cross-check) to the 13.52 WebKit for a userland R/W primitive.

#### CONFIRMED WORKING on 13.52
- **UAF**: rule-backed font B freed while still referenced by `FontFaceSet`'s `m_facesLookupTable` (v17/v20 mechanics, matches 9.00 reference `userland.mjs:938-951`).
- **Deterministic reclaim**: direct single `deleteRule(uaf_idx)` + spray of 0x100-byte ABs (refcount=1n@8, byte at target offset) reliably reclaims B's chunk.
- **`sizeof(CSSFontFace) = 0x100`** (behavioral): only 0x100 spray reclaims; 0x140/0x160/0x180 → no reclaim.
- **`m_status` @ 0xa8** (behavioral): val=4 (Failure) → `document.fonts.load()` returns then async-crashes (Failure-skip reject path, no wrapper); val=3 (Success) → renderer wedge. Different enum at same offset = distinct behavior = confirmed field.
- **616-era layout** (source-derived, Sony `WebKit-616-1300.zip`): vptr@0, refcount@8, m_propertiesOrCSSConnection@0x08, m_families@0x18, m_ranges@0x20, m_featureSettings@0x38 (inline Vector: buffer/size/capacity), m_sources@0x58, m_clients@0x70 (WeakHashSet, 24B), m_wrapper@0x88, m_fontSelectionCapabilities@0x90, m_status@0xa8, bools@0xa9-0xac, m_loadingBehavior@0xad, Timer m_timeoutTimer@0xb0, sizeof=0x100. 9.00 offsets (status@0x82, sizeof 0xb8) do NOT apply.

#### ROOT CAUSE — ENTRY DEAD on 13.52
- `FontFaceSet::load` (FontFaceSet.cpp:153) calls `face.get().wrapper()` (line 206) for **every** matching face — Success/Pending/Loading/TimedOut all reach it. Only Failure skips it (earlier reject loop, lines 193-196).
- `wrapper()` → `CSSFontFace::wrapper()` → `FontFace::create(context, *this)` on the reclaimed fake B **wedges the renderer** (5 min, then watchdog death) for every status that reaches it. Source model says the constructor (refcount bump, `addClient`→WeakHashSet::add on zeroed set, `LoadedPromise`, `suspendIfNeeded`) should be safe — the fatal path is deeper (JSC wrapper creation/GC), but empirically consistent and reproducible.
- **Consequence**: no JS `FontFace` wrapper (`uaf_font`) can be bound to fake B → `featureSettings` ARW read unreachable. Writes to B's chunk work without a wrapper (via owning AB), but the reference chain needs the read.
- v18 (FontFaceSet iterator) closed: B is removed from `m_faces` at rule-delete, so iteration never sees it (lookup table keeps it stale for matching only).
- v19 (1024-AB spray) always crashes collaterally; 128-AB spray flaky.

#### OTHER DATA
- Probe framework: `poc/browser_agent.html` + `agent_v17..v20.html` deployed at `http://127.0.0.1:8080/agent_v*.html` (`serve_cve.py`); `/enqueue` /`/poll` /`/results` /`/log` /`/clearlog`. Free/reclaim/spray/`document.fonts.load` signals COMPLETED/REJECTED/HUNG per family; refcount-2 detector; 8s HUNG timer; page self-reloads after renderer crash (`PAGE:new:<token>`); BEAT heartbeats.
- Authoritative source: Sony OSS PS4 page → `WebKit-616-1300.zip` (extracted `/data/data/com.termux/files/usr/tmp/opencode/sony616/`).

#### STATUS: PARKED (decision 2026-08-01)
9.00-style entry not portable to 616-1300. WebKit CSSFontFace on 13.52 = userland-only would-be anyway; kernel exploit still required. Returned to main tracks (BD-J Poopsploit 13.52 / offline PUP+shellcode research). To resume: would need a wrapper-free ARW read (e.g. FontRanges/`check()` deref) or a different 13.52-reachable UAF where the freed object is JS-visible.

### Session 4 (2026-08-01): /dev/dmem0 + /dev/dce Live Device Probing — CLOSED

**Objective**: Confirm the last untested kernel-reachable surface from the game sandbox — direct-memory device `/dev/dmem0` and GPU `/dev/dce` — after re-opening the game loader (port 9026).

**Method evolution (probe_dev_r1..r12.lua in `session_2026_jul28/`)**:
- R1: `open` + raw `read(dmem0)` via gadget → CRASH.
- R2/R3: `open` via gadget+`native.fcall_with_rax` → CRASH even on `/dev/null` (gadget open path is lethal; must use named wrapper).
- R5/R6: `S.open` (named wrapper) → **REAL fds**. Proven: `open(nonexistent)=-1`, `read(/dev/null)=0` on fd 22. `/dev/dce`, `/dev/dmem0`, `/dev/dipsw`, `/dev/gbase` all open (fd=22 = lowest free after close).
- R8: ~200 ioctl codes (A801/6600/8000/8F00/5300/0400/9500/7000/dmem_864 families) on dce+dmem0 → **ALL -1, zero buffer modifications**.
- R10/R11: REAL dmem0 ioctl codes extracted from libkernel RE (`0x18210` opener): 0x2000800b, 0xc018800d/e/f, 0x80288012, 0xc0408013, 0xc0388014, 0x80108017, 0xc0208016, 0x80020016, 0x480003f7 — with buffer structs matching the RE (`{u64,u64,u32}` etc.) → **CRASH**.
- R12: single ioctl `0x2000800b` with arg3=NULL exactly as libkernel calls it → **CRASH**.
- R9: `mmap(/dev/dmem0)` → CRASH.

**CONCLUSION — /dev path CLOSED from game sandbox**: `open()` is allowed and returns real fds, but ANY data interaction (`read`, `mmap`, `ioctl` including the exact real codes) kills the loader process. The sandbox enforces this even for the dmem0 memory-management interface that libkernel itself uses. No kernel pointer leaks obtained from any device. Matches the AGENTS.md `/dev` device table (all sandboxed). Game-sandbox live-probe phase is now **complete** — remaining options are BD-J (hardware required) or offline research.

Built on: W:\Build\J02697906
Remote Lua Loader port: 9026 (unstable, game must be running)

### Session 5 (2026-08-01): /dev/dmem0 — libkernel-INTERNAL fd OVERTURNS "CLOSED" (probe_dev_r9f..r9x)

**BREAKTHROUGH (overturns Session 4)**: Session 4's ioctls were called on **game-side `S.open` fds (fd=22)** — those are sandbox-wrapped and always filtered (-1) or crash. The REAL story: **libkernel caches its own device fds in globals at init** (`libk+0x58038+8 = 5` = dmem0, fd=7 = leak device), and **those internal fds BYPASS the game-sandbox ioctl filter**.

**What works (all on fd=5, game alive, verified across a PS4 reboot)**:
- `ioctl(5, 0x80108002, {base, size})` → ret 0, re-arms the descriptor. Then `mmap(fd5, 1MB, off=base)` → returns VA=base (physical-identity) containing a **kernel dmap descriptor block**.
- **`+0x18 = 0xffffffff2ec48000` = kernel dmap VA self-pointer** (dmap base 0xffffffff00000000 → phys 0x2ec48000). **FIXED across boots — dmap is not ASLR-randomized.**
- Descriptor block content (identical every boot): `0x80000000c0012800` (magic) / `0xc000120080000000` / `0xc005580000000000` (phys ptrs) / self-pointer / DMA entries `0x000000<off>c0027600` at +0x30..0xa0 (off = 8,0x48,0x88,0xc8,0x108,0x148,0x88,0x20c,0x218) / stride-0x40 pair table `{0xc010760000000000, 0xc+N*0x40}` at +0xe0/0x120/0x180/0x1c0. GPU bus base 0xc0027600 / 0xc0107600.
- **WRITES PERSIST across ioctl re-arm + re-mmap** (r9x: wrote 0xABCD0000 at +0x20 → still there after re-arm). The descriptor block is live kernel dmap memory with no reset.
- Descriptor is **one-shot per boot** unless re-armed via the release ioctl; window is fixed 16MB (descriptor + zeros), `size` parameter ignored (r9w).

**Limits (all confirmed)**:
- `offset ≠ phys` for content (r9m); no arbitrary-phys mapping (r9v: same descriptor page at ANY accepted base); no window expansion (r9w).
- **Query/leak ioctls filtered even on fd5** (r9y): `direct_memory_query` (0x80288012) and `get_direct_memory_type` (0xc0208004) both → **-1**, zero output. Only the `release_direct_memory` path (0x80108002) is allowed through.
- ioctl arg validation: base must be 0x40000-aligned (PASS 0x100000/0x40000000/0x80000000/0x2ec48000; FAIL 0x1000/0x100001/0xFFFFF/0x3FFFFFFF/0x7FFFFFFF/0xBFFFFFFF/0xFFFFFFFF/0xc0027600).
- **⚠️ CRASH (r9s)**: `ioctl{0x100000,0x100000}` then mmap → loader killed, PS4 restart needed. Only known-aligned args are safe.
- OTHER internal devices: dipsw open+ioctl ret 0; srtc/sbi/gbase/dce internal opens → 0x800f0513/0x80020002/0x80020013/0x80020001 (denied); leak-fn 0x19e80 (fd7, ioctl 0x4010a802) ret 0 but 16B output scrubbed to zeros.
- libkernel C functions through 0x22700 ARE callable via native.fcall (libk_base = S.open.fn_addr − 0x2750).

**ioctl identification (psdevwiki dmem table, public)**: 0x80108002 = `release_direct_memory`; 0x2000800b = `clear_game_direct_memory` (libkernel dmem opener @0x18235); 0x80288012 = `direct_memory_query`; 0x80108015 = `checked_release_direct_memory`; 0xc0208004 = `get_direct_memory_type`; 0xc0288001 = `allocate_direct_memory`.

**DEFINITIVE CONCLUSION — dmem0 surface exhausted**: We hold a **persistent write into a kernel dmap DMA-descriptor page** (phys 0x2ec48000, GPU-DMA descriptor for the game's direct-memory region), plus a fixed kernel dmap VA leak — but this is **NOT a privilege escalation primitive**:
- The descriptor is a GPU DMA table whose semantics require the kernel dmem driver source (not available; PUP AES-encrypted).
- Trigger = GPU rendering; blind edits risk GPU crash + game loss; the GPU bus→phys mapping (0xc0027600 vs descriptor phys 0x2ec48000) is inconsistent under any simple aperture model → cannot reliably redirect DMA.
- All information-leak ioctls are sandbox-filtered even through the internal fd.
- No privilege-relevant kernel struct is reachable or writable through this window.

### Session 5.5 (2026-08-01): dmem0 window — FULL DECODE (r9ai..r9am) + final syscall sweep (r9an/r9ao)

**Window content beyond the descriptor is NOT zeros — it's the game's live GPU state (frozen snapshot)**. Full 16MB map, structural decode:

| Offset | Content | Details |
|--------|---------|---------|
| +0x000 | DMA descriptor list | magic 0x80000000c0012800; DMA entries `{off, 0xc0027600}` (off=8,0x48,0xc8,0x108,0x148,0x88,0x20c,0x218); ring chain `{0xc0107600, off}` ×7 (off=0x240,0xc,0x4c,0x8c,0xcc,0x10c,0x14c) — GCN ring/doorbell descriptors; +0x18 kernel self-ptr |
| +0x2a0 | GPU VM map table | pairs `{gpu_base, size}`: 0xc0017600{0x20/0x47/0x1/0xff...}, 0xc0023600, 0xc0017900, 0xc0021100, 0xc0002a00, 0xc0012600, 0xc0001300, 0xc0002f00, 0xc0012000, 0xc0004600, **0xc0016900{0x79000,0x80000,0x3f800000,0xcc0000,0x10000}** (the big shader/heap ranges); **+0x318/+0x3d8 = 0xffffffff00000000 = dmap base itself** (2nd/3rd kernel leak) |
| +0x800 | **Region A: GPU command submission ring** | 47 × 20-byte records `{0xe0000c00 (PM4 hdr type3,count12), 0xc0038000 (GPU cmd-buf base), 0x0000000f, 0x00000100, 0x0000XX00 (offset)}`, offsets 0x2000→0xbc00 step 0x800 (triple-repeats) → cmd buffers at GPU phys ~0x38000+off |
| +0xf000 | **Region B: resident PM4/GCN command buffer** | live microcode: `0xbf810000`=PACKET3_NOP end, `0xf80018xx/0x7e04xx` GCN instructions, repeating signature `0x0772646853627240`, shader hashes (0x98b9cb94/0x6f130734) |
| +0x3000/+0xfff0 | fence/timestamp-ish singles | 0x1122334455660000 / 0x0010001000100010 (leftover marker residue + record patterns) |

**LIVENESS (r9am, decisive)**: two consecutive re-arm+mmap cycles → `changed_qwords_0x1000=0` AND `f000_region_changed=0`; mmap returns different VAs per arm (0x2ee48000/0x2ef48000) but identical content. **The window is a STATIC frozen snapshot** — set up once at dmem init, not refreshed by the GPU (game idle at static screen, ring not consumed). Re-arm does NOT repopulate it. → GPU-command-injection via window edits is **inert** (no live consumer to trigger).

**Final syscall sweep (r9an/r9ao)**:
- **sc#560 kevent STD (stub@libk+0x1b50, confirmed `48 c7 c0 30 02 00 00` = imm 560)**: registers fine (ret 0) on a sc#362 kqueue, but **collect always returns 0 events** while sc#363 COMPAT11 on the same kq delivers the event (id/filter/flags/data=8/udata echoed, **ext[4]=0 — no kernel-pointer leak**). STD path is instrumented/muted in the sandbox; COMPAT11 remains the only working kevent. **Lead closed.**
- **sc#551 fstat STD (stub@libk+0x1a30)**: **-1 on ALL fds** — internal device fds 5/6/7 AND fresh socketpair fds. The fstat syscall itself is sandbox-blocked (not fd-specific). **Lead closed.** (Note: COMPAT sc#189 fstat crashes the kernel — never call; STD 551 returns -1 cleanly.)
- **sc#563 getrandom (stub@libk+0x1b70)**: **-1**. **Lead closed.**

**UPDATE to Session 5 conclusion**: the window is confirmed **inert for exploitation** (static snapshot, no arbitrary phys, no live ring consumption, query/leak ioctls filtered) — but it is now **fully decoded as the game's GPU DMA/command state**, yielding the only kernel-pointers ever recovered from the game sandbox: `0xffffffff2ec48000` (window self) and `0xffffffff00000000` (dmap base, ×2). No privilege-relevant struct reachable.

**GAME SANDBOX: INFO-DRAIN COMPLETE.** Every untested lead from AGENTS.md has now been executed: kevent STD (560), fstat STD (551), getrandom (563), full dmem window decode. All remaining exploitation requires the **BD-J player process** (Poopsploit 1.8/1.9 — BD burner hardware) or offline research.
