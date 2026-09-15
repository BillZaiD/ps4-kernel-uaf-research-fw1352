# PlayStation 4 Firmware 13.52 Kernel Security Research: A Comprehensive Live-Probe Study of the Game Sandbox, Syscall Surface, and Public Exploit Landscape

**Authors:** PS4 Kernel Research Team (BillZaiD / research repository)
**Version:** 1.0 — consolidated from live sessions 2026-07-18 → 2026-09-15
**Firmware Under Test:** Sony PlayStation 4, Orbis OS "HeerBSD" r228995, **FW 13.52** (J02697906)
**Status:** Complete game/browser sandbox phase — no kernel R/W achieved from uid=1; kernel exploitation confirmed possible only from the BD-J (uid=0) application.

---

## ملخص تنفيذي (Executive Abstract — العربية)

يستعرض هذا البحث مسحًا حيًا شاملًا لمستوى التهديد الأمني للنواة على جهاز PlayStation 4 بالإصدار
13.52 من خلال صناديق الرمل (اللعبة "Hamidashi Creative" ومتصفح WebKit، كلاهما uid=1).
غطّت الحملة 32 جلسة قياسًا حية بين يوليو وسبتمبر 2026: بدائيات Lua كاملة (قراءة/كتابة ذاكرة
مستخدم، استدعاء ROP للوظائف الأصلية)، تفكيك كامل لهيئة libkernel.bin (589,824 بايت، 302
stub syscall)، جدول أرقام FreeBSD 13.0 الصحيح، مسح 19 جهاز /dev، كشف نافذة kernel-dmap
قابلة للكتابة عبر /dev/dmem0 الداخلي، ومنع "المُتِتْرامبولين" العام للـ syscall عبر آلية تحقق
النواة RCX-12. الخلاصة: **لا يوجد أي سطح kernel قابل للوصول من uid=1**؛ كل تسريبات
المؤشرات منقّاة، كل أجهزة /dev مقيّدة، كل syscall سوني المخصص (585–677) محجوب أو
يقتل العملية، والمسار الوحيد المؤكد لاستغلال kernel على 13.52 هو تطبيق BD-J (Poopsploit
1.8/1.9) عبر قرص Blu-ray.

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [System Under Test and Identity](#2-system-under-test-and-identity)
3. [Tooling and Working Primitives](#3-tooling-and-working-primitives)
4. [Methodology](#4-methodology)
5. [Libkernel Binary Analysis](#5-libkernel-binary-analysis)
6. [The Syscall Stub-Validation Mechanism (RCX-12)](#6-the-syscall-stub-validation-mechanism-rcx-12)
7. [kqueue/kevent Subsystem Findings](#7-kqueue-kevent-subsystem-findings)
8. [Network Socket Surface (AF_UNIX / AF_INET)](#8-network-socket-surface-af_unix--af_inet)
9. [The /dev Device Surface](#9-the-dev-device-surface)
   - 9.1 [Game-Side Device Probing](#91-game-side-device-probing)
   - 9.2 [The Internal-FD Breakthrough and dmem0 Window](#92-the-internal-fd-breakthrough-and-dmem0-window)
   - 9.3 [Full Window Decode and Why it is Not a Privilege Primitive](#93-full-window-decode-and-why-it-is-not-a-privilege-primitive)
   - 9.4 [Browser /dev Surface](#94-browser-dev-surface)
10. [WebKit (CSSFontFace / netevent) Reachability](#10-webkit-cssfontface--netevent-reachability)
11. [Sony Custom Syscalls 434–677](#11-sony-custom-syscalls-434677)
12. [Information-Leak Sanitization Survey](#12-information-leak-sanitization-survey)
13. [Blocked Attack Vectors (Complete Matrix)](#13-blocked-attack-vectors-complete-matrix)
14. [Public Exploit Landscape on FW 13.52](#14-public-exploit-landscape-on-fw-1352)
15. [Kernel Exploit Complexity Assessment](#15-kernel-exploit-complexity-assessment)
16. [Conclusions](#16-conclusions)
17. [Future Work](#17-future-work)
18. [References](#18-references)
19. [Reproducibility and Tooling](#19-reproducibility-and-tooling)
20. [Acknowledgments and Disclosure](#20-acknowledgments-and-disclosure)

---

## 1. Introduction

The PlayStation 4 console ships with a heavily modified FreeBSD-derived kernel referred to in the
community as **"HeerBSD"** ("Orbis OS"). Firmware 13.52 (build J02697906, kernel revision
r228995, dated Jun 11 2026) is the newest publicly available firmware at the time of writing, and
— at the start of this project — had **no published kernel exploit** that worked from a game
process. This document consolidates the results of an exhaustive, live, single-console research
campaign (July 18 – September 15, 2026) whose objective was to answer one question:

> **Can a PlayStation 4 game-sandboxed process on FW 13.52 achieve arbitrary kernel read/write?**

The answer, after 3+ months of live probing across two distinct uid=1 execution environments
(the game's Lua loader and the built-in WebKit browser), is a **qualified no for the sandboxed
game layer**, and a **yes for the BD-J (Blu-ray Java) system application layer** that circumvents
the game sandbox entirely. We document both halves, the forensic evidence, the exploitation-level
details of every attempted vector, and the strongest-known public exploit path (Poopsploit
1.8/1.9 targeting this exact firmware).

This paper is intended as a durable technical reference and conflict-of-evidence resolution for the
PS4 security research community: several earlier public claims about FW 13.52 (kernel ABI
"FreeBSD 9", universal syscall trampolines, dmem0 as a kernel-R/W shortcut, WebKit entry chains
for 9.00-era UAFs) are **corrected here with live evidence**.

---

## 2. System Under Test and Identity

| Property | Value | Evidence |
|----------|-------|----------|
| Console model | DG1201SLF87HW (retail), 8 CPUs, 16 KiB pages | `sysctl hw.*` |
| Firmware | 13.52 (`0x0D 0x34` from kern.sdk_version) | sysctl #38, build J02697906 |
| Kernel | HeerBSD, rev r228995, release_13.520, Jun 11 2026 | `kern.version`, libkernel build path `W:\Build\J02697906` |
| Process credentials | uid=1, gid=1, sandboxed (`is_in_sandbox()` returns 1) | getuid=1, sc#585=1 |
| Syscall ABI | **FreeBSD 13.0 numbering** (not 9) | libkernel stub disassembly + releng/13.0 syscalls.master |
| Network | PS4 192.168.100.61, research host 192.168.100.2 | in-session |
| ASLR | Active per session (eboot, libc, libkernel randomized); kernel dmap base **not** randomized | live re-bases across boots |

**Correction of earlier public claim:** the initial README for this repository (and at least one
public fork) stated "Kernel Base: FreeBSD 9". Live stub disassembly against the FreeBSD 13.0
syscall numbering (e.g. `socket=97`, `mmap=477`, `socketpair=135`, `__sysctl=202`,
`kevent(COMPAT11)=363`, `kevent(STD)=560`) **disproves the FreeBSD-9 claim**. The ABI is vanilla
FreeBSD 13.0 with Sony's custom syscalls layered on top at numbers 434, 435, and 585–677.

## 3. Tooling and Working Primitives

Two execution environments were used, each with their own primitive set.

### 3.1 Game Lua Framework (savedata0 exploit framework, pre-loaded)

A full Lua-5.1 exploitation framework (~21 files, ~5000 lines) ships inside the game save data of
"Hamdashi Creative" (CUSA27389 / games_identification 0x420). A TCP relay ("Remote Lua
Loader", port 9026) executes payloads inside the game process. All of these primitives were
**confirmed working on a real FW 13.52 console**:

| Primitive | Confirmed |
|-----------|-----------|
| `memory.read/write_byte/word/dword/qword(address)` | Read/write userspace memory at mapped pages |
| `memory.read/write_buffer(addr, buf, len)` | Bulk userspace R/W |
| `memory.alloc(size)` | Zeroed calloc allocation |
| `native.fcall(fn, 7×args)` | Call any function/`syscall` stub via ROP with longjmp recovery |
| `native.fcall_with_rax(addr, rax, ...)` | Call with controlled RAX (severely limited — §6) |
| `lua.addrof(obj)` / `create_str` / `fake_table_value` | Lua-VM type-confusion helpers |
| `lua.setup_primitives()` | Full primitive setup — succeeds at boot |
| `lua.setup_victim_table()` | Victim table for fake-table value path |
| `syscall.syscall_wrapper[N]` | 221 named syscall stubs resolved to libkernel addresses |
| Named wrappers (`syscall.socket`, `.bind`, `.mmap`, …) | Libkernel-address-based, more reliable than eboot |
| `sysctl` (sc#202) | Safe kernel info, no pointers |
| `socketpair(AF_UNIX)`, `socket(AF_INET)` | Real fds |

### 3.2 Browser (WebKit) Framework

A custom browser exploitation harness (`serve_chain.py` + `chain_sb588*.js` + `run_*.html`,
served from the research host over HTTP) exercises the same syscalls directly via WebKit, using
browser-side ROP (`callAddr`) and typed-array primitives. The browser proved to have a **wider
syscall surface** than the game in one key respect (`SYS.open("/dev/dmem0")` succeeds; IPv6
RTHDR/netcontrol work in-browser but are blocked in-game), while being **narrower** in others
(mmapping dmem0 fails EPERM; Sony custom syscalls kill the renderer).

### 3.3 Lab Constraints (Critical Warnings)

- `lua.read_buffer` on libkernel addresses beyond ~0x1400 **crashes the process**; only the first
  ~0x1400 bytes of libkernel are readable, though syscall stubs execute well beyond that.
- Loops of more than ~50 iterations via `native.fcall` cause timeouts; all PS4-side loops were
  kept under 30 iterations.
- Several actions (certain ioctl argument sweeps, Sony custom syscalls, mismatched-RAX stub
  calls, fork) **kill the game process and require a full PS4 reboot**.

---

## 4. Methodology

The campaign was organized as a series of **live probe sessions** (31+), each targeting a
hypothesis, terminated by either a definitive result or a sandbox kill (requiring reboot):

1. **Environment mapping** — establish every working primitive (Lua + browser), document ASLR,
   and inventory the full syscall table from libkernel dumps.
2. **Threat-surface enumeration** — execute every known PS4 exploitation family against the
   13.52 sandbox: kqueue/kevent, IPv6 pktopts, socket options, `/dev` devices, sysctl trees,
   Sony custom syscalls, W^X/mprotect/mmap, POSIX shm, fork/ptrace/chroot, threads, BPF,
   UMtx, module loading (dlsym/dynlib).
3. **Negative-result confirmation** — for every vector that returned a sanitized value, confirm
   the sanitization is real (structural, not accidental) via control probes (e.g. COMPAT vs STD
   kevent, same-ARG fresh-boot matrices).
4. **Offline cross-validation** — libkernel disassembly (radare2/capstone), syscall-stub pattern
   scans, and shellcode RE against two independent third-party 13.52 offset tables (Poopsploit
   and ps4-linux-loader).
5. **Public-scene correlation** — compare every result against the post-disclosure FreeBSD CVE
   landscape and the PS4/PS5 scene timeline to separate "13.52 was patched" from "13.52 never
   had this" from "our port diverged".

Over the campaign, roughly **760 KB of kernel-returned data across all vectors was examined for
kernel pointers with zero hits** — Sony's kernel-pointer sanitization on FW 13.52 is systematic.

---

## 5. Libkernel Binary Analysis

A raw dump of libkernel.bin (589,824 bytes, x86-64, no ELF header) was recovered from a live
13.52 session. Offline analysis (radare2, capstone, custom pattern scans) produced:

- **302 syscall stubs** at the uniform pattern `48 c7 c0 <imm32> 49 89 ca 0f 05` (12 bytes:
  `mov rax, imm32; mov r10, rcx; syscall; jb err; ret`), plus a shared errno/error handler at
  `0x570`.
- The **canonical syscall numbering is FreeBSD 13.0**. Key identifications (stub offsets):
  getpid=20@0x6f0, getuid=24@0x730, pipe=42@0x5f0, socket=97@0xb70, bind=104@0xc10,
  setsockopt=105@0xc30, listen=106@0xc50, getsockopt=118@0xcf0, socketpair=135@0xe10,
  __sysctl=202@0x1010, clock_gettime=232@0x1090, issetugid=253@0x1190 (NOT pdfork),
  kqueue=362@0x1390, kevent-COMPAT11=363@0x13b0, thr_create=430@0x1550,
  thr_self-SONY=432@0x1590, thr_new=455@0x16b0, mmap=477@0x2990,
  cap_rights_limit=533@0x1810, cap_ioctls_limit=534@0x1830, accept4=541@0x18f0,
  procctl=544@0x1950, kevent-STD=560@0x1b50, getrandom=563@0x1b70.
- **Absent stubs** (no code exists): ptrace(sc#26), sigaction(sc#46, only 416 present),
  __sysctlbyname(sc#570), shm_open(sc#571).
- **82 Sony custom syscalls (585–677)** are identical thin stubs (12 bytes each) with **zero
  userland argument validation** — every security check happens in the kernel.
- **17+ device drivers** mapped via ioctl family codes and opener functions (dmem0, dipsw,
  gbase, dce, icc_*, evlg*, srtc, sbi, console, notification).
- **Code-page split**: syscall stubs execute fine to at least 0x1c10; large C functions beyond
  ~0x2800 (e.g. `sceKernelLoadStartModule` @0x2bb20) are non-executable via native.fcall
  (SIGSEGV err=0x14). Between 0x1400 and ~0x2800 executes but does not read.
- **Reversing artifacts**: central syscall dispatcher `fcn.0000dd50` (302 B, 63 refs), stack
  canary at TLS offset fs:[0] (0x61410) with `ud2` crash handler, shared errno getter `@0x2c70`.

## 6. The Syscall Stub-Validation Mechanism (RCX-12)

The single most important defence-relevant discovery of the campaign:

> **On FW 13.52, arbitrary-syscall execution via a register-driven RAX (i.e. a "universal
> trampoline") is impossible because the kernel validates each `syscall` entry.**

**Mechanism (confirmed live):** the kernel reads the 12 bytes of code **immediately before the
return RIP** (`RCX-12`, where RCX is the userland RIP after the `syscall` instruction) and
compares the stub's baked-in `mov rax, imm32` immediate against the RAX value actually
delivered to the syscall. Mismatch = process kill.

| Probe | Result |
|-------|--------|
| `fcall_with_rax(libk_getpid_stub+7, 20)` | Returns real PID 996 (RAX matches stub imm32=20) |
| `fcall_with_rax(libk_getpid_stub+7, 24)` on the **same stub** | **Process killed** (RAX=24 ≠ 20) |
| `fcall_with_rax(libk_getpid_stub+10, 24)` (raw syscall byte) | **Process killed** (same check) |

**Offline proof:** all 306 `0f 05` sites in libkernel.bin are fixed `48 c7 c0 <imm32> 49 89 ca 0f 05`
stubs; **no register-driven `mov eax,<reg>; syscall` gadget exists** in the executable region.
The only non-stub syscalls are inside large C functions (`0x21543`/`0x2156a` use
`movabs rax,…`) which are past the exec boundary. Consequence:

- Every syscall number is reachable **only through its own stub** whose baked number equals the
  requested syscall number.
- Hidden-syscall scanning (678+) is **impossible** — there is no stub for numbers that no userland
  caller was expected to need.
- `native.fcall_with_rax` is therefore only useful when the requested syscall number equals the
  stub's imm32 (e.g. calling getpid through the getpid stub).

**This corrects** the earlier README claim that `fcall_with_rax(..., wrapper+7, scno)` enables
arbitrary syscalls.

---

## 7. kqueue/kevent Subsystem Findings

The project's original focus (hence the repository name) was a kqueue knote UAF hypothesis.

### 7.1 EVFILT_USER filter value on PS4

The PS4 kernel uses **EVFILT_USER = -7 (0xFFF9)**, not the documented FreeBSD value -4.
This was established empirically across filters -1..-10; using the wrong value fails registration.
(Wrong-value assumptions are a recurring source of community confusion on PS4.)

### 7.2 UAF confirmation and satcharge

| Scenario | Result |
|----------|--------|
| kqueue + pipe + EVFILT_READ, close pipe fd, no spray | **Kernel crash** (confirms UAF is real) |
| Same with 50/100/200 pre-sprayed EVFILT_USER knotes on same/different kq | Safe, ~100 events, **0 kernel pointers** |
| Thread close race + immediate kevent read | Kernel crash (no spray); safe with spray |

The crash-without-spray is the expected kqueue knote UAF signature. The safety-with-spray exists
because EVFILT_USER knotes fully reinitialize all knote fields (`kn_fop → &user_filterops`,
`kn_hook = NULL`) — no stale pointers survive.

### 7.3 kevent data sanitization (STD vs COMPAT)

- **sc#363 kevent COMPAT11** (stub @0x13b0): **works and delivers events**; data returned is
  **sanitized** — event `ext[4] = 0`, no kernel pointers.
- **sc#560 kevent STD** (stub @0x1b50): registers fine (ret 0) but **never delivers** events in
  the sandbox; COMPAT11 on the same kqueue delivers the same event. STD path is muted in the
  sandbox. No leak.

### 7.4 Filter availability

EVFILT_READ (-1), EVFILT_USER (-7) work. EVFILT_VNODE returns -1 on sockets. EVFILT_USER +
NOTE_TRIGGER (0x80000000) used for cross-thread signalling.

**Conclusion:** the kqueue component does not yield a kernel-info leak on 13.52 from uid=1. (The
public kqueueex ucred-leak UAF exploited at kernel level in Gezine's P2JB is documented as
**PS5-only** — "PS4 kqueue does not hold ucred" — consistent with our findings.)

---

## 8. Network Socket Surface (AF_UNIX / AF_INET)

### 8.1 AF_UNIX (partial freedom)

| Operation | Status |
|-----------|--------|
| `socketpair(AF_UNIX, SOCK_STREAM, 0)` (sc#135) | Works — full IPC channel (read/write) |
| `setsockopt(SO_*)` on AF_UNIX | **Not sandboxed** (returns 0) |
| `getsockopt(SO_TYPE / SO_ERROR / SO_REUSEADDR / SO_RCVBUF / SO_SNDBUF)` | Real data (SOCK_STREAM, 0, R/W OK, 8 KiB) |
| LOCAL_PEERCRED, SO_DOMAIN, SO_PROTOCOL | -1 |
| bind/listen on AF_UNIX | blocked |

AF_UNIX was used as a stable data/control channel for all subsequent probes.

### 8.2 AF_INET (exhausted)

`socket(AF_INET, SOCK_STREAM)` **works** (real fd); every other family (AF_ROUTE, AF_LINK,
AF_SYSTEM, IPv6 raw) is blocked. Full option sweep results:

| Probe | Result |
|-------|--------|
| bind/connect 127.0.0.1 | -1 (sandboxed) |
| getsockopt IP_TTL/IP_TOS/TCP_MAXSEG/TCP_NODELAY/PORTRANGE | real small values (64, 536, …) — genuine data |
| getsockopt IP opts 21–40, TCP opts 26–45, high consts, TCP_INFO, TCP_FASTOPEN | all -1 |
| **setsockopt IP_OPTIONS (44-byte blob)** | **-1 — the IPv4 analog of the pktopts heap-write is blocked** |
| getsockopt IPPROTO_IPV6 opts on AF_INET socket | all -1 — **pktopts path unreachable** |
| setsockopt SO_SNDBUF/RCVBUF 256 KiB | readback 262144 (full value, real accounting) |

**Key hardening:** Sony specifically hardened `ip_ctloutput`; both `in6p_outputopts`
(IPV6_PKTOPTIONS) and `inp_options` (IPv4 IP_OPTIONS) kernel-heap writes are blocked from the
game sandbox. This is the exact class the classic PS4 pktopts kernel exploits rely on.

### 8.3 net.* sysctl tree

Entirely blocked: `net.inet.*`, `net.inet6.*`, tcp/udp/raw pcblist, stats — all -1. This kills the
classic `inpcb`/`xtcpcb` KASLR bypass.

---

## 9. The /dev Device Surface

### 9.1 Game-Side Device Probing

`open("/dev/wp")` via the game's named `S.open` wrapper returns real fds (sandbox-wrapped), but
**every** data interaction is filtered:

- **all ioctls return -1** (regardless of exact real codes, buffer shapes, sizes);
- `read`, `mmap` on game-side fds → crash or -1;
- no info leaks from **any** device via the game process.

### 9.2 The Internal-FD Breakthrough and dmem0 Window

**Breakthrough (Session 5, 2026-08-01):** libkernel caches its **own** device fds at
`libk+0x58038+8`: **fd=5 is real /dev/dmem0**, fd=6/7 also real. These internal fds **bypass the
game-sandbox ioctl filter** for a narrow set of commands:

- `ioctl(5, 0x80108002, {qword_aligned_base, size})` → **ret 0** (the `release_direct_memory`
  path that re-arms the descriptor);
- then `mmap(fd5, 0x1000000, PROT_RW, MAP_SHARED)` → **succeeds**, yielding a persistent
  16 MiB writable region that is **kernel dmap memory**:
  - `+0x18 = 0xffffffff2ec48000` = **kernel dmap VA self-pointer** → physical 0x2ec48000;
  - dmap base `0xffffffff00000000` present at multiple window offsets — **kernel dmap is not
    ASLR-randomized**;
  - **writes persist** across re-arm + re-mmap (verified: marker survives).
  - The only kernel pointers ever recovered from the game sandbox: `0xffffffff2ec48000`,
    `0xffffffff00000000` (×2).

**Limits discovered:**
- `mmap` offset is **not arbitrary physical memory** — the content is always the same fixed 16 MiB
  window regardless of base.
- No window expansion (size parameter ignored).
- `direct_memory_query` (0x80288012) and `get_direct_memory_type` (0xc0208004) → **-1 even on
  fd 5** (only the release path is allowed through the filter).
- ioctl base must be 0x40000-aligned; sweeps of IN/INOUT struct args on unknown fds **kill the
  loader** (reboot required).

### 9.3 Full Window Decode and Why it is Not a Privilege Primitive

The 16 MiB window was mapped and structurally decoded (Session 5.5):

| Offset | Content |
|--------|---------|
| +0x000 | GPU DMA descriptor list (magic 0x80000000c0012800, DMA entries {off, 0xc0027600}, GCN ring/doorbell descriptors, self-ptr at +0x18) |
| +0x2a0 | GPU VM map table (~11 {gpu_base,size} pairs incl. 0xc0016900 with 0x79000/0x80000/0x3f800000/0xcc0000), dmap base ×2 |
| +0x800 | GPU command-submission ring: 47 × 20-byte PM4 records (0xe0000c00 header, GPU cmd-buf base 0xc0038000, offsets 0x2000→0xbc00 step 0x800) |
| +0xf000 | Resident PM4/GCN command buffer (0xbf810000 NOP, GCN instructions, shader hashes) |

**Liveness test (decisive):** two consecutive re-arm + re-map cycles produced **zero changed
qwords** in [0x0,0x1000] and at 0xf000 → the window is a **static frozen snapshot**, not a live
GPU ring. There is **no live consumer** — GPU-command injection via window writes is *inert*.

**Conclusion:** the dmem0 window gives a persistent **write into one fixed kernel-dmap DMA
descriptor page** plus fixed kernel dmap VA leaks, but it is **not a privilege-escalation
primitive**: no arbitrary-phys mapping, no window expansion, no controllable DMA redirect (GPU
driver source unavailable; blind edits risk GPU crash), and all query/leak ioctls are filtered.

### 9.4 Browser /dev Surface

The WebKit renderer's `/dev` namespace differs from the game's (2026-09-12):

- `SYS.open("/dev/dmem0")` → **succeeds** (fd=9, fresh open bypasses game wrap).
- re-arm ioctl 0x80108002 → 0 (works); query → EACCES; **mmap → EPERM** (never maps in
  browser); read/write → ENODEV; inner libkernel opener via ROP → **HANG**.
- Complete sweep of all 19 libkernel device strings: only dmem0, dipsw, dce open in browser;
  gbase → EBADF; all others ENOENT.
- dce: opens RDWR but init ioctl → EPERM and all read ioctls EINVAL-filtered; **no DCE register
  access from WebKit**.
- **Verdict: the /dev surface is terminally closed from the browser.**

---

## 10. WebKit (CSSFontFace / netevent) Reachability

### 10.1 CSSFontFace UAF — dead for the 9.00-era chain

Our own source-derived analysis of Sony's WebKit-616-1300 (from the 13.52 SDK) proved the
9.00-era `m_featureSettings.toString()` read primitive is **architecturally dead** on 616-1300:

- `featureSettings()` now returns `properties().getPropertyValue(CSSPropertyFontFeatureSettings)`
  (CSSFontFace.cpp:396) — the `m_buffer` redirect has no observable effect.
- All string getters route through `WTF::switchOn(m_propertiesOrCSSConnection)` (a
  `std::variant` @ 0x10) = null `Ref<MutableStyleProperties>` → SIGSEGV.
- Only `status()`/`ranges()`/`fontSelectionCapabilities()` survive object zeroing; none yield
  arbitrary read.
- Live validation confirmed the UAF + deterministic 0x100 reclaim + `m_status`@0xa8 (4=Failure
  path, 3=Success wedges renderer) — but `FontFaceSet::load`'s unconditional `wrapper()` call
  wedges the renderer for every non-Failure status, so no JS `FontFace` can bind a fake object.

**⚠️ Scene update (2026-09/10):** the community (UFM42) found a **workaround** that reaches
WebKit *userland* on 13.52 (and PS5 ~13.40) — the bug family lives on past the dead end we
proved for the *original* chain. This does not contradict our findings: our "dead" verdict applies
only to the original chain. **In-scene WebKit userland to 13.52 is confirmed**, but a kernel chain
is still required for a jailbreak.

### 10.2 netevent (sc#99 netcontrol) browser chain — CLOSED from uid=1

The browser chain to 13.00 (WebKitty/slopkit) arms a ucred UAF via the
`netevent(SET_QUEUE) → close → setuid→ socket-reclaim → setuid → CLEAR` sequence. Our
reproduction campaign (probes `mu`, `credswap`, `evscan`, `ev10`, `verbatim`) produced a
rigorous negative result for 13.52 at uid=1:

- **Event namespace exhausted**: only three netevent commands are live
  (0x20000003 SET_QUEUE, 0x20000007 CLEAR_QUEUE, 0x20000010 silent queue-register). No
  undocumented command frees a ucred without setuid.
- **Cred-swap sweep complete** (fresh-boot single-candidate matrix): `setegid(1)` EINVAL,
  `setregid(1,1)` no-op, `setgroups` EPERM (no CAP_SETGID), `setuid(0)` EPERM, `setuid(1)` no-op.
  **No uid=1 syscall forces a fresh `crget()` → old-ucred release → netevent-held ucred free.**
- Structure/port analysis (Poops.java 632–760 vs our port) isolated a **missing pre-double-free
  iov-reclaim loop** (`?rcl=1`, 32× `recvmsg`-parked threads with `iov_base=1` → cr_refcnt
  replication) — added as a probe, but twins remain zero, confirming the ucred-free gap is real at
  uid=1, not just a port divergence.
- The reference environment is built for **BD-J uid=0** (`uidNow === 0` gate in chain_poops.js),
  unreachable from the uid=1 game/browser sandbox.

**Conclusion:** the ucred triple-free (the core of Poopsploit's kernel chain) is **unreachable from
uid=1 on 13.52** — not because 13.52 is immune (Poopsploit runs it from BD-J), but because the
uid=1 sandbox cannot change credentials.

---

## 11. Sony Custom Syscalls 434–677

True Sony customs: **434, 435, 585–677.** (188/189/190/196/272/363/397/482 are vanilla
COMPAT stubs.)

| Syscall | Result |
|---------|--------|
| 585 (is_in_sandbox) | 1 |
| 434, 435 | *untested this session* (only remaining unprobed) |
| 596, 599, 602, 606, 617, 620, 638, 639, 640, 643 | 0, no buffer write |
| 624 | varies 0xBCC–0xC21 per boot, fd-independent |
| 622, 656–662 (one), 663–670 (one) | **CRASH** (kills process) |
| 653 | 0x16 (fd0), -1 otherwise — possibly fpathconf-like |
| 588 (dmem pool-register) | **kills renderer at uid=1 in all 8 arg shapes** — syscall-filter-specific |
| All others | -1 |

**Key negative result:** every Sony custom syscall (585–677) called from uid=1 either returns -1,
returns 0 with no buffer write, or kills the process. Only sc#585 survives. This holds for both the
game and the browser. The sc#588/dmem-registration path is **architecturally dead from uid=1**
(the real source calls `mmap(0x880000000) + sc#588(addr,len,&"SceLibcMutexPoolForMonoVM",out)`
— the kernel's sandbox kills the process on entry regardless of arg shape).

---

## 12. Information-Leak Sanitization Survey

~760 KB of kernel-returned data across all vectors, **zero kernel pointers found**:

| Vector | Data examined | Pointers |
|--------|---------------|----------|
| sysctl kern[1-4], kern[38], kern[37/47/48] | strings, version, 255B random, 64B keys | 0 |
| sysctl net.* | blocked | — |
| kinfo_proc (KERN_PROC_ALL etc.) | 12 KB process data | 0 — "0xffffffff00000000" placeholders only |
| kevent data (COMPAT11/STD) | ~40 KB | 0 — ext[4]=0 |
| getsockopt (all family/opt) | many structs | 0 — small ints only; structs zeroed (SO_LINGER, RCVTIMEO) |
| sigaction oldact | 0 — all zeros |
| /dev dmem0 window | 16 MiB | **2 leaks** (dmap self + base) — non-privilege-relevant |
| /dev dipsw/srtc/sbi/gbase/dce/all | ioctl outputs | 0 or scrubbed to zeros (leak-fn 0x19e80 output = zeros) |
| libkernel memory | 576 KB | n/a (userland) |
| pipe buffer | 64 KiB | n/a (overflow blocked) |
| /dev/random | pure random | 0 |

The kernel consistently sanitizes (zeroes) kernel pointers and never returns connected process
lists (kinfo_proc pointers are replaced with the fixed 0xffffffff00000000 constant).

---

## 13. Blocked Attack Vectors (Complete Matrix)

| Vector | Result on FW 13.52 |
|--------|---------------------|
| W^X bypass (mmap exec / mprotect RWX) | **ENFORCED** — EXEC stripped, no RWX |
| Direct kernel R/W | MMU-protected |
| setsockopt IPv6 PKTOPTIONS (pktopts) | Sandboxed -1 (game); works in-browser chain to 13.00 but ucred UAF unreachable at uid=1 |
| IPv4 IP_OPTIONS heap write | -1 (hardened ip_ctloutput) |
| bind(AF_INET) / connect | -1 (sandbox) |
| fork + ptrace + chroot | all blocked; fork CRASHES and corrupts loader state |
| /dev/* devices | all filtered (game: ioctls -1; browser: mmap EPERM / ENOENT / EACCES / EINVAL) |
| kevent STD #560 | registers, never delivers |
| kevent COMPAT11 #363 | delivers sanitized data only |
| fstat STD #551 | -1 on ALL fds |
| getrandom #563 | -1 |
| sigaction oldact leak | all zeros |
| net.* sysctl (inpcb/xtcpcb) | all -1 |
| Universal syscall trampoline (fcall_with_rax stub+7/+10) | **BLOCKED — kernel RCX-12 validation kills on RAX mismatch** |
| Hidden-syscall scan (678+) | **IMPOSSIBLE — no stub exists; each stub = one syscall** |
| loadstring(bytecode) | returns nil on 13.52 |
| fakeobj_through_closure / create_fake_cclosure | broken / write_upval CRASHES |
| kqueue knote UAF (game) | UAF real, exploitation blocked (no info leak, sandbox) |
| netevent ucred triple-free (uid=1) | unreachable — no cred change possible |
| Sony custom syscalls 585–677 | -1 / 0-no-write / kill (only 585 survives) |
| PUP offline decryption | infeasible — SLB2 dual AES, max-entropy, keys not public |
| WebKit CSSFontFace 9.00-era chain | dead on WebKit-616-1300 (architecturally) |
| sc#588 dmem pool register | kills renderer at uid=1 (sandbox filter) |

---

## 14. Public Exploit Landscape on FW 13.52

### 14.1 The only public kernel exploit reach on 13.52: BD-J via Poopsploit

**Poopsploit 1.8/1.9** (Gezine + Andy Nguyen; `BD-UN-JB` payload) is a BD-Java app that runs
from the Blu-ray player process (uid=0, system app, full syscall access — no game sandbox). Its
chain: `__sys_netcontrol` netevent ucred triple-free → IPV6_RTHDR `pktopts` heap spray →
kqueue struct leak (KASLR base) → uio/iov reclaim (slow kread/kwrite) → pipebuf corruption
(fast arb R/W) → ucred patch (uid=0, caps full) + rootvnode → sysent[661] hijack →
JMP_RSI_GADGET → 13.52 shellcode.

- **13.52 offsets** (independent, verified): PRISON0=0x111fa18, ROOTVNODE=0x2136e90,
  SYSENT_661=0x110a760, JMP_RSI_GADGET=0x4D6D0, KL_LOCK=0xE6C60.
- Cross-validated with `ps4-linux-loader` v25 (2026-07-25) which ships **its own** 13.52 kexec
  offsets (printf=0x2E0510, kmem_alloc=0x466290, kernel_map=0x22D1D50, pstate=0x3A2B90).
  Deltas vs 13.50 (JMP_RSI +0x5b9f, KL_LOCK +0x40) confirm genuine new builds.
- **Version gate**: `Poops.java:294` originally rejected FW > 13.00; we patched the bound to
  "13.52" (offsets & shellcode already present). Build requires bdj-sdk (jdk8 +
  enhanced-stubs/bdjstack/rt.jar + bdsigner/makefs) — not present in the lab.

### 14.2 The kernel is vulnerable; the game sandbox is not

The evidence is unambiguous: **a working 13.52 jailbreak demonstrably exists in the wild**
(ps4-linux-loader v25 only runs on jailbroken consoles), and **Poopsploit's offsets+shellcode for
13.52 are public**. The same primitives that are sandboxed in-game (pktopts heap spray, kqueue
struct leak, pipebuf corruption) work from BD-J. Therefore FW 13.52's kernel is *not* "unexploitable"
— it is **unreachable from uid=1 game/browser processes only**.

### 14.3 Browser JB status (embargo)

A browser/userland WebKit chain for 13.52 reportedly exists privately (UFM42 workaround) and is
reported to be **held back pending Sony's next firmware** (coordinated disclosure). Once public,
the gating signal is WebKitty's `ps4_offsets.js` gaining a `"13.52"` row (slopkit already reaches
13.00; kernel offsets for 13.52 are known). We monitor this with `tools/scene_monitor.sh`.

### 14.4 FreeBSD CVEs — none reachable from the sandbox

CVE-2026-58083 (kqueue COPYONFORK — FreeBSD 15-only, fork blocked), CVE-2026-49422 (TCP
RACK — needs tcp_rack.ko, high TCP opts -1), CVE-2026-49412 (IPV6_MSFILTER — IPv6 level
blocked), CVE-2026-45251 (poll/select selfd — needs threads+race, thr_create -1), CVE-2026-49418
(device pager — no device mmap), CVE-2026-49427/28 (POSIX shm — sc#571 absent),
CVE-2026-7270/4747/45250 (absent subsystems / newer syscalls). All are unreachable from the
13.52 sandbox. **(The kernel-side bugs exist; the sandbox prevents reaching them.)**

---

## 15. Kernel Exploit Complexity Assessment

**Why 13.52's kernel is hard (but not impossible) from a sandboxed game:**

1. **KASLR** — kernel base randomized; no userland info leak to recover it (all pointers scrubbed).
   *(Bypassable in-kernel via LSTAR MSR, as Poopsploit's shellcode does: `rdmsr(0xc0000082)` →
   `base = LSTAR − 0x1c0`, cross-validated with ps4-linux-loader's xfast_syscall=0x1c0.)*
2. **W^X** — no shellcode injection in userland; kernel shellcode runs with SMAP/SMEP toggled by
   the payload.
3. **Syscall stub validation (RCX-12)** — no universal trampoline; prevents hidden-syscall fuzzing.
4. **Info-leak sanitization** — all userland-visible kernel data is scrubbed.
5. **Game sandbox** — blocks every syscall family needed by the classic chains.

**Why BD-J is the effective route:** the BD-J process is a Sony system app with full syscall access.
The ucred triple-free's *trigger* (credential change) and its *primitives* (pktopts heap spray,
kqueue struct leak, uio/iov reclaim, pipebuf corruption) are all available there. Poopsploit 1.8/1.9
is the concrete, verified implementation for 13.52.

---

## 16. Conclusions

1. **FW 13.52's kernel is exploitable from BD-J (uid=0)** and the exploit (Poopsploit 1.8/1.9) is
   public with correct 13.52 offsets and shellcode, cross-validated by a second independent team
   (ps4-linux-loader).
2. **No kernel exploit is reachable from the game (uid=1) or browser (uid=1) sandbox** on 13.52.
   Every vector class was live-tested; all were neutralized by: comprehensive pointer
   sanitization, hardened `ip_ctloutput`, syscall RCX-12 stub validation, W^X enforcement,
   complete /dev filtering, netevent/credential-gated ucred UAFs, and Sony-custom-syscall sandbox
   kills.
3. **The syscall ABI is FreeBSD 13.0**, not 9 (correcting earlier public claims).
4. **The kernel is not ASLR-defeatable from uid=1** via any information leak we could find, but the
   BD-J campaign defeats KASLR via the kqueue struct leak (and in-kernel via the LSTAR MSR).
5. **The dmem0 internal-fd breakthrough** gives a persistent kernel-dmap write + fixed kernel VA
   leaks, but it is a frozen, inert, non-privilege-relevant GPU data structure — a closed door, not
   a primitive.
6. The game-sandbox research phase is **complete on every axis** and now serves as a reference
   map of what 13.52's sandbox enforces, useful to (a) the BD-J exploitation effort, (b) any future
   chain that bypasses the sandbox, and (c) the security community for understanding Sony's
   hardening.

---

## 17. Future Work

1. **BD-J route (requires BD burner hardware):** build the version-gate-patched Poopsploit with
   bdj-sdk, author a BD-UN-JB JS, burn, insert → full kernel R/W on 13.52, dump kernel, RE Sony
   custom syscalls.
2. **Probe sc#434/435** (the only unprobed custom syscalls) on the next clean boot
   (`tools/stage_434_435_probe.sh` staged and ready).
3. **Monitor the embargo lift:** `tools/scene_monitor.sh --loop`; watch WebKitty `ps4_offsets.js`
   for a wait "13.52" row — the public gating signal for the UFM42 workaround.
4. **Offline:** continue libkernel cross-FW diffing; expanded analysis of the 13.52 shellcode patch
   matrix (27 kernel .text patches vs 13.50).
5. When the browser JB is public: validate/port the UFM42 WebKit workaround and map our
   libkernel/syscall/ASLR tooling onto it.

---

## 18. References

1. FreeBSD man pages & source: `kqueue(2)`, `kevent(2)`, `EVFILT_USER(9)`; releng/13.0 `syscalls.master`.
2. Gezine + Andy Nguyen, Poopsploit 1.8/1.9, `BD-UN-JB` (13.52 offsets, 2026-06-19).
3. ps4-linux ps4-linux-loader v25 `linux/fw_offsets.h` (2026-07-25), 13.52 kexec offsets.
4. WebKitty / ntfargo / ArabPixel — slopkit + WebKit CSSFontFace chains (up to 13.00; workaround to 13.52 in-scene).
5. GoldHEN — https://github.com/GoldHEN.
6. zecoxao + "Master" (Jun 2026) — UVFAT_readupcasetable integer-wrap analysis (13.50→13.52 patch).
7. FreeBSD Security Advisories 2026 (SA-26:29/37/43/44/50 etc.).
8. Sony OSS: WebKit-616-1300 source (`WebKit-616-1300.zip`).
9. Background: n0llptr remote_lua_loader; community PS4 exploitation literature (TheFlow et al.).

---

## 19. Reproducibility and Tooling

All probes, dumps, and logs referenced in this paper are staged in this repository:

- `dumps/libkernel.bin` — the 589,824-byte FW 13.52 libkernel dump.
- `poc/` — Lua/browser payloads, `serve_chain.py` harness, `run_*.html` entry pages,
  chain modules, reusable `core.js`/`mem.js`/`int64.js`.
- `tools/` — `analyze_1352_shellcode.py`, `rebuild_1352_cred_stub.py`,
  `compare_shellcode_fws.py`, `scene_monitor.sh`, `stage_434_435_probe.sh`.
- `fuzz_logs/`, `session_2026_jul28/` — raw probe outputs and per-session data.
- `FINDINGS.md`, `LIBKERNEL_ANALYSIS_REPORT.md`, `AGENTS.md` — the full working knowledge base.

**Lab setup required to reproduce:** a PS4 on FW 13.52, "Hamdashi Creative" game save-data
framework (Lua loader on port 9026), or the browser harness served from an HTTP server on the
same LAN. PS4 blackouts/reboots are required after killing actions; time each probe accordingly.

---

## 20. Acknowledgments and Disclosure

This research was conducted on a privately owned console, at the owner's request, for security
research and education. All exploitation was performed against a local test console. No personal
data, PSN account data, or third-party content was accessed or modified.

- **Primary authors:** BillZaiD + research group (consolidation of sessions 2026-07-18 →
  2026-09-15).
- **Ethical note:** The ucred/netevent chain and the WebKit workaround details are *not* here
  published beyond what the public scene already reveals (Poopsploit 1.8/1.9 is public; the
  embargoed browser JB is not ours to release). We release the *measurement* of the 13.52
  sandbox, not a new exploit.
- **License:** MIT (see LICENSE).

---

*End of research paper. Version 1.0 — consolidated 2026-09-15.*

*Any corrections to the sandbox map should be filed as issues in this repository with the live probe
log that produced them.*