# Detailed Findings Log

## Environment

```
Platform:    PlayStation 4 (CUH-xxxx)
Firmware:    13.52 (Orbis OS)
Kernel:      FreeBSD 9 derivative
Game:        Hamidashi Creative (CUSA27389)
Tool:        Remote Lua Loader (n0llptr/remote_lua_loader)
Lua Version: 5.1
Sandbox:     ACTIVE (is_in_sandbox() = 1)
UID:         1 (not root)
```

## Critical Discoveries

### 1. EVFILT_USER Filter Value (PS4-Specific)

**Standard FreeBSD**: EVFILT_USER = -4 (0xFFFC)
**PS4 FW 13.52**: EVFILT_USER = -7 (0xFFF9)

This was determined through empirical testing of all filter values from -1 to -10. Using the standard FreeBSD value (-4) causes kevent registration to fail or kernel panics.

```
Filter -1 (0xFFFF): EVFILT_READ   - WORKS
Filter -2 (0xFFFE): EVFILT_WRITE  - WORKS
Filter -3 (0xFFFD): EVFILT_AIO    - WORKS
Filter -4 (0xFFFC): EVFILT_VNODE  - WORKS
Filter -5 (0xFFFB): EVFILT_PROC   - WORKS
Filter -6 (0xFFFA): EVFILT_SIGNAL - WORKS
Filter -7 (0xFFF9): EVFILT_USER   - WORKS (PS4-specific!)
Filter -8 (0xFFF8): EVFILT_FS     - WORKS
```

### 2. libkernel Base Address

```
S.init() output: [+] libkernel base @ 0x80a67c000
Stability:      Confirmed across 3 consecutive calls
Type:           Userland shared library (NOT kernel memory)
Size:           ~576KB (0x80a67c000 to ~0x80a70c000)
```

### 3. Knote UAF Confirmation

```
Without spray: Kernel CRASH (SIGKILL, connection abort)
With 50 spray: SAFE, ~100 events, 0 kernel pointers
With 100 spray: SAFE, ~100 events, 0 kernel pointers
Thread race + spray: SAFE, 5/5 survived, 0 kernel pointers
```

### 4. Sandbox Impact

The PS4 sandbox blocks 60%+ of syscalls:

| Category | Working | Blocked |
|----------|---------|---------|
| File I/O | 50% | 50% |
| Network | 40% | 60% |
| Process | 20% | 80% |
| Memory | 60% | 40% |

### 5. Kernel Hardening Evidence

Sony has systematically removed kernel pointers from all userland-accessible data:

1. **kinfo_proc**: Stripped of all kernel pointers, contains only:
   - Process names ("eboot.bin")
   - Thread names ("SceLibc_Thr")
   - Usernames ("root")
   - MAC labels ("ORBIS kernel SEL")

2. **sysctl**: Returns only strings, small integers, or userland pointers

3. **Socket options**: getsockopt returns 0 for ALL options

4. **Device memory**: /dev/gc mmap returns all zeros

5. **Crypto sysctl**: kern.37/47/48 return high-entropy random data (likely KASLR seeds)

## Syscall Table

### Working Syscalls (via wrapper)

| # | Name | Status | Notes |
|---|------|--------|-------|
| 1 | exit | ✅ | |
| 2 | fork | ✅ | |
| 3 | read | ✅ | |
| 4 | write | ✅ | |
| 5 | open | ✅ | |
| 6 | close | ✅ | |
| 20 | getpid | ✅ | |
| 42 | pipe | ✅ | 65536 byte limit |
| 54 | ioctl | ✅ | On pipes |
| 73 | munmap | ✅ | |
| 97 | socket | ✅ | AF_INET |
| 105 | setsockopt | ✅ | On DGRAM |
| 106 | getsockopt | ✅ | Returns 0 |
| 202 | sysctl | ✅ | kern.* only |
| 362 | kqueue | ✅ | |
| 363 | kevent | ✅ | |
| 477 | mmap | ✅ | ANON only |

### Blocked Syscalls

| # | Name | Error |
|---|------|-------|
| 49 | bind | -1 |
| 90 | dup2 | -1 |
| 92 | fcntl (most) | -1 |
| 104 | connect (alt) | -1 |
| 189 | fstat | CRASH |
| 198 | kldstat | CRASH |
| 432 | thr_self | -1 |
| 509 | closefrom | -1 |

### DANGEROUS Syscalls

| # | Name | Effect |
|---|------|--------|
| kern.49 | sysctl | Kernel CRASH |
| fstat | (sc189) | Kernel CRASH |
| kldstat | (sc198) | Kernel CRASH |
| wrapper+4 | jump | CRASH (only +7 works) |

## Data Collected

| Source | Size | Kernel Ptrs |
|--------|------|-------------|
| kern.* sysctl | ~50 KB | 0 |
| kinfo_proc | ~20 KB | 0 |
| EVFILT_USER events | ~40 KB | 0 |
| /dev/gc mmap | 64 KB | 0 |
| /dev/random | 4 KB | 0 |
| kern.37/47/48 crypto | 384 B | 0 |
| libkernel scan | 576 KB | 0 |
| **Total** | **~760 KB** | **0** |

## Conclusion

The kqueue UAF vulnerability on PS4 FW 13.52 is a real, confirmed bug. However, Sony's kernel hardening (pointer sanitization, sandbox restrictions, syscall filtering) prevents exploitation from the game sandbox. The vulnerability may be exploitable in combination with other bugs or on less restricted firmware versions.
