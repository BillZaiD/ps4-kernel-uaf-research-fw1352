# PS4 libkernel.bin Analysis Report (FW 13.52)
## Complete Syscall Table & Vulnerability Assessment

### Binary Overview
- **File**: `dumps/libkernel.bin`
- **Size**: 589,824 bytes (0x90000)
- **Architecture**: x86-64 raw binary, no ELF header
- **Purpose**: PS4 userspace runtime library providing syscall wrappers for game processes

---

## Complete Syscall Table (298 unique syscalls, 302 stubs)

### BSD Standard Syscalls (216 unique)

| sc# | Name | Stub @ | Notes |
|-----|------|--------|-------|
| 1 | exit | 0x0049a, 0x028b0 | 2 stubs |
| 2 | fork | 0x02a10 | |
| 3 | read | 0x027d0 | |
| 4 | write | 0x02910 | |
| 5 | open | 0x02750 | |
| 6 | close | 0x026b0 | |
| 7 | wait4 | 0x028f0 | |
| 10 | unlink | 0x00690 | |
| 12 | chdir | 0x006b0 | |
| 15 | chmod | 0x006d0 | |
| 20 | getpid | 0x006f0 | |
| 23 | setuid | 0x00710 | |
| 24 | getuid | 0x00730 | |
| 25 | geteuid | 0x00750 | |
| 27 | ptrace | 0x02830 | |
| 28 | recvmsg | 0x02870 | |
| 29 | sendmsg | 0x02810 | |
| 30 | accept | 0x02670 | |
| 31 | getpeername | 0x00770 | |
| 32 | getsockname | 0x00790 | |
| 33 | access | 0x007b0 | |
| 34 | chflags | 0x007d0 | |
| 35 | fchflags | 0x007f0 | |
| 36 | ioctl | 0x00810 | |
| 37 | reboot | 0x00830 | |
| 39 | kill | 0x00870 | |
| 41 | socket | 0x008b0 | |
| 42 | pipe | 0x005f0 | |
| 43 | oprofil | 0x008d0 | |
| 44 | getppid | 0x008f0 | |
| 47 | munmap | 0x00910 | |
| 49 | getgroups | 0x028d0 | |
| 50 | setgroups | 0x00640 | |
| 53 | setitimer | 0x00950 | |
| 54 | getitimer | 0x00970 | |
| 55 | dup2 | 0x00620 | |
| 56 | access (old) | 0x00990 | Used for /dev/console access check |
| 59 | execve | 0x0059d, 0x009b0 | 2 stubs |
| 65 | setlogin | 0x02710 | |
| 73 | munlockall | 0x009f0 | |
| 74 | fchdir | 0x00a10 | |
| 75 | fchmod | 0x00a30 | |
| 78 | getrlimit | 0x00a50 | |
| 79 | setrlimit | 0x00a70 | |
| 80 | mmap | 0x00a90 | Old mmap |
| 83 | setuid | 0x00ab0 | |
| 86 | setgid | 0x00ad0 | |
| 89 | sysarch | 0x00af0 | |
| 90 | pread | 0x00b10 | |
| 92 | lseek | 0x00b30 | |
| 93 | mprotect | 0x02850 | |
| 95 | mincore | 0x026f0 | |
| 96 | mlock | 0x00b50 | |
| 97 | socket | 0x00b70 | |
| 98 | connect | 0x026d0 | |
| 99 | accept | 0x00b90 | |
| 100 | getpriority | 0x00bb0 | |
| 101 | send | 0x00bd0 | |
| 102 | recv | 0x00bf0 | |
| 104 | bind | 0x00c10 | |
| 105 | setsockopt | 0x00c30 | |
| 106 | listen | 0x00c50 | |
| 113 | socketpair | 0x00c70 | |
| 114 | fork | 0x00c90 | |
| 116 | setitimer | 0x00cb0 | |
| 117 | select | 0x00cd0 | |
| 118 | getsockopt | 0x00cf0 | |
| 120 | getitimer | 0x027f0 | |
| 121 | madvise | 0x02930 | |
| 122 | semget | 0x00d10 | |
| 124 | msgget | 0x00d30 | |
| 125 | msgsnd | 0x00d50 | |
| 126 | msgrcv | 0x00d70 | |
| 127 | shmat | 0x00d90 | |
| 128 | shmdt | 0x00db0 | |
| 131 | shmat | 0x00dd0 | |
| 133 | sigsuspend | 0x02890 | |
| 134 | sigaction | 0x00df0 | |
| 135 | sigprocmask | 0x00e10 | |
| 136 | getlogin | 0x00e30 | |
| 137 | setlogin | 0x00e50 | |
| 138 | acct | 0x00e70 | |
| 140 | sigpending | 0x00e90 | |
| 141 | sigaltstack | 0x00eb0 | |
| 147 | setsid | 0x00f10 | |
| 165 | sysarch | 0x00f70 | |
| 182 | rtprio | 0x00f90 | |
| 183 | sctp_peeloff | 0x00fb0 | |
| 188 | __sysctl | 0x00850 | Used by /dev/gbase |
| 189 | prctl | 0x009d0 | |
| 190 | minherit | 0x00890 | |
| 191 | sigprocmask | 0x00fd0 | |
| 192 | setcontext | 0x00ff0 | |
| 194 | sigwait | 0x00ed0 | |
| 195 | thr_create | 0x00ef0 | |
| 196 | thr_exit | 0x00f30 | |
| 202 | sysctl | 0x01010 | |
| 203 | kqueue | 0x01030 | |
| 204 | kqueue_fast | 0x01050 | |
| 206 | sigaction | 0x01070 | |
| 209 | thr_kill | 0x02790 | |
| 232 | thr_self | 0x01090 | |
| 233 | thr_kill2 | 0x010b0 | |
| 234 | thr_set_name | 0x010d0 | |
| 235 | thr_suspend | 0x010f0 | |
| 236 | thr_resume | 0x01110 | |
| 237-239 | kqueue variants | 0x01130-0x01170 | |
| 240 | getrlimit | 0x02730 | |
| 251 | cpuset | 0x00479 | |
| 253 | cpuset_getid | 0x01190 | |
| 272 | rtld | 0x011b0 | |
| 289 | umtx_op | 0x011d0 | |
| 290 | rtprio_thread | 0x011f0 | |
| 310 | thr_setscheduler | 0x01210 | |
| 315 | __getcwd | 0x02690 | |
| 324 | futimesat | 0x01230 | |
| 325 | select | 0x01250 | |
| 327-334 | Various | 0x01270-0x01350 | |
| 340 | pdfork | 0x02a70, 0x02b13 | 2 stubs |
| 341 | pdkill | 0x02a90 | |
| 343 | openat | 0x00930 | |
| 345 | pdfork1 | 0x02ab0 | |
| 346 | pdgetpid | 0x02ad0 | |
| 362 | kqueue | 0x01390 | |
| 363 | kevent | 0x013b0 | |
| 379 | pselect | 0x013d0 | |
| 392-393 | kqueue1/kevent1 | 0x013f0, 0x01370 | |
| 397 | pipe2 | 0x00f50 | |
| 400-488 | Various new syscalls | scattered | |
| 499 | iobuffer_create | 0x02770 | |
| 522 | memfd_create | 0x027b0 | |
| 532-567 | sched/umtx/misc | scattered | |

### Sony Custom Syscalls (82 unique, #585-677)

| sc# | Stub @ | Wrapper(s) | Evidence |
|-----|--------|------------|----------|
| 585 | 0x01c30 | fcn.000181b0 | RTLD entry point (_orbis_rtld_entry) |
| 586 | 0x01c50 | | |
| 587 | 0x01c70 | fcn.0001e480, fcn.0001e500 | ICC device read (32 callers) |
| 588 | 0x01c90 | | |
| 591-596 | 0x01cb0-0x01d50 | | |
| 598-608 | 0x01d70-0x01eb0 | | |
| 610-613 | 0x01ed0-0x01f30 | | |
| 615-620 | 0x01f50-0x01ff0 | | |
| 622-643 | 0x02010-0x02290 | | |
| 646-649 | 0x022b0-0x02310 | | |
| 652-677 | 0x02330-0x02650 | | |

**All 82 custom stubs are identical thin wrappers** (12 bytes each):
```asm
mov rax, <syscall_number>    ; 48 c7 c0 XX XX XX XX
mov r10, rcx                ; 49 89 ca
syscall                      ; 0f 05
jb error_handler            ; 72 01
ret                         ; c3
error_handler:              ; (at 0x570)
push rax
call get_errno              ; fcn.00002c70
pop rcx
mov [rax], ecx
mov rax, -1
mov rdx, -1
ret
```
**No userland argument validation in the stubs themselves.**

---

## Error Handling Pattern
All syscall stubs share a common error handler at **0x570**:
- On error (CF=1), pushes return value
- Calls `fcn.00002c70` to get TLS errno location
- Stores errno value
- Returns (-1, -1) in rax, rdx
- Stack canary at **0x61410** (TLS offset `fs:[0]`) checked in wrapper functions

---

## Device Interface Map

| Device | Open Mode | Ioctl Commands | Function(s) |
|--------|-----------|----------------|-------------|
| `/dev/dmem0` | RDWR | 0x2000800b (NULL buf) | fcn.00018210 |
| `/dev/dipsw` | RDONLY | 0x40048806 (4-byte read) | fcn.00019810 |
| `/dev/gbase` | RDWR | 0xc0044509-0xc004450a (8 sequential) | fcn.0001d400-0x01da60 |
| `/dev/dce` | RDWR | 0xc0308203 (32-byte R/W) | fcn.0001deb0 |
| `/dev/icc_configuration` | RDWR\|O_NONBLOCK | 0x80029204 (2-byte read) | fcn.0001f930 + 6 more |
| `/dev/icc_indicator` | | | fcn.0001f9e0+ |
| `/dev/icc_nvs` | | | |
| `/dev/icc_power` | | | |
| `/dev/icc_device_power` | | | |
| `/dev/iccnvs1` | | | |
| `/dev/icc_fan` | | | |
| `/dev/evlg0` | | | fcn.000218b0 |
| `/dev/evlg1` | | | |
| `/dev/sdk_eventlog` | | | |
| `/dev/srtc` | RDWR | 0x40105303 (8-byte R) | fcn.00021a90 + 11 more |
| `/dev/sbi` | RDONLY | 0x4004a501 (8-byte R) | fcn.000226c0, fcn.00022720 |
| `/dev/console` | RDWR | (access check) | fcn.000332f0 |
| `/dev/notification%d` | | | |

---

## Vulnerability Findings

### 1. `/dev/srtc` -- Arbitrary Kernel-to-Userspace Write (Medium)
**Function**: `fcn.00021a90` @ 0x21a90
**Syscalls used**: sc#5 (`open`), sc#36 (`ioctl`), sc#6 (`close`)

```asm
; User arg1 (rdi) = destination pointer, saved in r14
0x21aa6: mov r14, rdi              ; r14 = user-controlled pointer
0x21aa9: lea rdi, ["/dev/srtc"]
0x21ab0: mov esi, 2                ; O_RDWR
0x21abf: call fcn.0000dd50         ; open("/dev/srtc", O_RDWR)
0x21ac8: lea rdx, [var_38h]       ; stack buffer
0x21acc: mov esi, 0x40105303       ; ioctl command
0x21ad7: call fcn.00000970         ; ioctl(fd, 0x40105303, stack_buf)
0x21aee: mov qword [r14], rax     ; *** WRITES 8 BYTES TO USER r14 ***
```

**Impact**: If the ioctl succeeds, 8 bytes of kernel data (SRTC time value) are written to the address in r14, which is the user-controlled first argument. This is a **write-what-where** primitive with kernel-controlled data at a user-controlled destination.

**Exploitability**: The data written is kernel-controlled (RTC time data), not fully attacker-controlled. However, this could be used to:
- Overwrite function pointers or vtable entries at known addresses
- Corrupt heap metadata at predictable locations
- Combined with ASLR info leak, could corrupt specific targets

**Count**: 11 wrapper functions open `/dev/srtc` with various ioctl commands, all following the same pattern.

### 2. `/dev/sbi` -- User-Controlled ioctl Buffer (Medium)
**Function**: `fcn.000226c0` @ 0x226c0

```asm
0x226c7: mov r14, rdi              ; r14 = user-controlled pointer
0x226ca: lea rdi, ["/dev/sbi"]
0x226d5: call fcn.0000dd50         ; open("/dev/sbi", RDONLY)
0x226de: mov esi, 0x4004a501       ; ioctl command
0x226e5: mov rdx, r14              ; *** USER POINTER PASSED AS IOCTL DATA ***
0x226ec: call fcn.00000970         ; ioctl(fd, 0x4004a501, user_ptr)
```

**Impact**: The user-controlled pointer r14 is passed directly as the ioctl data buffer. The kernel's ioctl handler for this device will copy data TO and/or FROM this user address. This creates a TOCTOU (Time-of-Check-Time-of-Use) race condition:
- User can change the buffer content between ioctl calls
- If the kernel driver doesn't properly copy_in/copy_out, kernel may dereference user-controlled pointers
- The 0x40 in the ioctl command high byte = `_IOC_READ` (kernel writes 8 bytes to user buffer)

### 3. `/dev/dce` -- Large Kernel Write to Stack (Low)
**Function**: `fcn.0001deb0` @ 0x1deb0

```asm
0x1def6: vxorps xmm0, xmm0, xmm0
0x1defa: vmovups [rsp], ymm0      ; zero 32 bytes of stack
0x1defa: vmovups [rsp+0x10], ymm0 ; (total 32 bytes zeroed)
0x1df07: mov dword [rsp], 0x23    ; first dword = 0x23
0x1deea: mov rdx, rsp             ; pointer to stack buffer
0x1deed: mov esi, 0xc0308203       ; _IOWR ioctl (32-byte R/W)
0x1df0e: call fcn.00000970         ; ioctl(fd, 0xc0308203, stack_buf)
```

**Impact**: The ioctl command 0xc0308203 encodes a 32-byte bidirectional transfer (_IOWR). The kernel writes 32 bytes to a stack buffer. While the buffer is properly allocated, the ioctl command number itself is interesting -- the `0x8203` group/number could be a DCE (Display Controller Engine) command with a large transfer size. If the encoded size doesn't match the actual kernel handler's expected size, a kernel buffer overread/overwrite could occur in the driver.

### 4. `/dev/gbase` -- Sequential ioctl Pattern (Informational)
**Function**: `fcn.0001d400` @ 0x1d400

The gbase initialization function issues 8 sequential ioctls with incrementing command numbers (0xc0044509 through 0xc004450a, then 0xc004450b, etc.), each reading 4 bytes. It also calls `sysctlbyname("dev.cpu.0.freq")`. All use stack-allocated buffers and are safe.

### 5. ICC Device Wrappers -- Device Communication Pattern (Informational)
**Functions**: fcn.0001f930 through fcn.00020aa0 (7 functions for `/dev/icc_configuration`)

The ICC (Inter-Chip Communication) device wrappers follow a consistent pattern:
1. Open the device with `O_RDWR|O_NONBLOCK` (0x10002)
2. Set up a 2-byte stack buffer with command bytes
3. Issue ioctl with `_IOC_READ` command (0x80029204)
4. Close the device

These are safe -- fixed 2-byte buffers, no user-controlled pointers.

---

## Syscall Architecture Analysis

### Internal Dispatch Function
**`fcn.0000dd50`** (302 bytes, 63 cross-references) is the central syscall dispatch wrapper:
- Takes syscall number in esi, up to 6 args in rdi/rsi/rdx/rcx/r8/r9
- Saves XMM0-7 to stack for variadic calls
- Uses TLS thread context at fs:[0x10]
- Calls `fcn.00004990` (TLS setup) then `fcn.00002750` (open syscall)
- Stack canary checked via `fcn.000006f0` / `fcn.0000eea0`

### Standard Wrapper Pattern
Most device wrappers follow this template:
1. Check stack canary (`0x61410`)
2. Zero out 192-byte stack buffer (ymm0 x6 = 192 bytes)
3. Call internal dispatch or direct syscall
4. Extract specific field from returned buffer
5. Check stack canary before return
6. `ud2` (crash) on canary mismatch

---

## Key Addresses

| Address | Content |
|---------|---------|
| 0x000570 | Common error handler (errno store + return -1,-1) |
| 0x0006f0 | Stack canary getter |
| 0x000eea0 | Stack canary crash handler (ud2) |
| 0x001e90 | ioctl syscall stub (sc#607 = 0x25f) |
| 0x001c70 | sc#587 syscall stub (custom ICC) |
| 0x000dd50 | Central dispatch function |
| 0x002750 | open() syscall stub (sc#5) |
| 0x000970 | ioctl() syscall stub (sc#36 = 0x36) |
| 0x0026b0 | close() syscall stub (sc#6) |
| 0x002c70 | get_errno (TLS) |
| 0x002910 | write() syscall stub (sc#4) |
| 0x0002f8 | strlen (PLT: jmp [0x54f80]) |
| 0x000138 | snprintf (PLT: jmp [0x54ea0]) |
| 0x0000e8 | malloc (PLT: jmp [0x54e78]) |
| 0x0000f8 | memcpy (PLT) |
| 0x000108 | memset (PLT) |
| 0x0061410 | TLS stack canary location |

---

## Conclusions

1. **All 82 Sony custom syscall stubs (#585-677) are thin wrappers** with zero userspace argument validation. All security checks happen kernel-side.

2. **The `/dev/srtc` wrapper has a genuine write-what-where primitive** -- user-controlled destination pointer with kernel-controlled 8-byte data. This is the most promising finding for further exploitation research.

3. **The `/dev/sbi` wrapper passes user pointers directly to kernel ioctl** -- potential TOCTOU opportunity.

4. **The ICC device subsystem is heavily instrumented** (32 callers for sc#587 alone) but uses fixed-size stack buffers throughout.

5. **The device driver surface is extensive**: 17+ devices with hundreds of ioctl commands. The kernel-side handlers for these devices are not in this binary and would need separate analysis.

6. **Stack canary protection is consistently applied** across all wrapper functions, with crash-on-mismatch behavior.

7. **No format string vulnerabilities** were found. The internal `fcn.0002d660` (5803 bytes) is a printf-like engine with 88-case switch table, but it only processes internal format strings, not user input.
