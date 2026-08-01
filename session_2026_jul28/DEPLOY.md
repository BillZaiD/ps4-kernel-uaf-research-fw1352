PS4 FW 13.52 - EXPLOIT DEPLOYMENT GUIDE
========================================

SESSION: 2026_jul28
PS4 IP: 192.168.100.61
Port: 9026
Game: Hamidashi Creative

========================================
TESTING ORDER (send each via nc/netcat)
========================================

PRIORITY 1 — Device Discovery (SAFE, no crash risk)
  cat device_ioctl_fuzzer.lua | nc 192.168.100.61 9026

PRIORITY 2 — /dev/srtc Write-What-Where (may crash if sandboxed)
  cat srtc_writewhatwhere.lua | nc 192.168.100.61 9026

PRIORITY 3 — Sony Memory Syscalls 597-677 (safe, long test)
  cat sony_memory_syscall_test.lua | nc 192.168.100.61 9026

PRIORITY 4 — kqueue UAF Test (will crash if UAF triggers)
  cat kqueue_uaf_exploit.lua | nc 192.168.100.61 9026

PRIORITY 5 — RTSock CVE-2026-3038 (may crash or hang)
  cat cve_2026_3038_rtsock.lua | nc 192.168.100.61 9026

========================================
FULL LIST (16 scripts)
========================================

# Safe Enumeration
device_ioctl_fuzzer.lua      Device × ioctl matrix
device_sysctl_probe.lua      Device + sysctl enum
gpu_token_exploit.lua        GPU + MAC tokens
ps4_utils.lua                Shared utilities (load first)

# Vulnerability Tests
srtc_writewhatwhere.lua      /dev/srtc W^W vuln
sony_memory_syscall_test.lua Syscalls 597-677 fuzzer
sony_full_fuzzer.lua         82 syscalls × 10 patterns
memory_syscall_exploit.lua   Memory syscall targeted

# UAF / Overflow
kqueue_uaf_exploit.lua       kqueue/knote UAF
combined_uaf_rtsock.lua      UAF + RTSock chain
cve_2026_3038_rtsock.lua     RTSock overflow standalone

# Full Chains (need kernel leak first)
chain1_stack_exploit.lua     Stack leak → ROP → ring0
chain2_heap_exploit.lua      Heap overflow → pipe confusion → ring0
top3_vectors_exploit.lua     Memory syscalls + ioctl cross-probe

========================================
WHAT TO REPORT
========================================

After each script, send back to Termux:

1. RETURN VALUES:
   - Positive = success
   - Negative = error/sandboxed
   - Zero = unusual

2. KERNEL POINTERS:
   - Any value in 0xFFFFFFFF80000000 - 0xFFFFFFFFFFFFFFFF range
   - Even ONE kernel pointer = critical breakthrough

3. BUFFER MODIFICATIONS:
   - Did ioctl change the buffer contents?
   - Were kernel values written to userland?

4. CRASHES:
   - Which script crashed?
   - At what line/operation?
   - Did the PS4 reboot?

========================================
KNOWN KERNEL POINTERS (from sysctl)
========================================

kern[4] build string = "r228995/release_13.520 Jun 11 2026"
kern[38] FW version = 0x13520001

These are NOT kernel code pointers but confirm:
  - Kernel is HeerBSD (Sony custom FreeBSD)
  - Built Jun 11 2026
  - W^X enforced, MMU active

========================================
EXPLOIT CHAIN STRATEGY
========================================

Step 1: Get kernel info leak
  - device_ioctl_fuzzer.lua → may find leak in ioctl responses
  - sony_memory_syscall_test.lua → may find leak in syscall returns
  - kqueue UAF → race for kn_fop pointer

Step 2: Use leak to find kernel base
  - If leak = kernel ptr, subtract known offset
  - kern[38] = 0x13520001 → helps calibrate addresses

Step 3: Build ROP chain in userspace
  - Use mmap RW pages
  - Chain syscalls for ring0 transition

Step 4: Execute ring0 payload
  - uid=0, escape jail, root shell
