------------------------------------------------------------
PS4 FW 13.52 - PROCEDESC UAF SANDBOX PROBE
Tests if CVE-2026-45251 exploit chain syscalls are accessible

The exploit requires these syscalls:
  pdfork (518), poll (143), sendmsg (28), recvmsg (27),
  cap_ioctls_limit (534), cap_ioctls_get (535),
  chown (16), chmod (15), pipe (42), close (6)

If any critical syscall is sandboxed, the chain breaks.
This script tests each one and reports accessibility.
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

print("============================================")
print("PS4 FW 13.52 - PROCEDESC UAF PROBE")
print("Testing CVE-2026-45251 exploit chain")
print("============================================")

local results = {}
local critical_fail = false

local function test(name, fn)
  local ok, ret = pcall(fn)
  if ok then
    print(string.format("  [OK]   %s = %d (0x%x)", name, ret, ret))
    results[#results + 1] = {name = name, ok = true, val = ret}
    return ret
  else
    print(string.format("  [FAIL] %s = CRASH", name))
    results[#results + 1] = {name = name, ok = false, val = nil}
    critical_fail = true
    return nil
  end
end

------------------------------------------------------------
-- Test 1: Basic syscalls (already known to work)
------------------------------------------------------------
print("\n--- Basic Syscalls ---")
test("close(6)", function() return s(6, 9999) end)
test("pipe(42)", function()
  local pf = memory.alloc(8)
  return s(42, pf, 0)
end)
test("getpid(20)", function() return s(20) end)
test("getuid(24)", function() return s(24) end)

------------------------------------------------------------
-- Test 2: pdfork (critical for CVE-2026-45251)
------------------------------------------------------------
print("\n--- pdfork (518) ---")
local fdp = memory.alloc(8)
memory.write_dword(fdp, 0)
local pd_ret = test("pdfork(518)", function() return s(518, fdp) end)
local pd_fd = -1
if pd_ret and pd_ret == 0 then
  pd_fd = memory.read_dword(fdp)
  print(string.format("  pdfork success! pd_fd = %d", pd_fd))
  -- Check if it's a valid fd
  local fstat_buf = memory.alloc(1024)
  for i = 0, 1023 do memory.write_byte(fstat_buf + i, 0) end
  local fstat_ret = s(189, pd_fd, fstat_buf)
  print(string.format("  fstat(pd_fd) = %d", fstat_ret))
  if fstat_ret == 0 then
    local file_type = memory.read_byte(fstat_buf + 21)
    print(string.format("  file type = %d (should be 7=DTYPE_PROCDESC)", file_type))
  end
  s(6, pd_fd)
end

------------------------------------------------------------
-- Test 3: poll (critical for UAF trigger)
------------------------------------------------------------
print("\n--- poll (143) ---")
local pipe_fds = memory.alloc(8)
s(42, pipe_fds, 0)
local pipe_rd = memory.read_dword(pipe_fds)
test("poll(143)", function()
  local pollfds = memory.alloc(16)
  memory.write_dword(pollfds, pipe_rd)
  memory.write_word(pollfds + 4, 1)  -- POLLIN
  return s(143, pollfds, 1, 0)
end)

------------------------------------------------------------
-- Test 4: sendmsg/recvmsg (for SCM_RIGHTS)
------------------------------------------------------------
print("\n--- sendmsg/recvmsg (28/27) ---")
test("socketpair AF_UNIX", function()
  local sp = memory.alloc(16)
  local r = s(135, 1, 1, 0, sp)  -- socketpair(1,1,0,sp)
  if r == 0 then
    local s1 = memory.read_dword(sp)
    local s2 = memory.read_dword(sp + 4)
    print(string.format("  socketpair: %d, %d", s1, s2))
  end
  return r
end)

------------------------------------------------------------
-- Test 5: cap_ioctls_limit/get (critical for exploit primitives)
------------------------------------------------------------
print("\n--- cap_ioctls (534/535) ---")
-- cap_rights_limit needs a valid fd and cap_rights struct
test("cap_rights_limit(533)", function()
  local pipe2 = memory.alloc(8)
  s(42, pipe2, 0)
  local pfd = memory.read_dword(pipe2)
  -- cap_rights_t is 8 bytes: CAP_IOCTL | CAP_READ | CAP_WRITE = 0x0000000400000003
  local cap = memory.alloc(8)
  memory.write_qword(cap, 0x0000000400000003)
  local r = s(533, pfd, cap)
  s(6, pfd)
  return r
end)

test("cap_ioctls_limit(534)", function()
  local pipe3 = memory.alloc(8)
  s(42, pipe3, 0)
  local pfd = memory.read_dword(pipe3)
  local cap = memory.alloc(8)
  memory.write_qword(cap, 0x0000000400000003)
  s(533, pfd, cap)
  local r = s(534, pfd, 0, 0)  -- limit with NULL = free
  s(6, pfd)
  return r
end)

test("cap_ioctls_get(535)", function()
  local pipe4 = memory.alloc(8)
  s(42, pipe4, 0)
  local pfd = memory.read_dword(pipe4)
  local cap = memory.alloc(8)
  memory.write_qword(cap, 0x0000000400000003)
  s(533, pfd, cap)
  local out = memory.alloc(64)
  for i = 0, 63 do memory.write_byte(out + i, 0) end
  local r = s(535, pfd, out, 8)
  if r == 0 then
    local val = read_qw(out)
    print(string.format("  cap_ioctls_get returned: 0x%x", val))
  end
  s(6, pfd)
  return r
end)

------------------------------------------------------------
-- Test 6: chown/chmod (for final LPE step)
------------------------------------------------------------
print("\n--- chown/chmod (15/16) ---")
local tmp_path = "/tmp/.probe_test"
local tmp_buf = memory.alloc(64)
for i = 1, #tmp_path do memory.write_byte(tmp_buf + i - 1, string.byte(tmp_path, i)) end
memory.write_byte(tmp_buf + #tmp_path, 0)
test("chown(16)", function()
  local fd = s(5, tmp_buf, 0x241, 0x1B6)  -- create file
  if fd >= 0 and fd < 1024 then
    local r = s(16, tmp_buf, 0, 0)  -- chown to root:root
    s(6, fd)
    s(19, tmp_buf)  -- unlink
    return r
  end
  return -1
end)
test("chmod(15)", function()
  local fd = s(5, tmp_buf, 0x241, 0x1B6)
  if fd >= 0 and fd < 1024 then
    local r = s(15, tmp_buf, 0x8000 | 0x4000 | 0x40)  -- SUID + 0700
    s(6, fd)
    s(19, tmp_buf)
    return r
  end
  return -1
end)

------------------------------------------------------------
-- Test 7: Thread creation (for 2-thread poll UAF)
------------------------------------------------------------
print("\n--- Thread (thr_new 455) ---")
test("thr_new(455)", function()
  local attr = memory.alloc(256)
  for i = 0, 255 do memory.write_byte(attr + i, 0) end
  memory.write_dword(attr, 0x100000)  -- size
  memory.write_dword(attr + 4, 1)     -- flags
  local thr_id = memory.alloc(8)
  return s(455, attr, 256, thr_id, 0)
end)

------------------------------------------------------------
-- SUMMARY
------------------------------------------------------------
print("\n============================================")
print("PROCEDESC UAF SANDBOX RESULTS")
print("============================================")

local critical = {"pdfork(518)", "poll(143)", "cap_ioctls_limit(534)", "cap_ioctls_get(535)"}
local critical_ok = 0

for _, name in ipairs(critical) do
  for _, r in ipairs(results) do
    if r.name == name then
      if r.ok and r.val == 0 then
        critical_ok = critical_ok + 1
        print(string.format("  [PASS] %s", name))
      else
        print(string.format("  [FAIL] %s (SANDDBOXED?)", name))
      end
    end
  end
end

print(string.format("\nCritical syscalls available: %d/%d", critical_ok, #critical))

if critical_ok == #critical then
  print("\n*** CVE-2026-45251 EXPLOIT CHAIN: FEASIBLE ***")
  print("All required syscalls are accessible!")
elseif critical_ok >= 2 then
  print("\n*** PARTIAL: Some exploit primitives available ***")
else
  print("\n*** BLOCKED: Most critical syscalls sandboxed ***")
  print("Try kqueue UAF or device ioctl vectors instead")
end

print("============================================")
print("SEND THIS OUTPUT TO TERMUX")
print("============================================")
