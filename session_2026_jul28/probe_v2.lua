-- PS4 FW 13.52 - PROBE v2 (Correct API)
-- Uses S.resolve() pattern confirmed working on PS4

local mem = rawget(_G, "memory")
local S = rawget(_G, "syscall")

-- Resolve all syscalls we need
S.resolve({
  getpid = 20, getuid = 24, close = 6, pipe = 42,
  open = 5, read = 3, write = 4,
  kqueue = 362, kevent = 363,
  fork = 241, thr_new = 455,
  socket = 97, connect = 98, bind = 104, listen = 106,
  accept = 30, setsockopt = 105, getsockopt = 118,
  sysctl = 202, ioctl = 54,
  mmap = 477, mprotect = 74,
  chown = 16, chmod = 15, unlink = 19,
  pdfork = 518, poll = 143, select = 93,
  sendto = 28, recvfrom = 27,
  socketpair = 135,
  sigaction = 36, nanosleep = 240,
})

local function tonn(v)
  if v == nil then return 0 end
  if type(v) == "table" and v.h then return v.h * 4294967296 + v.l end
  return tonumber(tostring(v or 0)) or 0
end

print("============================================")
print("PS4 FW 13.52 - PROBE v2")
print("============================================")

------------------------------------------------------------
-- SECTION 1: Basic sanity
------------------------------------------------------------
print("\n=== BASIC SANITY ===")
print(string.format("getpid = %d", tonn(S.getpid())))
print(string.format("getuid = %d", tonn(S.getuid())))

------------------------------------------------------------
-- SECTION 2: Device open test
------------------------------------------------------------
print("\n=== DEVICE OPEN TEST ===")
local dev_list = {
  "/dev/sbi", "/dev/srtc", "/dev/dce", "/dev/dipsw",
  "/dev/dmem0", "/dev/dmem1", "/dev/notification0",
  "/dev/notification1", "/dev/evlg0", "/dev/console",
  "/dev/gpu0", "/dev/icc0", "/dev/icc1",
  "/dev/aci0", "/dev/acp0",
}
local open_fds = {}
for _, dp in ipairs(dev_list) do
  local buf = mem.alloc(128)
  for i = 1, #dp do mem.write_byte(buf + i - 1, string.byte(dp, i)) end
  mem.write_byte(buf + #dp, 0)
  local fd = tonn(S.open(buf, 2, 0))
  if fd >= 0 and fd < 1024 then
    print(string.format("  OPEN %s fd=%d", dp, fd))
    open_fds[dp] = fd
  end
end
print(string.format("Opened %d devices", #open_fds))

------------------------------------------------------------
-- SECTION 3: Socket test (for RTSock)
------------------------------------------------------------
print("\n=== SOCKET TEST ===")
local af_route = 17  -- PF_ROUTE
local sock_stream = 1
local sock_raw = 3
local ipproto_raw = 255

-- Try PF_ROUTE socket
local rt_buf = mem.alloc(4)
mem.write_dword(rt_buf, af_route)
local rt_fd = tonn(S.socket(af_route, sock_raw, 0))
print(string.format("PF_ROUTE socket = %d", rt_fd))

-- Try AF_INET sock_raw
local in_fd = tonn(S.socket(2, sock_raw, ipproto_raw))
print(string.format("AF_INET raw socket = %d", in_fd))

-- Try AF_UNIX socketpair
local sp = mem.alloc(16)
local sp_ret = tonn(S.socketpair(1, 1, 0, sp))
if sp_ret == 0 then
  local sp1 = mem.read_dword(sp)
  local sp2 = mem.read_dword(sp + 4)
  print(string.format("socketpair: %d, %d", sp1, sp2))
else
  print(string.format("socketpair = %d", sp_ret))
end

------------------------------------------------------------
-- SECTION 4: kqueue + kevent
------------------------------------------------------------
print("\n=== KQUEUE/KEVENT ===")
local kq = tonn(S.kqueue())
print(string.format("kqueue = %d", kq))

if kq >= 0 and kq < 1024 then
  -- Test EVFILT_USER (-7 on PS4, not -4!)
  local ev = mem.alloc(32)
  for i = 0, 31 do mem.write_byte(ev + i, 0) end
  mem.write_qword(ev + 0, 0x42)
  mem.write_word(ev + 8, 0xFFF9)      -- EVFILT_USER = -7 on PS4
  mem.write_word(ev + 10, 0x0011)     -- EV_ADD|EV_CLEAR
  mem.write_dword(ev + 12, 0)
  mem.write_qword(ev + 16, 0)
  mem.write_qword(ev + 24, 0)

  local r = tonn(S.kevent(kq, ev, 1, nil, 0, 0))
  print(string.format("kevent(EVFILT_USER ADD) = %d", r))

  -- Trigger
  mem.write_dword(ev + 12, 0x80000000) -- NOTE_TRIGGER
  r = tonn(S.kevent(kq, ev, 1, nil, 0, 0))
  print(string.format("kevent(EVFILT_USER TRIGGER) = %d", r))

  -- Read
  local out = mem.alloc(256)
  for i = 0, 255 do mem.write_byte(out + i, 0xCC) end
  r = tonn(S.kevent(kq, nil, 0, out, 4, 0))
  print(string.format("kevent(READ) = %d events", r))
  if r > 0 then
    local ident = tonn(mem.read_qword(out + 0))
    local filter = mem.read_word(out + 8)
    local data = tonn(mem.read_qword(out + 16))
    print(string.format("  ident=0x%x filter=%d data=%d", ident, filter, data))
  end

  -- Test EVFILT_READ on pipe
  local p = mem.alloc(8)
  S.pipe(p)
  local prd = mem.read_dword(p)
  local pwr = mem.read_dword(p + 4)
  print(string.format("pipe: rd=%d wr=%d", prd, pwr))

  -- Write to pipe
  local wbuf = mem.alloc(16)
  mem.write_qword(wbuf, 0x4141414141414141)
  S.write(pwr, wbuf, 8)

  -- Register EVFILT_READ on pipe
  mem.write_qword(ev + 0, prd)
  mem.write_word(ev + 8, 0xFFFF)  -- EVFILT_READ = -1
  mem.write_word(ev + 10, 0x0001) -- EV_ADD
  mem.write_dword(ev + 12, 0)
  mem.write_qword(ev + 16, 0)
  mem.write_qword(ev + 24, 0)
  r = tonn(S.kevent(kq, ev, 1, nil, 0, 0))
  print(string.format("kevent(EVFILT_READ pipe) = %d", r))

  -- Read events
  for i = 0, 255 do mem.write_byte(out + i, 0xCC) end
  r = tonn(S.kevent(kq, nil, 0, out, 4, 0))
  print(string.format("kevent(READ after pipe write) = %d events", r))
  if r > 0 then
    local ident = tonn(mem.read_qword(out + 0))
    local filter = mem.read_word(out + 8)
    local fflags = mem.read_dword(out + 12)
    local data = tonn(mem.read_qword(out + 16))
    print(string.format("  ident=%d filter=%d fflags=0x%x data=%d", ident, filter, fflags, data))
    -- Check for kernel pointer leak in udata
    local udata = tonn(mem.read_qword(out + 24))
    print(string.format("  udata=0x%x", udata))
    if udata > 0x80000000 then
      print("  *** POTENTIAL KERNEL POINTER LEAK ***")
    end
  end

  S.close(prd)
  S.close(pwr)
  S.close(kq)
end

------------------------------------------------------------
-- SECTION 5: pdfork test (CVE-2026-45251)
------------------------------------------------------------
print("\n=== PDFORK TEST ===")
local pdfd_out = mem.alloc(8)
mem.write_dword(pdfd_out, 0)
local pd_ret = tonn(S.pdfork(pdfd_out))
print(string.format("pdfork = %d", pd_ret))
if pd_ret == 0 then
  local pd_fd = mem.read_dword(pdfd_out)
  print(string.format("  pd_fd = %d", pd_fd))
  S.close(pd_fd)
end

------------------------------------------------------------
-- SECTION 6: sysctl deep scan
------------------------------------------------------------
print("\n=== SYSCTL SCAN ===")
local sysctl_tests = {
  {name = "kern.ostype",      mib = {1, 1}},
  {name = "kern.osrelease",   mib = {1, 2}},
  {name = "kern.version",     mib = {1, 4}},
  {name = "kern.maxproc",     mib = {1, 6}},
  {name = "kern.argmax",      mib = {1, 8}},
  {name = "kern.hostname",    mib = {1, 10}},
  {name = "kern.osreldate",   mib = {1, 17}},
  {name = "kern.firmware",    mib = {1, 38}},
  {name = "kern.usrstack",    mib = {1, 32}},
  {name = "kern.ps_strings",  mib = {1, 46}},
  {name = "hw.model",         mib = {6, 2}},
  {name = "hw.ncpu",          mib = {6, 3}},
  {name = "hw.pagesize",      mib = {6, 7}},
  {name = "hw.physmem",       mib = {6, 5}},
}

for _, t in ipairs(sysctl_tests) do
  local mib_buf = mem.alloc(#t.mib * 4)
  for i, v in ipairs(t.mib) do
    mem.write_dword(mib_buf + (i - 1) * 4, v)
  end
  local out_buf = mem.alloc(256)
  for i = 0, 255 do mem.write_byte(out_buf + i, 0) end
  local out_len = mem.alloc(8)
  mem.write_qword(out_len, 256)
  local r = tonn(S.sysctl(mib_buf, #t.mib, out_buf, out_len, 0, 0))
  if r == 0 then
    local actual_len = tonn(mem.read_qword(out_len))
    -- Try to read as string
    local str = ""
    for i = 0, math.min(actual_len - 1, 100) do
      local c = mem.read_byte(out_buf + i)
      if c == 0 then break end
      str = str .. string.char(c)
    end
    local num = tonn(mem.read_qword(out_buf))
    print(string.format("  %s = \"%s\" (len=%d, num=0x%x)", t.name, str, actual_len, num))
  else
    print(string.format("  %s = FAILED (%d)", t.name, r))
  end
end

------------------------------------------------------------
-- SECTION 7: ioctl on devices
------------------------------------------------------------
print("\n=== IOCTL SCAN ===")
-- Test known ioctl codes on open devices
local ioctl_tests = {
  {dev = "/dev/sbi",  codes = {0xc008a801, 0xc010a802, 0xc008a804, 0x40105303}},
  {dev = "/dev/srtc", codes = {0x40105303, 0x40105305, 0x40105309}},
  {dev = "/dev/dce",  codes = {0xc008a801, 0xc010a802, 0xc040a803}},
}

for _, test in ipairs(ioctl_tests) do
  local buf = mem.alloc(128)
  for i = 1, #test.dev do mem.write_byte(buf + i - 1, string.byte(test.dev, i)) end
  mem.write_byte(buf + #test.dev, 0)
  local fd = tonn(S.open(buf, 2, 0))
  if fd >= 0 and fd < 1024 then
    print(string.format("  %s fd=%d", test.dev, fd))
    for _, code in ipairs(test.codes) do
      local iobuf = mem.alloc(256)
      for i = 0, 255 do mem.write_byte(iobuf + i, 0xCC) end
      local r = tonn(S.ioctl(fd, code, iobuf))
      -- Check if any non-zero data was written by kernel
      local has_data = false
      for i = 0, 63 do
        if mem.read_byte(iobuf + i) ~= 0xCC and mem.read_byte(iobuf + i) ~= 0 then
          has_data = true
          break
        end
      end
      if has_data or r ~= -1 then
        print(string.format("    ioctl(0x%x) = %d [DATA CHANGED!]", code, r))
        -- Dump first 32 bytes
        local hex = ""
        for i = 0, 31 do
          hex = hex .. string.format("%02x ", mem.read_byte(iobuf + i))
        end
        print(string.format("    hex: %s", hex))
      else
        print(string.format("    ioctl(0x%x) = %d (empty)", code, r))
      end
    end
    S.close(fd)
  end
end

------------------------------------------------------------
-- SECTION 8: Memory mapping
------------------------------------------------------------
print("\n=== MEMORY MAPPING ===")
local map_sz = 0x4000
local map = tonn(S.mmap(0, map_sz, 7, 0x1002, -1, 0))
print(string.format("mmap(RWX, 16KB) = 0x%x", map))
if map ~= 0xffffffffffffffff and map > 0 then
  mem.write_byte(map, 0x41)
  local v = mem.read_byte(map)
  print(string.format("  write/read: %d (expect 65)", v))
  -- Write a pattern
  for i = 0, 15 do mem.write_byte(map + i, i) end
  local hex = ""
  for i = 0, 15 do hex = hex .. string.format("%02x ", mem.read_byte(map + i)) end
  print(string.format("  pattern: %s", hex))
end

------------------------------------------------------------
-- SECTION 9: Context restore / thr_new
------------------------------------------------------------
print("\n=== THREAD TEST ===")
local thr_out = mem.alloc(8)
local thr_attr = mem.alloc(256)
for i = 0, 255 do mem.write_byte(thr_attr + i, 0) end
mem.write_dword(thr_attr, 0x100000)
mem.write_dword(thr_attr + 4, 1)
local thr_ret = tonn(S.thr_new(thr_attr, 256, thr_out, 0))
print(string.format("thr_new = %d", thr_ret))

------------------------------------------------------------
-- SECTION 10: pf_route sendto/recvfrom (CVE-2026-3038)
------------------------------------------------------------
print("\n=== PF_ROUTE TEST ===")
if rt_fd >= 0 and rt_fd < 1024 then
  -- Build RTM_GET message
  local msg = mem.alloc(512)
  for i = 0, 511 do mem.write_byte(msg + i, 0) end
  -- struct rt_msghdr
  mem.write_dword(msg + 0, 92)    -- rtm_msglen
  mem.write_byte(msg + 4, 12)     -- rtm_version (RTM_VERSION=12)
  mem.write_byte(msg + 5, 2)      -- rtm_type = RTM_GET
  mem.write_word(msg + 6, 0x0007) -- rtm_index (non-zero)
  mem.write_dword(msg + 8, 0x0806) -- rtm_flags
  mem.write_dword(msg + 12, 0)    -- rtm_addrs
  -- send RTM_GET
  local r = tonn(S.sendto(rt_fd, msg, 92, 0, msg, 16))
  print(string.format("sendto(RTM_GET) = %d", r))

  -- Try recvfrom
  local rbuf = mem.alloc(1024)
  for i = 0, 1023 do mem.write_byte(rbuf + i, 0xCC) end
  local from = mem.alloc(16)
  mem.write_byte(from, 16)
  mem.write_byte(from + 1, 17)  -- AF_ROUTE
  local rlen = mem.alloc(8)
  mem.write_qword(rlen, 16)
  local r2 = tonn(S.recvfrom(rt_fd, rbuf, 512, 0, from, rlen))
  print(string.format("recvfrom(RTM_GET reply) = %d", r2))
  if r2 > 0 then
    -- Check for kernel pointers (non-zero values in unexpected places)
    local kptrs = 0
    for i = 16, math.min(r2 - 8, 256), 8 do
      local v = tonn(mem.read_qword(rbuf + i))
      if v > 0x8000000000 and v < 0xffff000000000000 then
        kptrs = kptrs + 1
        print(string.format("  *** KERNEL PTR at +%d: 0x%x", i, v))
      end
    end
    print(string.format("  kernel pointers found: %d", kptrs))
    -- Dump first 64 bytes
    local hex = ""
    for i = 0, 63 do hex = hex .. string.format("%02x ", mem.read_byte(rbuf + i)) end
    print(string.format("  hex: %s", hex))
  end
  S.close(rt_fd)
end

------------------------------------------------------------
-- SECTION 11: Pipe + poll
------------------------------------------------------------
print("\n=== PIPE + POLL TEST ===")
local p2 = mem.alloc(8)
S.pipe(p2)
local prd2 = mem.read_dword(p2)
local pwr2 = mem.read_dword(p2 + 4)
print(string.format("pipe: rd=%d wr=%d", prd2, pwr2))

-- Write some data
local wbuf2 = mem.alloc(8)
mem.write_qword(wbuf2, 0xDEADBEEFCAFEBABE)
S.write(pwr2, wbuf2, 8)

-- poll
local pollfds = mem.alloc(16)
mem.write_dword(pollfds, prd2)
mem.write_word(pollfds + 4, 1)  -- POLLIN
mem.write_word(pollfds + 6, 0)
mem.write_dword(pollfds + 8, 0)
local poll_r = tonn(S.poll(pollfds, 1, 0))
print(string.format("poll(rd_pipe) = %d", poll_r))

S.close(prd2)
S.close(pwr2)

------------------------------------------------------------
-- SECTION 12: cap_rights syscalls
------------------------------------------------------------
print("\n=== CAP_RIGHTS TEST ===")
S.resolve({cap_rights_limit = 533, cap_ioctls_limit = 534, cap_ioctls_get = 535})

local cp = mem.alloc(8)
S.pipe(cp)
local cp_rd = mem.read_dword(cp)
print(string.format("pipe fd = %d", cp_rd))

-- cap_rights_limit
local cap = mem.alloc(8)
mem.write_qword(cap, 0x0000000400000003) -- CAP_IOCTL|CAP_READ|CAP_WRITE
local cr_ret = tonn(S.cap_rights_limit(cp_rd, cap))
print(string.format("cap_rights_limit = %d", cr_ret))

-- cap_ioctls_limit
local ci_ret = tonn(S.cap_ioctls_limit(cp_rd, 0, 0))
print(string.format("cap_ioctls_limit = %d", ci_ret))

-- cap_ioctls_get
local ci_out = mem.alloc(64)
for i = 0, 63 do mem.write_byte(ci_out + i, 0) end
local cg_ret = tonn(S.cap_ioctls_get(cp_rd, ci_out, 8))
print(string.format("cap_ioctls_get = %d", cg_ret))

S.close(cp_rd)
S.close(mem.read_dword(cp + 4))

------------------------------------------------------------
-- SUMMARY
------------------------------------------------------------
print("\n============================================")
print("PROBE v2 COMPLETE")
print("============================================")
print("SEND THIS OUTPUT TO TERMUX")
print("============================================")
