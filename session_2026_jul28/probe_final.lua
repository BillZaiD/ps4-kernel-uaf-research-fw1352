-- PS4 FW 13.52 - DEFINITIVE PROBE
-- Every memory read wrapped in tonn(), every call in pcall

local mem = rawget(_G, "memory")
local S = rawget(_G, "syscall")
local nat = rawget(_G, "native")

pcall(S.resolve, {
  close = 6, pipe = 42, open = 5, read = 3, write = 4,
  getpid = 20, getuid = 24,
  sysctl = 202, mmap = 477,
  socket = 97, is_in_sandbox = 585,
})

local function t(v)
  if v == nil then return -1 end
  if type(v) == "number" then return v end
  if type(v) == "table" and v.h ~= nil then return v.h * 4294967296 + v.l end
  local n = tonumber(tostring(v))
  return n or -1
end

local function rb(a) return t(mem.read_byte(a)) end
local function rw(a) return t(mem.read_word(a)) end
local function rd(a) return t(mem.read_dword(a)) end
local function rq(a) return t(mem.read_qword(a)) end

print("=== PROBE START ===")
print("S1")

-- 1. Basic
pcall(function()
  print(string.format("getpid=%d getuid=%d sandbox=%d", t(S.getpid()), t(S.getuid()), t(S.is_in_sandbox())))
end)

-- 2. Pipe r/w
pcall(function()
  local pf = mem.alloc(8)
  S.pipe(pf)
  local r, w = rd(pf), rd(pf+4)
  local wb = mem.alloc(4)
  mem.write_dword(wb, 0xDEADBEEF)
  S.write(w, wb, 4)
  local rbuf = mem.alloc(4)
  S.read(r, rbuf, 4)
  print(string.format("pipe r=%d w=%d data=0x%x", r, w, rd(rbuf)))
  S.close(r); S.close(w)
end)

-- 3. mmap
pcall(function()
  print(string.format("mmap=0x%x", t(S.mmap(0, 0x4000, 7, 0x1002, -1, 0))))
end)

-- 4. Devices
pcall(function()
  local devs = {"/dev/sbi","/dev/srtc","/dev/dce","/dev/dipsw","/dev/dmem0","/dev/console","/dev/notification0","/dev/evlg0"}
  for _, dp in ipairs(devs) do
    local b = mem.alloc(128)
    for i = 1, #dp do mem.write_byte(b+i-1, string.byte(dp,i)) end
    mem.write_byte(b+#dp, 0)
    local fd = t(S.open(b, 2, 0))
    if fd >= 0 and fd < 1024 then
      print(string.format("OPEN %s fd=%d", dp, fd))
      -- Try ioctl 0xc010a802
      local ib = mem.alloc(256)
      for i = 0, 255 do mem.write_byte(ib+i, 0xCC) end
      local r = t(S.ioctl(fd, 0xc010a802, ib))
      local ch = false
      for i = 0, 31 do if rb(ib+i) ~= 0xCC then ch=true; break end end
      if r ~= -1 or ch then
        local hx = ""
        for i = 0, 15 do hx = hx .. string.format("%02x ", rb(ib+i)) end
        print(string.format("  ioctl(0xc010a802)=%d data=%s", r, hx))
      end
      -- Try ioctl 0x40105303
      for i = 0, 255 do mem.write_byte(ib+i, 0xCC) end
      r = t(S.ioctl(fd, 0x40105303, ib))
      ch = false
      for i = 0, 31 do if rb(ib+i) ~= 0xCC then ch=true; break end end
      if r ~= -1 or ch then
        local hx = ""
        for i = 0, 15 do hx = hx .. string.format("%02x ", rb(ib+i)) end
        print(string.format("  ioctl(0x40105303)=%d data=%s", r, hx))
      end
      S.close(fd)
    end
  end
end)

-- 5. Socket
pcall(function()
  print(string.format("socket inet=%d unix=%d route=%d", t(S.socket(2,1,0)), t(S.socket(1,1,0)), t(S.socket(17,3,0))))
end)

-- 6. sysctl deep
pcall(function()
  local tests = {
    {"kern.ostype", {1,1}}, {"kern.osrelease", {1,2}}, {"kern.version", {1,4}},
    {"kern.argmax", {1,8}}, {"kern.usrstack", {1,32}}, {"kern.firmware", {1,38}},
    {"hw.model", {6,2}}, {"hw.ncpu", {6,3}}, {"hw.pagesize", {6,7}},
  }
  for _, tt in ipairs(tests) do
    local mb = mem.alloc(#tt[2]*4)
    for i,v in ipairs(tt[2]) do mem.write_dword(mb+(i-1)*4, v) end
    local ob = mem.alloc(256)
    for i=0,255 do mem.write_byte(ob+i, 0) end
    local ol = mem.alloc(8)
    mem.write_qword(ol, 256)
    local r = t(S.sysctl(mb, #tt[2], ob, ol, 0, 0))
    if r == 0 then
      local len = rd(ol)
      local num = rq(ob)
      local hx = ""
      for i = 0, math.min(len-1, 31) do hx = hx .. string.format("%02x ", rb(ob+i)) end
      local s = ""
      for i = 0, math.min(len-1, 63) do
        local c = rb(ob+i)
        if c == 0 then break end
        if c >= 32 and c < 127 then s = s .. string.char(c) end
      end
      print(string.format("sysctl %s: len=%d hex=[%s] str=[%s] num=0x%x", tt[1], len, hx, s, num))
    end
  end
end)

-- 7. kqueue/kevent via native fcall
pcall(function()
  -- Find syscall instruction in any wrapper
  local waddr = t(S.syscall_wrapper[20])
  local syscall_off = -1
  for i = 0, 30 do
    if rb(waddr+i) == 0x0F and rb(waddr+i+1) == 0x05 then
      syscall_off = i
      break
    end
  end
  if syscall_off < 0 then print("no syscall gadget"); return end
  local gadget = waddr + syscall_off
  print(string.format("syscall gadget at 0x%x", gadget))

  -- Test with getpid
  local pid = t(nat.fcall_with_rax(gadget, 20, 0,0,0,0,0,0))
  print(string.format("getpid via gadget=%d", pid))

  -- kqueue
  local kq = t(nat.fcall_with_rax(gadget, 362, 0,0,0,0,0,0))
  print(string.format("kqueue=%d", kq))

  if kq >= 0 and kq < 1024 then
    -- kevent EVFILT_USER
    local ev = mem.alloc(32)
    for i=0,31 do mem.write_byte(ev+i, 0) end
    mem.write_qword(ev+0, 0x42)
    mem.write_word(ev+8, 0xFFF9)   -- EVFILT_USER=-7
    mem.write_word(ev+10, 0x0011)  -- EV_ADD|EV_CLEAR
    local r = t(nat.fcall_with_rax(gadget, 363, kq, ev, 1, 0, 0, 0))
    print(string.format("kevent ADD=%d", r))

    -- Trigger
    mem.write_dword(ev+12, 0x80000000)
    r = t(nat.fcall_with_rax(gadget, 363, kq, ev, 1, 0, 0, 0))
    print(string.format("kevent TRIGGER=%d", r))

    -- Read
    local out = mem.alloc(256)
    for i=0,255 do mem.write_byte(out+i, 0xCC) end
    r = t(nat.fcall_with_rax(gadget, 363, kq, 0, 0, out, 4, 0))
    print(string.format("kevent READ=%d", r))
    if r > 0 then
      for e=0, r-1 do
        local off = e*32
        local ident = rq(out+off)
        local filter = rw(out+off+8)
        local fflags = rd(out+off+12)
        local data = rq(out+off+16)
        local udata = rq(out+off+24)
        print(string.format("  ev[%d]: id=0x%x filt=%d data=%d udata=0x%x", e, ident, filter, data, udata))
      end
    end

    -- EVFILT_READ on pipe
    local pf = mem.alloc(8)
    nat.fcall_with_rax(gadget, 42, pf, 0,0,0,0,0)
    local pr = rd(pf)
    local pw = rd(pf+4)
    local wb = mem.alloc(8)
    mem.write_dword(wb, 0x41414141)
    nat.fcall_with_rax(gadget, 4, pw, wb, 4, 0,0,0)
    mem.write_qword(ev+0, pr)
    mem.write_word(ev+8, 0xFFFF)
    mem.write_word(ev+10, 0x0001)
    mem.write_dword(ev+12, 0)
    mem.write_qword(ev+16, 0)
    mem.write_qword(ev+24, 0)
    r = t(nat.fcall_with_rax(gadget, 363, kq, ev, 1, 0, 0, 0))
    print(string.format("kevent EVFILT_READ=%d", r))
    for i=0,255 do mem.write_byte(out+i, 0xCC) end
    r = t(nat.fcall_with_rax(gadget, 363, kq, 0,0, out, 4, 0))
    print(string.format("kevent READ2=%d", r))
    if r > 0 then
      local ident = rq(out)
      local filter = rw(out+8)
      local data = rq(out+16)
      local udata = rq(out+24)
      print(string.format("  id=%d filt=%d data=%d udata=0x%x", ident, filter, data, udata))
    end

    -- PF_ROUTE
    local rt = t(nat.fcall_with_rax(gadget, 97, 17, 3, 0, 0,0,0))
    print(string.format("PF_ROUTE=%d", rt))
    if rt >= 0 and rt < 1024 then
      local msg = mem.alloc(512)
      for i=0,511 do mem.write_byte(msg+i, 0) end
      mem.write_dword(msg, 92)
      mem.write_byte(msg+4, 12)
      mem.write_byte(msg+5, 2)  -- RTM_GET
      local sr = t(nat.fcall_with_rax(gadget, 28, rt, msg, 92, 0, msg, 16))
      print(string.format("sendto RTM_GET=%d", sr))
      local rbuf = mem.alloc(1024)
      for i=0,1023 do mem.write_byte(rbuf+i, 0xCC) end
      local from = mem.alloc(16)
      mem.write_byte(from, 16)
      mem.write_byte(from+1, 17)
      local rl = mem.alloc(8)
      mem.write_qword(rl, 16)
      local rr = t(nat.fcall_with_rax(gadget, 27, rt, rbuf, 512, 0, from, rl))
      print(string.format("recvfrom=%d", rr))
      if rr > 0 then
        local kptrs = 0
        for i=0, math.min(rr-8, 256) do
          if i%8 == 0 then
            local v = rq(rbuf+i)
            if v > 0x8000000000 and v < 0xffff000000000000 then
              kptrs = kptrs+1
              print(string.format("  KPTR at +%d: 0x%x", i, v))
            end
          end
        end
        print(string.format("  kernel ptrs: %d", kptrs))
      end
      nat.fcall_with_rax(gadget, 6, rt, 0,0,0,0,0)
    end

    -- cap_rights
    local cp = mem.alloc(8)
    nat.fcall_with_rax(gadget, 42, cp, 0,0,0,0,0)
    local cpd = rd(cp)
    local cap = mem.alloc(8)
    mem.write_qword(cap, 0x40000003)
    local cr = t(nat.fcall_with_rax(gadget, 533, cpd, cap, 0,0,0,0))
    print(string.format("cap_rights_limit=%d", cr))
    local ci = t(nat.fcall_with_rax(gadget, 534, cpd, 0, 0, 0,0,0))
    print(string.format("cap_ioctls_limit=%d", ci))
    local cio = mem.alloc(64)
    for i=0,63 do mem.write_byte(cio+i, 0) end
    local cg = t(nat.fcall_with_rax(gadget, 535, cpd, cio, 8, 0,0,0))
    print(string.format("cap_ioctls_get=%d", cg))
    nat.fcall_with_rax(gadget, 6, cpd, 0,0,0,0,0)
    nat.fcall_with_rax(gadget, 6, rd(cp+4), 0,0,0,0,0)

    -- pdfork
    local pd = mem.alloc(8)
    mem.write_dword(pd, 0)
    local pdr = t(nat.fcall_with_rax(gadget, 518, pd, 0,0,0,0,0))
    print(string.format("pdfork=%d", pdr))
    if pdr == 0 then
      local pdfd = rd(pd)
      print(string.format("  pd_fd=%d", pdfd))
      nat.fcall_with_rax(gadget, 6, pdfd, 0,0,0,0,0)
    end

    -- poll
    local pp = mem.alloc(8)
    nat.fcall_with_rax(gadget, 42, pp, 0,0,0,0,0)
    local ppr = rd(pp)
    local ppw = rd(pp+4)
    local pwb = mem.alloc(4)
    mem.write_dword(pwb, 0x41414141)
    nat.fcall_with_rax(gadget, 4, ppw, pwb, 4, 0,0,0)
    local pfd = mem.alloc(16)
    mem.write_dword(pfd, ppr)
    mem.write_word(pfd+4, 1)
    mem.write_dword(pfd+8, 0)
    local pollr = t(nat.fcall_with_rax(gadget, 143, pfd, 1, 0, 0,0,0))
    print(string.format("poll(pipe)=%d", pollr))
    nat.fcall_with_rax(gadget, 6, ppr, 0,0,0,0,0)
    nat.fcall_with_rax(gadget, 6, ppw, 0,0,0,0,0)

    nat.fcall_with_rax(gadget, 6, kq, 0,0,0,0,0)
  end
end)

-- 8. Sony custom 585 scan
pcall(function()
  print("\n--- SONY 585-677 ---")
  local waddr = t(S.syscall_wrapper[20])
  local gadget = 0
  for i=0, 30 do
    if rb(waddr+i) == 0x0F and rb(waddr+i+1) == 0x05 then
      gadget = waddr + i
      break
    end
  end
  if gadget == 0 then return end
  for scno = 585, 677 do
    local r = t(nat.fcall_with_rax(gadget, scno, 0,0,0,0,0,0))
    if r ~= -1 and r ~= 0 then
      print(string.format("  sc%d = %d (0x%x)", scno, r, r))
    end
  end
end)

print("\n=== PROBE DONE ===")
