-- PS4 FW 13.52 - PROBE FINAL v2
-- Fixed: pipe write, ioctl not named, section markers
-- Every memory read via tonn(), every section in pcall

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
  return tonumber(tostring(v)) or -1
end
local function rb(a) return t(mem.read_byte(a)) end
local function rw(a) return t(mem.read_word(a)) end
local function rd(a) return t(mem.read_dword(a)) end
local function rq(a) return t(mem.read_qword(a)) end

print("=== START ===")

-- Find syscall gadget once (used by all sections)
local function find_gadget()
  local waddr = t(S.syscall_wrapper[20])
  if waddr <= 0 then return nil end
  for i = 0, 30 do
    if rb(waddr+i) == 0x0F and rb(waddr+i+1) == 0x05 then
      return waddr + i
    end
  end
  return nil
end

local function sc(g, scno, a1, a2, a3, a4, a5, a6)
  return t(nat.fcall_with_rax(g, scno, a1 or 0, a2 or 0, a3 or 0, a4 or 0, a5 or 0, a6 or 0))
end

-- S1: Basic
print("[S1]")
pcall(function()
  print(string.format("pid=%d uid=%d sb=%d", t(S.getpid()), t(S.getuid()), t(S.is_in_sandbox())))
end)

-- S2: Pipe
print("[S2]")
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

-- S3: mmap
print("[S3]")
pcall(function()
  print(string.format("mmap=0x%x", t(S.mmap(0, 0x4000, 7, 0x1002, -1, 0))))
end)

-- S4: Devices
print("[S4]")
pcall(function()
  local devs = {"/dev/sbi","/dev/srtc","/dev/dce","/dev/dipsw","/dev/dmem0","/dev/console"}
  for _, dp in ipairs(devs) do
    local b = mem.alloc(128)
    for i = 1, #dp do mem.write_byte(b+i-1, string.byte(dp,i)) end
    mem.write_byte(b+#dp, 0)
    local fd = t(S.open(b, 2, 0))
    if fd >= 0 and fd < 1024 then
      print(string.format("OPEN %s fd=%d", dp, fd))
      S.close(fd)
    end
  end
end)

-- S5: Socket
print("[S5]")
pcall(function()
  local a = t(S.socket(2,1,0))
  print(string.format("inet=%d", a))
  if a >= 0 then S.close(a) end
  local b = t(S.socket(17,3,0))
  print(string.format("route=%d", b))
  if b >= 0 then S.close(b) end
end)

-- S6: sysctl
print("[S6]")
pcall(function()
  local tests = {
    {"kern.ostype", {1,1}}, {"kern.osrelease", {1,2}}, {"kern.version", {1,4}},
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
      local s = ""
      for i = 0, math.min(len-1, 63) do
        local c = rb(ob+i)
        if c == 0 then break end
        if c >= 32 and c < 127 then s = s .. string.char(c) end
      end
      if #s > 0 then
        print(string.format("%s = '%s'", tt[1], s))
      else
        print(string.format("%s = num=0x%x len=%d", tt[1], num, len))
      end
    end
  end
end)

-- S7: Gadget discovery
print("[S7]")
local gadget = nil
pcall(function()
  gadget = find_gadget()
  if gadget then
    print(string.format("gadget=0x%x", gadget))
    print(string.format("verify=%d", sc(gadget, 20)))
  else
    print("no gadget")
  end
end)

-- S8: kqueue
print("[S8]")
pcall(function()
  if not gadget then return end
  local kq = sc(gadget, 362)
  print(string.format("kqueue=%d", kq))
  if kq < 0 or kq > 1024 then return end

  local ev = mem.alloc(32)
  for i=0,31 do mem.write_byte(ev+i, 0) end
  mem.write_qword(ev+0, 0x42)
  mem.write_word(ev+8, 0xFFF9)
  mem.write_word(ev+10, 0x0011)
  local r = sc(gadget, 363, kq, ev, 1, 0, 0, 0)
  print(string.format("EVFILT_USER ADD=%d", r))

  mem.write_dword(ev+12, 0x80000000)
  r = sc(gadget, 363, kq, ev, 1, 0, 0, 0)
  print(string.format("TRIGGER=%d", r))

  local out = mem.alloc(256)
  for i=0,255 do mem.write_byte(out+i, 0xCC) end
  r = sc(gadget, 363, kq, 0, 0, out, 4, 0)
  print(string.format("READ=%d", r))
  if r > 0 then
    local ident = rq(out)
    local filter = rw(out+8)
    local data = rq(out+16)
    local udata = rq(out+24)
    print(string.format("id=0x%x f=%d d=%d u=0x%x", ident, filter, data, udata))
  end

  sc(gadget, 6, kq)
end)

-- S9: PF_ROUTE
print("[S9]")
pcall(function()
  if not gadget then return end
  local rt = sc(gadget, 97, 17, 3, 0)
  print(string.format("PF_ROUTE=%d", rt))
  if rt < 0 or rt > 1024 then return end

  local msg = mem.alloc(256)
  for i=0,255 do mem.write_byte(msg+i, 0) end
  mem.write_dword(msg, 92)
  mem.write_byte(msg+4, 12)
  mem.write_byte(msg+5, 2)
  local sr = sc(gadget, 28, rt, msg, 92, 0, msg, 16)
  print(string.format("sendto=%d", sr))

  local rbuf = mem.alloc(1024)
  for i=0,1023 do mem.write_byte(rbuf+i, 0xCC) end
  local from = mem.alloc(16)
  mem.write_byte(from, 16)
  mem.write_byte(from+1, 17)
  local rl = mem.alloc(8)
  mem.write_qword(rl, 16)
  local rr = sc(gadget, 27, rt, rbuf, 512, 0, from, rl)
  print(string.format("recvfrom=%d", rr))
  if rr > 0 then
    local kptrs = 0
    for i = 0, math.min(rr - 1, 256) do
      if i % 8 == 0 then
        local v = rq(rbuf + i)
        if v > 0x8000000000 and v < 0xFFFF000000000000 then
          kptrs = kptrs + 1
          print(string.format("KPTR +%d=0x%x", i, v))
        end
      end
    end
    print(string.format("kptrs=%d", kptrs))
  end
  sc(gadget, 6, rt)
end)

-- S10: pdfork
print("[S10]")
pcall(function()
  if not gadget then return end
  local pd = mem.alloc(8)
  mem.write_dword(pd, 0)
  local r = sc(gadget, 518, pd)
  print(string.format("pdfork=%d", r))
  if r == 0 then
    print(string.format("pd_fd=%d", rd(pd)))
    sc(gadget, 6, rd(pd))
  end
end)

-- S11: poll
print("[S11]")
pcall(function()
  if not gadget then return end
  local pf = mem.alloc(8)
  sc(gadget, 42, pf)
  local pr, pw = rd(pf), rd(pf+4)
  local wb = mem.alloc(4)
  mem.write_dword(wb, 0x41414141)
  sc(gadget, 4, pw, wb, 4)
  local pfd = mem.alloc(16)
  mem.write_dword(pfd, pr)
  mem.write_word(pfd+4, 1)
  mem.write_dword(pfd+8, 0)
  local r = sc(gadget, 143, pfd, 1, 0)
  print(string.format("poll=%d", r))
  sc(gadget, 6, pr)
  sc(gadget, 6, pw)
end)

-- S12: cap_rights
print("[S12]")
pcall(function()
  if not gadget then return end
  local cp = mem.alloc(8)
  sc(gadget, 42, cp)
  local cfd = rd(cp)
  local cap = mem.alloc(8)
  mem.write_qword(cap, 0x0000000400000003)
  print(string.format("cap_rights_limit=%d", sc(gadget, 533, cfd, cap)))
  print(string.format("cap_ioctls_limit=%d", sc(gadget, 534, cfd, 0, 0)))
  local cio = mem.alloc(64)
  for i=0,63 do mem.write_byte(cio+i, 0) end
  local cg = sc(gadget, 535, cfd, cio, 8)
  print(string.format("cap_ioctls_get=%d", cg))
  if cg == 0 then
    print(string.format("cap_val=0x%x", rq(cio)))
  end
  sc(gadget, 6, cfd)
  sc(gadget, 6, rd(cp+4))
end)

-- S13: Sony 585-677 (non-zero only)
print("[S13]")
pcall(function()
  if not gadget then return end
  for scno = 585, 677 do
    local r = sc(gadget, scno)
    if r ~= -1 and r ~= 0 then
      print(string.format("sc%d=%d", scno, r))
    end
  end
end)

-- S14: Sony 585-677 with buffer
print("[S14]")
pcall(function()
  if not gadget then return end
  local buf = mem.alloc(4096)
  for i=0,4095 do mem.write_byte(buf+i, 0) end
  for scno = 585, 677 do
    local r = sc(gadget, scno, buf, 0x1000)
    if r ~= -1 and r ~= 0 then
      local changed = false
      for i=0,63 do
        if rb(buf+i) ~= 0 then changed=true; break end
      end
      local tag = changed and "WRITTEN" or ""
      print(string.format("sc%d(buf)=%d %s", scno, r, tag))
      if changed then
        local hx = ""
        for i=0,15 do hx = hx .. string.format("%02x ", rb(buf+i)) end
        print("  " .. hx)
      end
    end
  end
end)

print("=== DONE ===")
