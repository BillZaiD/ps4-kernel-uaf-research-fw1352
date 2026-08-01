-- PS4 FW 13.52 - DEVICE PROBE R1
-- Focus: /dev/dmem0 (direct memory) + /dev/dce (GPU)
-- KEY FIX vs old probes: scan buffer for writes even when ioctl returns -1
-- Every section in pcall, loops capped, tonn() on all reads

local mem = rawget(_G, "memory")
local S = rawget(_G, "syscall")
local nat = rawget(_G, "native")

pcall(S.resolve, {
  close = 6, open = 5, read = 3, write = 4, lseek = 478,
  sysctl = 202, mmap = 477, ioctl = 54,
})

local function t(v)
  if v == nil then return -1 end
  if type(v) == "number" then return v end
  if type(v) == "table" and v.h ~= nil then return v.h * 4294967296 + v.l end
  return tonumber(tostring(v)) or -1
end
local function rb(a) return t(mem.read_byte(a)) end
local function rd(a) return t(mem.read_dword(a)) end
local function rq(a) return t(mem.read_qword(a)) end

print("=== DEV-R1 START ===")

local gadget = nil
pcall(function()
  local waddr = t(S.syscall_wrapper[20])
  if waddr > 0 then
    for i = 0, 30 do
      if rb(waddr+i) == 0x0F and rb(waddr+i+1) == 0x05 then
        gadget = waddr + i
        break
      end
    end
  end
  print(string.format("gadget=0x%x", gadget or 0))
end)

local function sc(g, scno, a1, a2, a3, a4, a5, a6)
  return t(nat.fcall_with_rax(g, scno, a1 or 0, a2 or 0, a3 or 0, a4 or 0, a5 or 0, a6 or 0))
end

local function open_dev(path, flags)
  local b = mem.alloc(128)
  for i = 1, #path do mem.write_byte(b+i-1, string.byte(path,i)) end
  mem.write_byte(b+#path, 0)
  return t(sc(gadget, 5, b, flags, 0))
end

local function scan_buf(buf, n, label)
  local kptrs = 0
  for i = 0, n-1, 8 do
    local v = rq(buf+i)
    if v > 0xFFFF800000000000 and v < 0xFFFFFFFFFFFFFFFF then
      kptrs = kptrs + 1
      print(string.format("  KPTR %s+0x%x = 0x%x", label, i, v))
    end
  end
  if kptrs == 0 then
    for i = 0, math.min(n-1, 63) do
      if rb(buf+i) ~= 0 then return true end
    end
  end
  return kptrs > 0
end

-- [D1] Open dmem0 + dce + basic read/lseek
print("[D1]")
pcall(function()
  local dm = open_dev("/dev/dmem0", 2)
  print(string.format("dmem0 fd=%d", dm))
  if dm >= 0 and dm < 1024 then
    local buf = mem.alloc(256)
    for i = 0, 255 do mem.write_byte(buf+i, 0xCC) end
    local n = sc(gadget, 3, dm, buf, 256)
    print(string.format("read(dmem0)=%d", n))
    if n > 0 then
      scan_buf(buf, math.min(n, 256), "dmem")
      local hx = ""
      for i = 0, math.min(n-1, 31) do hx = hx .. string.format("%02x ", rb(buf+i)) end
      print("  " .. hx)
    end
    sc(gadget, 6, dm)
  end
end)

pcall(function()
  local dc = open_dev("/dev/dce", 2)
  print(string.format("dce fd=%d", dc))
  if dc >= 0 and dc < 1024 then
    local buf = mem.alloc(256)
    for i = 0, 255 do mem.write_byte(buf+i, 0xCC) end
    local n = sc(gadget, 3, dc, buf, 256)
    print(string.format("read(dce)=%d", n))
    if n > 0 then
      local hx = ""
      for i = 0, math.min(n-1, 31) do hx = hx .. string.format("%02x ", rb(buf+i)) end
      print("  " .. hx)
    end
    sc(gadget, 6, dc)
  end
end)

-- [D2] ioctl sweep on dmem0 - scan buffer even when ret == -1
print("[D2]")
pcall(function()
  local dm = open_dev("/dev/dmem0", 2)
  if not (dm >= 0 and dm < 1024) then
    print("dmem0 not open, skip")
    return
  end
  local cmds = {
    0x40086418, 0x40026417, 0x8004667e, 0x4004667b,
    0xC008A801, 0xC010A801, 0xC020A801,
    0xC008A802, 0xC010A802, 0xC020A802,
    0x8008A801, 0x8010A801, 0x8020A801,
    0x4008A801, 0x4010A801, 0x4020A801,
    0xC0188F01, 0xC0208F02, 0xC0408F03,
    0xC0106601, 0xC0106602, 0xC0106610, 0xC0106630,
    0x40105303, 0x80105303, 0xC0105303,
    0xC0080001, 0xC0080002, 0xC0080003,
  }
  for _, req in ipairs(cmds) do
    local buf = mem.alloc(512)
    for i = 0, 511 do mem.write_byte(buf+i, 0x41 + (i % 26)) end
    local r = sc(gadget, 54, dm, req, buf)
    local mod = scan_buf(buf, 64, "dmem")
    if r ~= -1 or mod then
      print(string.format("ioctl(0x%x)=%d bufmod=%s", req, r, tostring(mod)))
      if r == 0 or mod then
        local hx = ""
        for i = 0, 31 do hx = hx .. string.format("%02x ", rb(buf+i)) end
        print("  " .. hx)
      end
    end
  end
  sc(gadget, 6, dm)
end)

-- [D3] mmap on /dev/dmem0 (direct physical memory?)
print("[D3]")
pcall(function()
  local dm = open_dev("/dev/dmem0", 2)
  if not (dm >= 0 and dm < 1024) then return end
  local m = sc(gadget, 477, 0, 0x4000, 3, 0x1001, dm, 0)
  print(string.format("mmap(dmem0)=0x%x", m))
  if m > 0x100000 and m < 0xFFFFFFFFFFFF then
    local v = rq(m)
    print(string.format("first qword=0x%x", v))
    sc(gadget, 477, m, 0x4000, 0, 0x1002, -1, 0)
  end
  sc(gadget, 6, dm)
end)

print("=== DEV-R1 DONE ===")
