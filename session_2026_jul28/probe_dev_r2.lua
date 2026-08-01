-- PS4 FW 13.52 - DEVICE PROBE R2 (safe)
-- Lesson from R1: read(dmem0) directly CRASHES. 
-- R2: open-only + ioctl-only, no raw read(), no mmap on device.
-- Every step isolated, close immediately.

local mem = rawget(_G, "memory")
local S = rawget(_G, "syscall")
local nat = rawget(_G, "native")

pcall(S.resolve, { close = 6, open = 5, ioctl = 54 })

local function t(v)
  if v == nil then return -1 end
  if type(v) == "number" then return v end
  if type(v) == "table" and v.h ~= nil then return v.h * 4294967296 + v.l end
  return tonumber(tostring(v)) or -1
end
local function rb(a) return t(mem.read_byte(a)) end
local function rq(a) return t(mem.read_qword(a)) end

print("=== DEV-R2 START ===")

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
  return sc(gadget, 5, b, flags, 0)
end

-- [E1] dmem0: open O_RDWR, read magic from a small ioctl that needs no setup
print("[E1] dmem0 open only")
pcall(function()
  local dm = open_dev("/dev/dmem0", 2)
  print(string.format("dmem0 fd=%d", dm))
  if dm >= 0 and dm < 1024 then
    local buf = mem.alloc(256)
    for i = 0, 255 do mem.write_byte(buf+i, 0xCC) end
    local r = sc(gadget, 54, dm, 0x40086418, buf)
    print(string.format("ioctl(DIOCGMEDIASIZE 0x40086418)=%d", r))
    if r == 0 then print(string.format("  size=0x%x", rq(buf))) end
    for i = 0, 255 do mem.write_byte(buf+i, 0xCC) end
    r = sc(gadget, 54, dm, 0x40026417, buf)
    print(string.format("ioctl(DIOCGSECTORSIZE)=%d", r))
    if r == 0 then print(string.format("  sz=%d", rq(buf))) end
    for i = 0, 255 do mem.write_byte(buf+i, 0xCC) end
    r = sc(gadget, 54, dm, 0xC010A802, buf)
    print(string.format("ioctl(0xC010A802)=%d", r))
    if r == 0 then
      local hx = ""
      for i = 0, 31 do hx = hx .. string.format("%02x ", rb(buf+i)) end
      print("  " .. hx)
    end
    sc(gadget, 6, dm)
  end
end)

-- [E2] dce: open + version ioctls
print("[E2] dce open only")
pcall(function()
  local dc = open_dev("/dev/dce", 2)
  print(string.format("dce fd=%d", dc))
  if dc >= 0 and dc < 1024 then
    local buf = mem.alloc(256)
    for i = 0, 255 do mem.write_byte(buf+i, 0xCC) end
    local r = sc(gadget, 54, dc, 0xC0106601, buf)
    print(string.format("ioctl(0xC0106601 GET_VERSION)=%d", r))
    if r == 0 then
      local hx = ""
      for i = 0, 31 do hx = hx .. string.format("%02x ", rb(buf+i)) end
      print("  " .. hx)
    end
    sc(gadget, 6, dc)
  end
end)

-- [E3] dce ioctl sweep (no read)
print("[E3] dce ioctl sweep")
pcall(function()
  local dc = open_dev("/dev/dce", 2)
  if not (dc >= 0 and dc < 1024) then return end
  local cmds = {
    0xC0106602, 0xC0106603, 0xC0106604, 0xC0106605,
    0xC0106610, 0xC0106611, 0xC0106612, 0xC0106613,
    0xC0106614, 0xC0106615, 0xC0106620, 0xC0106621,
    0xC0106630, 0xC0106640, 0xC0106650, 0xC0106660,
    0xC0108F00, 0xC0188F01, 0xC0208F02,
  }
  for _, req in ipairs(cmds) do
    local buf = mem.alloc(256)
    for i = 0, 255 do mem.write_byte(buf+i, 0x41 + (i % 26)) end
    local r = sc(gadget, 54, dc, req, buf)
    if r ~= -1 then
      print(string.format("dce ioctl(0x%x)=%d", req, r))
      local hx = ""
      for i = 0, 31 do hx = hx .. string.format("%02x ", rb(buf+i)) end
      print("  " .. hx)
    end
  end
  sc(gadget, 6, dc)
end)

print("=== DEV-R2 DONE ===")
