-- PS4 FW 13.52 - DEVICE SURFACE MAPPING (r9c) — SAFE, ONE GAME-LIFE
-- Confirmed (r10): libkernel C functions 0x11400-0x22700 EXECUTABLE via native.fcall.
-- This script: (A) real ioctls on opened dmem0/dce fds WITH buffers,
--              (B) internal device-open functions via native.fcall.
-- ALL paths return gracefully on open/ioctl failure (error codes, not crashes).

local mem = rawget(_G, "memory")
local S = rawget(_G, "syscall")
local nat = rawget(_G, "native")

pcall(S.resolve, { open = 5, close = 6, ioctl = 54 })

local function t(v)
  if v == nil then return -1 end
  if type(v) == "number" then return v end
  if type(v) == "table" and v.h ~= nil then return v.h * 4294967296 + v.l end
  return tonumber(tostring(v)) or -1
end
local function rb(a) return t(mem.read_byte(a)) end

print("=== R9C START ===")

local function open_dev(path, flags)
  local b = mem.alloc(128)
  for i = 1, #path do mem.write_byte(b+i-1, string.byte(path,i)) end
  mem.write_byte(b+#path, 0)
  return t(S.open(b, flags, 0))
end

local function dump(buf, n)
  local hx = ""
  for i = 0, n-1 do hx = hx .. string.format("%02x ", rb(buf+i)) end
  return hx
end

-- A. real ioctls with buffers
print("[A1] ioctl(dmem0, 0x2000800b, buf)")
pcall(function()
  local fd = open_dev("/dev/dmem0", 2)
  print(string.format("  dmem0 fd=%d", fd))
  if fd >= 0 and fd < 1024 then
    local buf = mem.alloc(0x100)
    for i = 0, 0xff do mem.write_byte(buf+i, 0) end
    local r = t(S.ioctl(fd, 0x2000800b, buf))
    print(string.format("  ret=%d", r))
    print("  " .. dump(buf, 16))
    S.close(fd)
  end
end)

print("[A2] ioctl(dce, 0x40084516, buf)")
pcall(function()
  local fd = open_dev("/dev/dce", 2)
  print(string.format("  dce fd=%d", fd))
  if fd >= 0 and fd < 1024 then
    local buf = mem.alloc(0x100)
    for i = 0, 0xff do mem.write_byte(buf+i, 0) end
    local r = t(S.ioctl(fd, 0x40084516, buf))
    print(string.format("  ret=%d", r))
    print("  " .. dump(buf, 16))
    S.close(fd)
  end
end)

print("[A3] ioctl(dce, 0xC0106601 ver, buf)")
pcall(function()
  local fd = open_dev("/dev/dce", 2)
  if fd >= 0 and fd < 1024 then
    local buf = mem.alloc(0x100)
    for i = 0, 0xff do mem.write_byte(buf+i, 0) end
    local r = t(S.ioctl(fd, 0xC0106601, buf))
    print(string.format("  ret=%d", r))
    print("  " .. dump(buf, 16))
    S.close(fd)
  end
end)

-- B. internal device-open functions via native.fcall
local f = S.open.fn_addr
local open_addr = t(f)
local libk = open_addr - 0x2750
print(string.format("libk_base=0x%x", libk))

local calls = {
  {0x16ff0, "DMEM init(open dmem0/1/2+cache)"},
  {0x18210, "DMEM0 opener(ioctl 0x2000800b)"},
  {0x19810, "DIPSW reader"},
  {0x1d400, "GBASE func#1"},
  {0x1d680, "GBASE func#2"},
  {0x1deb0, "DCE func"},
  {0x1a470, "NOTIFICATION func"},
  {0x1f930, "ICC_CONFIG func"},
}
for _, c in ipairs(calls) do
  pcall(function()
    local fn = libk + c[1]
    local ok, ret = pcall(nat.fcall, fn, 0, 0, 0, 0, 0, 0)
    print(string.format("  %-34s ret=%s", c[2], tostring(ret)))
  end)
end

print("=== R9C DONE ===")
