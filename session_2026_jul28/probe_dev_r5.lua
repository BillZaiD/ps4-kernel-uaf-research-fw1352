-- PS4 FW 13.52 - DEVICE PROBE R5
-- Use S.open (named wrapper, proven in probe_final2) instead of gadget+fcall_with_rax.
-- probe_final2 S4 opened dce/dmem0 fine. Replicate exactly.

local mem = rawget(_G, "memory")
local S = rawget(_G, "syscall")

pcall(S.resolve, {
  close = 6, open = 5, ioctl = 54, read = 3, write = 4, lseek = 478, mmap = 477,
})

local function t(v)
  if v == nil then return -1 end
  if type(v) == "number" then return v end
  if type(v) == "table" and v.h ~= nil then return v.h * 4294967296 + v.l end
  return tonumber(tostring(v)) or -1
end
local function rb(a) return t(mem.read_byte(a)) end
local function rq(a) return t(mem.read_qword(a)) end

print("=== DEV-R5 START ===")

local function open_dev(path, flags)
  local b = mem.alloc(128)
  for i = 1, #path do mem.write_byte(b+i-1, string.byte(path,i)) end
  mem.write_byte(b+#path, 0)
  return t(S.open(b, flags, 0))
end

print("[R5-1] null via S.open")
pcall(function()
  local fd = open_dev("/dev/null", 2)
  print(string.format("null fd=%d", fd))
  if fd >= 0 and fd < 1024 then S.close(fd) end
end)

print("[R5-2] dce via S.open")
pcall(function()
  local fd = open_dev("/dev/dce", 2)
  print(string.format("dce fd=%d", fd))
  if fd >= 0 and fd < 1024 then S.close(fd) end
end)

print("[R5-3] dmem0 via S.open")
pcall(function()
  local fd = open_dev("/dev/dmem0", 2)
  print(string.format("dmem0 fd=%d", fd))
  if fd >= 0 and fd < 1024 then S.close(fd) end
end)

print("[R5-4] dmem0 + ioctl")
pcall(function()
  local fd = open_dev("/dev/dmem0", 2)
  print(string.format("dmem0 fd=%d", fd))
  if not (fd >= 0 and fd < 1024) then return end
  local buf = mem.alloc(256)
  for i = 0, 255 do mem.write_byte(buf+i, 0xCC) end
  local r = t(S.ioctl(fd, 0x40086418, buf))
  print(string.format("ioctl(size)=%d", r))
  if r == 0 then print(string.format("  size=0x%x", rq(buf))) end
  for i = 0, 255 do mem.write_byte(buf+i, 0xCC) end
  r = t(S.ioctl(fd, 0xC010A802, buf))
  print(string.format("ioctl(0xC010A802)=%d", r))
  if r == 0 then
    local hx = ""
    for i = 0, 31 do hx = hx .. string.format("%02x ", rb(buf+i)) end
    print("  " .. hx)
  end
  S.close(fd)
end)

print("=== DEV-R5 DONE ===")
