-- PS4 FW 13.52 - DMEM0/DCE READ+MMAP (r9b) — HIGH RISK, ONE GAME-LIFE
-- If /dev/dmem0 is openable, test read()/pread()/mmap() for direct memory access.
-- Run LAST. A crash here = strong signal the device surface is real but guarded.

local mem = rawget(_G, "memory")
local S = rawget(_G, "syscall")
local nat = rawget(_G, "native")

pcall(S.resolve, {
  open = 5, close = 6, read = 3, write = 4, lseek = 478,
  mmap = 477, ioctl = 54, getpid = 20,
})

local function t(v)
  if v == nil then return -1 end
  if type(v) == "number" then return v end
  if type(v) == "table" and v.h ~= nil then return v.h * 4294967296 + v.l end
  return tonumber(tostring(v)) or -1
end

local function make_cstr(s)
  local b = mem.alloc(#s + 1)
  for i = 1, #s do mem.write_byte(b + i - 1, string.byte(s, i)) end
  mem.write_byte(b + #s, 0)
  return b
end

print("=== R9B START ===")
for _, dp in ipairs({"/dev/dmem0", "/dev/dce"}) do
  pcall(function()
    local b = make_cstr(dp)
    local fd = t(S.open(b, 2, 0))
    if fd < 0 or fd >= 1024 then
      print(string.format("  %-12s NOT OPENED ret=%d", dp, fd))
      return
    end
    print(string.format("  %-12s fd=%d", dp, fd))
    pcall(function()
      local buf = mem.alloc(0x1000)
      local n = t(S.read(fd, buf, 0x1000))
      local q0 = t(mem.read_qword(buf))
      local q1 = t(mem.read_qword(buf + 8))
      print(string.format("    read(fd,0x1000) n=%d q0=0x%016x q1=0x%016x", n, q0, q1))
    end)
    pcall(function()
      local m = t(S.mmap(0, 0x1000, 3, 0x1002, fd, 0))
      print(string.format("    mmap(fd,0x1000,RDWR,MAP_SHARED) = 0x%x", m))
    end)
    S.close(fd)
  end)
end
print("=== R9B DONE ===")
