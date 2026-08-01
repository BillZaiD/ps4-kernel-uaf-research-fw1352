-- PS4 FW 13.52 - DEVICE PROBE R9 (mmap on dmem0)
-- dmem0 = direct memory device. mmap on it = potential physical mem access.
-- Use S.mmap + S.munmap named wrappers. Read ONE page. Very careful.

local mem = rawget(_G, "memory")
local S = rawget(_G, "syscall")

pcall(S.resolve, {
  close = 6, open = 5, mmap = 477,
})

local function t(v)
  if v == nil then return -1 end
  if type(v) == "number" then return v end
  if type(v) == "table" and v.h ~= nil then return v.h * 4294967296 + v.l end
  return tonumber(tostring(v)) or -1
end
local function rb(a) return t(mem.read_byte(a)) end
local function rq(a) return t(mem.read_qword(a)) end

print("=== DEV-R9 START ===")

local function open_dev(path, flags)
  local b = mem.alloc(128)
  for i = 1, #path do mem.write_byte(b+i-1, string.byte(path,i)) end
  mem.write_byte(b+#path, 0)
  return t(S.open(b, flags, 0))
end

print("[R9-1] sanity mmap anon RW")
pcall(function()
  local m = t(S.mmap(0, 0x4000, 3, 0x1002, -1, 0))
  print(string.format("anon mmap=0x%x", m))
  if m > 0x100000 and m < 0xFFFFFFFFFF then
    mem.write_qword(m, 0x4242424242424242)
    print(string.format("rw check=0x%x", rq(m)))
  end
end)

print("[R9-2] mmap /dev/dmem0 page")
pcall(function()
  local fd = open_dev("/dev/dmem0", 2)
  print(string.format("dmem0 fd=%d", fd))
  if not (fd >= 0 and fd < 1024) then return end
  local m = t(S.mmap(0, 0x4000, 3, 0x1001, fd, 0))
  print(string.format("mmap(dmem0)=0x%x", m))
  if m > 0x100000 and m < 0xFFFFFFFFFF then
    local v = rq(m)
    print(string.format("first qword=0x%x", v))
    local v2 = rq(m + 0x1000)
    print(string.format("qword@+0x1000=0x%x", v2))
  end
  S.close(fd)
end)

print("[R9-3] mmap /dev/dce page")
pcall(function()
  local fd = open_dev("/dev/dce", 2)
  print(string.format("dce fd=%d", fd))
  if not (fd >= 0 and fd < 1024) then return end
  local m = t(S.mmap(0, 0x4000, 3, 0x1001, fd, 0))
  print(string.format("mmap(dce)=0x%x", m))
  if m > 0x100000 and m < 0xFFFFFFFFFF then
    local v = rq(m)
    print(string.format("first qword=0x%x", v))
  end
  S.close(fd)
end)

print("=== DEV-R9 DONE ===")
