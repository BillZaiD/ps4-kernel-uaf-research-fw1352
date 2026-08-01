-- PS4 FW 13.52 - DEVICE PROBE R6 (verify fd=22 is real)
-- Question: is fd=22 a real fd or a fixed bogus return from S.open?
-- 1. getpid/getuid via named wrappers (sanity)
-- 2. open /dev/null via S.open, then fstat/read it to confirm it's a real fd
-- 3. open a nonexistent path -> expect -1 (proves open actually syscalls)

local mem = rawget(_G, "memory")
local S = rawget(_G, "syscall")

pcall(S.resolve, {
  close = 6, open = 5, ioctl = 54, read = 3, write = 4,
  getpid = 20, getuid = 24, fstat = 551,
})

local function t(v)
  if v == nil then return -1 end
  if type(v) == "number" then return v end
  if type(v) == "table" and v.h ~= nil then return v.h * 4294967296 + v.l end
  return tonumber(tostring(v)) or -1
end
local function rb(a) return t(mem.read_byte(a)) end
local function rq(a) return t(mem.read_qword(a)) end

print("=== DEV-R6 START ===")

print("[R6-1] named wrapper sanity")
pcall(function()
  print(string.format("getpid=%d getuid=%d", t(S.getpid()), t(S.getuid())))
end)

print("[R6-2] open nonexistent")
pcall(function()
  local b = mem.alloc(64)
  local p = "/no/such/file"
  for i = 1, #p do mem.write_byte(b+i-1, string.byte(p,i)) end
  mem.write_byte(b+#p, 0)
  print(string.format("open(nonexist)=%d (expect -1)", t(S.open(b, 0, 0))))
end)

print("[R6-3] open /dev/null then read")
pcall(function()
  local b = mem.alloc(64)
  local p = "/dev/null"
  for i = 1, #p do mem.write_byte(b+i-1, string.byte(p,i)) end
  mem.write_byte(b+#p, 0)
  local fd = t(S.open(b, 2, 0))
  print(string.format("open(/dev/null)=%d", fd))
  if fd >= 0 and fd < 1024 then
    local buf = mem.alloc(16)
    for i = 0, 15 do mem.write_byte(buf+i, 0) end
    local n = t(S.read(fd, buf, 16))
    print(string.format("read(null)=%d", n))
    S.close(fd)
  end
end)

print("[R6-4] open /dev/dce then ioctl")
pcall(function()
  local b = mem.alloc(64)
  local p = "/dev/dce"
  for i = 1, #p do mem.write_byte(b+i-1, string.byte(p,i)) end
  mem.write_byte(b+#p, 0)
  local fd = t(S.open(b, 2, 0))
  print(string.format("open(/dev/dce)=%d", fd))
  if fd >= 0 and fd < 1024 then
    local buf = mem.alloc(256)
    for i = 0, 255 do mem.write_byte(buf+i, 0xCC) end
    local r = t(S.ioctl(fd, 0xC0106601, buf))
    print(string.format("ioctl(dce ver)=%d", r))
    if r == 0 then
      local hx = ""
      for i = 0, 31 do hx = hx .. string.format("%02x ", rb(buf+i)) end
      print("  " .. hx)
    end
    S.close(fd)
  end
end)

print("=== DEV-R6 DONE ===")
