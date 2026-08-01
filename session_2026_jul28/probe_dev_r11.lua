-- PS4 FW 13.52 - DEVICE PROBE R11 (dmem0 correct structs)
-- Extract the exact buffer layouts from libkernel RE and test ONE cmd per run.
-- To isolate, pass cmd index as arg. Layouts:
--  0xc018800d: {u64 p0; u64 p1; u32 p2}  (0x18)
--  0xc018800e: {u64 a; u64 b; u32 mode}  (0x18) mode 0 or 1
--  0xc018800f: {u64 p0; u64 p1; u32 n; u32 m} (0x18)
--  0x80288012: {u32;u32;u32;u64 p0;u64 p1;u64 p2} (0x28)
--  0xc0408013: {u64 p0;u64 p1;u64 p2;u64 p3;u64 p4;u64 p5;u64 p6;u64 p7} (0x40)
--  0xc0388014: {u64 x5; u64 y2...} (0x38)
--  0x80108017: {u64 a; u32 b; u32 c} (0x10)
--  0xc0208016: {u64 x4...} (0x20)
--  0x2000800b: arg3 = 0 (no buffer)

local mem = rawget(_G, "memory")
local S = rawget(_G, "syscall")

pcall(S.resolve, { close = 6, open = 5, ioctl = 54 })

local function t(v)
  if v == nil then return -1 end
  if type(v) == "number" then return v end
  if type(v) == "table" and v.h ~= nil then return v.h * 4294967296 + v.l end
  return tonumber(tostring(v)) or -1
end
local function rb(a) return t(mem.read_byte(a)) end

print("=== DEV-R11 START ===")

local function open_dev(path, flags)
  local b = mem.alloc(128)
  for i = 1, #path do mem.write_byte(b+i-1, string.byte(path,i)) end
  mem.write_byte(b+#path, 0)
  return t(S.open(b, flags, 0))
end

local fd = open_dev("/dev/dmem0", 2)
print(string.format("dmem0 fd=%d", fd))
if not (fd >= 0 and fd < 1024) then
  print("CANNOT OPEN - DONE")
  return
end

-- Test 0x2000800b first (no buffer - safest, matches libkernel call)
local r = t(S.ioctl(fd, 0x2000800b, 0))
print(string.format("ioctl(0x2000800b, NULL)=%d", r))

-- 0xc0408013: 8 qwords, zero-filled (map request)
local buf = mem.alloc(0x80)
for i = 0, 0x7F do mem.write_byte(buf+i, 0) end
r = t(S.ioctl(fd, 0xc0408013, buf))
print(string.format("ioctl(0xc0408013)=%d", r))
if r ~= -1 then
  local hx = ""
  for i = 0, 63 do hx = hx .. string.format("%02x ", rb(buf+i)) end
  print("  " .. hx)
end

-- 0xc018800d: {u64, u64, u32}
for i = 0, 0x7F do mem.write_byte(buf+i, 0) end
mem.write_qword(buf, 0x1000)
mem.write_qword(buf+8, 0x1000)
mem.write_dword(buf+16, 0)
r = t(S.ioctl(fd, 0xc018800d, buf))
print(string.format("ioctl(0xc018800d)=%d", r))
if r ~= -1 then
  local hx = ""
  for i = 0, 23 do hx = hx .. string.format("%02x ", rb(buf+i)) end
  print("  " .. hx)
end

-- 0xc018800e: {u64, u64, u32 mode=0}
for i = 0, 0x7F do mem.write_byte(buf+i, 0) end
mem.write_qword(buf, 0x1000)
mem.write_qword(buf+8, 0x1000)
mem.write_dword(buf+16, 0)
r = t(S.ioctl(fd, 0xc018800e, buf))
print(string.format("ioctl(0xc018800e, mode=0)=%d", r))
if r ~= -1 then
  local hx = ""
  for i = 0, 23 do hx = hx .. string.format("%02x ", rb(buf+i)) end
  print("  " .. hx)
end

-- 0x80108017: {u64 a, u32 b, u32 c}
for i = 0, 0x7F do mem.write_byte(buf+i, 0) end
mem.write_qword(buf, 0x1000)
mem.write_dword(buf+8, 0)
mem.write_dword(buf+12, 0)
r = t(S.ioctl(fd, 0x80108017, buf))
print(string.format("ioctl(0x80108017)=%d", r))
if r ~= -1 then
  local hx = ""
  for i = 0, 15 do hx = hx .. string.format("%02x ", rb(buf+i)) end
  print("  " .. hx)
end

S.close(fd)
print("=== DEV-R11 DONE ===")
