-- R12: single ioctl 0x2000800b on dmem0, NULL arg3 (matches libkernel call pattern)
local mem = rawget(_G, "memory")
local S = rawget(_G, "syscall")
pcall(S.resolve, { close = 6, open = 5, ioctl = 54 })

local function t(v)
  if v == nil then return -1 end
  if type(v) == "number" then return v end
  if type(v) == "table" and v.h ~= nil then return v.h * 4294967296 + v.l end
  return tonumber(tostring(v)) or -1
end

print("=== R12 START ===")
local b = mem.alloc(128)
local p = "/dev/dmem0"
for i = 1, #p do mem.write_byte(b+i-1, string.byte(p,i)) end
mem.write_byte(b+#p, 0)
local fd = t(S.open(b, 2, 0))
print(string.format("dmem0 fd=%d", fd))
if fd >= 0 and fd < 1024 then
  local r = t(S.ioctl(fd, 0x2000800b, 0))
  print(string.format("ioctl(0x2000800b)=%d", r))
  S.close(fd)
end
print("=== R12 DONE ===")
