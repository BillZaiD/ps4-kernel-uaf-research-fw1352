-- PS4 FW 13.52 - DEVICE PROBE R3 (max isolation)
-- R2 crashed inside open(dmem0,O_RDWR) itself.
-- R3: one device per section, try multiple open flags, NO ioctl at all first.

local mem = rawget(_G, "memory")
local S = rawget(_G, "syscall")
local nat = rawget(_G, "native")

pcall(S.resolve, { close = 6, open = 5 })

local function t(v)
  if v == nil then return -1 end
  if type(v) == "number" then return v end
  if type(v) == "table" and v.h ~= nil then return v.h * 4294967296 + v.l end
  return tonumber(tostring(v)) or -1
end
local function rb(a) return t(mem.read_byte(a)) end

print("=== DEV-R3 START ===")

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

local devs = { "/dev/dmem0", "/dev/dce", "/dev/dipsw", "/dev/gbase" }
local flags = { 0, 2, 0x42 }

for _, dp in ipairs(devs) do
  print("-- " .. dp)
  for _, fl in ipairs(flags) do
    pcall(function()
      local fd = open_dev(dp, fl)
      print(string.format("  open(flags=0x%x)=%d", fl, fd))
      if fd >= 0 and fd < 1024 then
        sc(gadget, 6, fd)
      end
    end)
  end
end

print("=== DEV-R3 DONE ===")
