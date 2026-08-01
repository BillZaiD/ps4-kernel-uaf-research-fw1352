-- PS4 FW 13.52 - DEVICE PROBE R4 (diagnostic open)
-- Question: does open() via gadget work at all? Test /dev/null first.
-- If null opens, open path is fine -> dmem0 open itself is lethal (sandbox death)

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

print("=== DEV-R4 START ===")

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

print("[R4-1] /dev/null flags=0")
pcall(function()
  local fd = open_dev("/dev/null", 0)
  print(string.format("null fd=%d", fd))
  if fd >= 0 and fd < 1024 then sc(gadget, 6, fd) end
end)

print("[R4-2] /dev/null flags=2")
pcall(function()
  local fd = open_dev("/dev/null", 2)
  print(string.format("null fd=%d", fd))
  if fd >= 0 and fd < 1024 then sc(gadget, 6, fd) end
end)

print("[R4-3] /dev/console flags=0")
pcall(function()
  local fd = open_dev("/dev/console", 0)
  print(string.format("console fd=%d", fd))
  if fd >= 0 and fd < 1024 then sc(gadget, 6, fd) end
end)

print("[R4-4] /dev/dce flags=0")
pcall(function()
  local fd = open_dev("/dev/dce", 0)
  print(string.format("dce fd=%d", fd))
  if fd >= 0 and fd < 1024 then sc(gadget, 6, fd) end
end)

print("=== DEV-R4 DONE ===")
