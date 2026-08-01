-- PS4 FW 13.52 - DEVICE PROBE R10 (dmem0 real ioctls from libkernel RE)
-- Extracted from libkernel.bin @0x18210-0x19000:
--  0x2000800b, 0x80020016, 0x480003f7, 0xc018800d, 0xc018800e,
--  0xc018800f, 0x80288012, 0xc0408013, 0xc0388014, 0x80108017, 0xc0208016
-- Try each with correctly-sized buffers, scan buf even on -1.

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
local function rq(a) return t(mem.read_qword(a)) end

print("=== DEV-R10 START ===")

local function open_dev(path, flags)
  local b = mem.alloc(128)
  for i = 1, #path do mem.write_byte(b+i-1, string.byte(path,i)) end
  mem.write_byte(b+#path, 0)
  return t(S.open(b, flags, 0))
end

local dmem_ioctls = {
  {cmd=0x2000800b, sz=0x20, name="open_init"},
  {cmd=0x80020016, sz=0x8,  name="info16"},
  {cmd=0x480003f7, sz=0x40, name="tune_f7"},
  {cmd=0xc018800d, sz=0x18, name="mem_d"},
  {cmd=0xc018800e, sz=0x18, name="mem_e"},
  {cmd=0xc018800f, sz=0x18, name="mem_f"},
  {cmd=0x80288012, sz=0x28, name="map_12"},
  {cmd=0xc0408013, sz=0x40, name="map_13"},
  {cmd=0xc0388014, sz=0x38, name="alloc_14"},
  {cmd=0x80108017, sz=0x10, name="map_17"},
  {cmd=0xc0208016, sz=0x20, name="map_16"},
}

print("[R10-1] dmem0 real ioctls")
pcall(function()
  local fd = open_dev("/dev/dmem0", 2)
  print(string.format("dmem0 fd=%d", fd))
  if not (fd >= 0 and fd < 1024) then return end

  for _, io in ipairs(dmem_ioctls) do
    pcall(function()
      local buf = mem.alloc(io.sz + 64)
      for i = 0, io.sz + 63 do mem.write_byte(buf+i, 0xCC) end
      local r = t(S.ioctl(fd, io.cmd, buf))
      local hx = ""
      for i = 0, math.min(io.sz-1, 31) do hx = hx .. string.format("%02x ", rb(buf+i)) end
      print(string.format("%s 0x%08x: ret=%d buf[0..%d]=%s", io.name, io.cmd, r, math.min(io.sz-1,31), hx))
    end)
  end
  S.close(fd)
end)

print("[R10-2] dce real ioctls (same family codes)")
pcall(function()
  local fd = open_dev("/dev/dce", 2)
  print(string.format("dce fd=%d", fd))
  if not (fd >= 0 and fd < 1024) then return end

  for _, io in ipairs(dmem_ioctls) do
    pcall(function()
      local buf = mem.alloc(io.sz + 64)
      for i = 0, io.sz + 63 do mem.write_byte(buf+i, 0xCC) end
      local r = t(S.ioctl(fd, io.cmd, buf))
      local hx = ""
      for i = 0, math.min(io.sz-1, 31) do hx = hx .. string.format("%02x ", rb(buf+i)) end
      print(string.format("%s 0x%08x: ret=%d buf=%s", io.name, io.cmd, r, hx))
    end)
  end
  S.close(fd)
end)

print("=== DEV-R10 DONE ===")
