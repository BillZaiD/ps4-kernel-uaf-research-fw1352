-- PS4 FW 13.52 - INCREMENTAL TEST 1
-- Tests: basic syscalls + device open + ioctl

local mem = rawget(_G, "memory")
local S = rawget(_G, "syscall")
local nat = rawget(_G, "native")

S.resolve({getpid = 20, getuid = 24, close = 6, pipe = 42, open = 5})

local function tonn(v)
  if v == nil then return 0 end
  if type(v) == "table" and v.h then return v.h * 4294967296 + v.l end
  return tonumber(tostring(v or 0)) or 0
end

local function toaddr(v)
  if v == nil then return 0 end
  if type(v) == "table" and v.h then return v.h * 4294967296 + v.l end
  return tonumber(tostring(v))
end

print("=== TEST 1: Syscalls + Devices + Ioctl ===")

-- Build universal trampoline
local w_getpid = toaddr(S.syscall_wrapper[20])
local tramp = w_getpid + 10
print(string.format("tramp = 0x%x", tramp))

local function sc(scno, a1, a2, a3, a4, a5, a6)
  return tonn(nat.fcall_with_rax(tramp, scno, a1 or 0, a2 or 0, a3 or 0, a4 or 0, a5 or 0, a6 or 0))
end

-- Test basic
print(string.format("getpid = %d", sc(20)))
print(string.format("getuid = %d", sc(24)))

-- pipe
local pf = mem.alloc(8)
print(string.format("pipe ret = %d rd=%d wr=%d", sc(42, pf), mem.read_dword(pf), mem.read_dword(pf+4)))
sc(6, mem.read_dword(pf))
sc(6, mem.read_dword(pf+4))

-- devices
print("\n--- DEVICES ---")
local devs = {"/dev/sbi", "/dev/srtc", "/dev/dce", "/dev/dipsw", "/dev/dmem0", "/dev/notification0", "/dev/console", "/dev/gpu0"}
local fds = {}
for _, dp in ipairs(devs) do
  local buf = mem.alloc(128)
  for i = 1, #dp do mem.write_byte(buf + i - 1, string.byte(dp, i)) end
  mem.write_byte(buf + #dp, 0)
  local fd = sc(5, buf, 2, 0)
  if fd >= 0 and fd < 1024 then
    print(string.format("  OPEN %s fd=%d", dp, fd))
    fds[#fds+1] = {path=dp, fd=fd}
  end
end

-- ioctl on open devs
print("\n--- IOCTL ---")
local codes = {0xc008a801, 0xc010a802, 0x40105303, 0x40105305}
for _, item in ipairs(fds) do
  for _, code in ipairs(codes) do
    local iobuf = mem.alloc(256)
    for i = 0, 255 do mem.write_byte(iobuf + i, 0xCC) end
    local r = sc(54, item.fd, code, iobuf)
    local changed = false
    for i = 0, 31 do
      if mem.read_byte(iobuf + i) ~= 0xCC then changed = true; break end
    end
    if r ~= -1 or changed then
      print(string.format("  %s ioctl(0x%x)=%d", item.path, code, r))
      local hex = ""
      for i = 0, 15 do hex = hex .. string.format("%02x ", mem.read_byte(iobuf + i)) end
      print(string.format("    %s", hex))
    end
  end
end

-- cleanup
for _, item in ipairs(fds) do sc(6, item.fd) end

print("\n=== TEST 1 DONE ===")
