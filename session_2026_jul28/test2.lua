-- PS4 FW 13.52 - SAFE TEST 2
-- Uses only named wrappers + pcall for safety

local mem = rawget(_G, "memory")
local S = rawget(_G, "syscall")
local nat = rawget(_G, "native")

-- Only resolve known-good named wrappers
local ok, err = pcall(S.resolve, {
  close = 6, pipe = 42, open = 5, read = 3, write = 4,
  getpid = 20, getuid = 24, sigaction = 36,
  sysctl = 202, mmap = 477, mprotect = 74,
  socket = 97, connect = 98, bind = 104, listen = 106,
  accept = 30, getsockopt = 118, setsockopt = 105,
  thr_self = 315, nanosleep = 240,
  read = 3, write = 4,
})
print("resolve: " .. tostring(ok) .. " " .. tostring(err))

local function tonn(v)
  if v == nil then return 0 end
  if type(v) == "table" and v.h then return v.h * 4294967296 + v.l end
  return tonumber(tostring(v or 0)) or 0
end

local function scall(fn, ...)
  local r = {pcall(fn, ...)}
  return r[1], r[2]
end

print("=== SAFE TEST 2 ===")

-- Test named wrappers
local function test_call(name, fn)
  local ok, ret = scall(fn)
  if ok then
    print(string.format("  [OK]   %s = %d (0x%x)", name, tonn(ret), tonn(ret)))
  else
    print(string.format("  [FAIL] %s = %s", name, tostring(ret)))
  end
end

test_call("getpid", function() return S.getpid() end)
test_call("getuid", function() return S.getuid() end)

-- pipe
test_call("pipe", function()
  local pf = mem.alloc(8)
  local r = S.pipe(pf)
  return r
end)

-- open + close
test_call("open+close", function()
  local buf = mem.alloc(32)
  mem.write_byte(buf, 47)
  mem.write_byte(buf + 1, 100)
  mem.write_byte(buf + 2, 101)
  mem.write_byte(buf + 3, 118)
  mem.write_byte(buf + 4, 47)
  mem.write_byte(buf + 5, 110)
  mem.write_byte(buf + 6, 117)
  mem.write_byte(buf + 7, 108)
  mem.write_byte(buf + 8, 108)
  mem.write_byte(buf + 9, 0)
  -- /dev/null
  local fd = S.open(buf, 2, 0)
  return fd
end)

-- sysctl
test_call("sysctl kern.ostype", function()
  local mib = mem.alloc(8)
  mem.write_dword(mib, 1)
  mem.write_dword(mib + 4, 1)
  local out = mem.alloc(256)
  for i = 0, 255 do mem.write_byte(out + i, 0) end
  local outlen = mem.alloc(8)
  mem.write_qword(outlen, 256)
  return S.sysctl(mib, 2, out, outlen, 0, 0)
end)

-- read sysctl result
local mib = mem.alloc(8)
mem.write_dword(mib, 1)
mem.write_dword(mib + 4, 1)
local out = mem.alloc(256)
for i = 0, 255 do mem.write_byte(out + i, 0) end
local outlen = mem.alloc(8)
mem.write_qword(outlen, 256)
local sr = S.sysctl(mib, 2, out, outlen, 0, 0)
if tonn(sr) == 0 then
  local str = ""
  for i = 0, 63 do
    local c = mem.read_byte(out + i)
    if c == 0 then break end
    str = str .. string.char(c)
  end
  print(string.format("  sysctl result: %s", str))
end

-- mmap
test_call("mmap RW 16KB", function()
  return S.mmap(0, 0x4000, 7, 0x1002, -1, 0)
end)

-- is_in_sandbox
test_call("is_in_sandbox", function()
  return S.is_in_sandbox()
end)

-- socket
test_call("socket AF_INET", function()
  return S.socket(2, 1, 0)
end)

-- device open
print("\n--- DEVICE OPEN ---")
local dev_tests = {"/dev/sbi", "/dev/srtc", "/dev/dce", "/dev/dipsw", "/dev/dmem0", "/dev/notification0", "/dev/console", "/dev/gpu0"}
for _, dp in ipairs(dev_tests) do
  local buf = mem.alloc(128)
  for i = 1, #dp do mem.write_byte(buf + i - 1, string.byte(dp, i)) end
  mem.write_byte(buf + #dp, 0)
  local fd = scall(S.open, buf, 2, 0)
  if fd and tonn(fd) >= 0 and tonn(fd) < 1024 then
    fd = tonn(fd)
    print(string.format("  OPEN %s fd=%d", dp, fd))
    -- Try ioctl on open device
    local iobuf = mem.alloc(256)
    for i = 0, 255 do mem.write_byte(iobuf + i, 0xCC) end
    local ioret = scall(S.ioctl or function() return -1 end, fd, 0xc010a802, iobuf)
    print(string.format("    ioctl(0xc010a802) = %s", tostring(ioret)))
    S.close(fd)
  else
    print(string.format("  BLOCKED %s", dp))
  end
end

-- sysctl deep scan
print("\n--- SYSCTL DEEP ---")
local sysctls = {
  {name = "kern.version",    mib = {1, 4}},
  {name = "kern.usrstack",   mib = {1, 32}},
  {name = "kern.firmware",   mib = {1, 38}},
  {name = "hw.model",        mib = {6, 2}},
  {name = "hw.pagesize",     mib = {6, 7}},
}
for _, t in ipairs(sysctls) do
  local mib_buf = mem.alloc(#t.mib * 4)
  for i, v in ipairs(t.mib) do mem.write_dword(mib_buf + (i-1)*4, v) end
  local out_buf = mem.alloc(256)
  for i = 0, 255 do mem.write_byte(out_buf + i, 0) end
  local out_len = mem.alloc(8)
  mem.write_qword(out_len, 256)
  local r = scall(S.sysctl, mib_buf, #t.mib, out_buf, out_len, 0, 0)
  if r and tonn(r) == 0 then
    local actual_len = tonn(mem.read_qword(out_len))
    local num = tonn(mem.read_qword(out_buf))
    local str = ""
    for i = 0, math.min(actual_len - 1, 100) do
      local c = mem.read_byte(out_buf + i)
      if c == 0 then break end
      str = str .. string.char(c)
    end
    print(string.format("  %s = %d bytes, str='%s', num=0x%x", t.name, actual_len, str, num))
    if num > 0x80000000 and num < 0xffff000000000000 then
      print("    *** POTENTIAL KERNEL PTR ***")
    end
  else
    print(string.format("  %s = FAIL: %s", t.name, tostring(r)))
  end
end

print("\n=== TEST 2 DONE ===")
