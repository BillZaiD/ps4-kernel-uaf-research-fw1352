-- PS4 FW 13.52 - SAFE TEST 3
-- Uses only named wrappers, careful with uint64

local mem = rawget(_G, "memory")
local S = rawget(_G, "syscall")

local ok, err = pcall(S.resolve, {
  close = 6, pipe = 42, open = 5, read = 3, write = 4,
  getpid = 20, getuid = 24, sigaction = 36,
  sysctl = 202, mmap = 477, mprotect = 74,
  socket = 97, connect = 98, bind = 104, listen = 106,
  accept = 30, getsockopt = 118, setsockopt = 105,
  thr_self = 315, nanosleep = 240,
})
print("resolve: " .. tostring(ok))

local function tonn(v)
  if v == nil then return -1 end
  if type(v) == "table" and v.h then return v.h * 4294967296 + v.l end
  local n = tonumber(tostring(v))
  if n == nil then return -1 end
  return n
end

print("=== SAFE TEST 3 ===")

-- Test each named wrapper safely
local function t(name, fn)
  local ok2, r1, r2 = pcall(fn)
  if ok2 then
    print(string.format("  [OK]   %s = %d", name, tonn(r1)))
    return tonn(r1)
  else
    print(string.format("  [FAIL] %s: %s", name, tostring(r1)))
    return nil
  end
end

t("getpid", function() return S.getpid() end)
t("getuid", function() return S.getuid() end)

-- pipe
local pf = mem.alloc(8)
t("pipe", function() return S.pipe(pf) end)
local rd = tonn(mem.read_dword(pf))
local wr = tonn(mem.read_dword(pf + 4))
print(string.format("  pipe: rd=%d wr=%d", rd, wr))

-- write + read
local wbuf = mem.alloc(8)
mem.write_qword(wbuf, 0xDEADBEEF12345678)
t("write", function() return S.write(wr, wbuf, 8) end)

local rbuf = mem.alloc(8)
t("read", function() return S.read(rd, rbuf, 8) end)
  local val = tonn(mem.read_qword(rbuf))
print(string.format("  read back: 0x%x", val))

-- close
t("close(-1)", function() return S.close(0xFFFFFFFF) end)

-- mmap
t("mmap", function() return S.mmap(0, 0x4000, 7, 0x1002, -1, 0) end)

-- is_in_sandbox
t("is_in_sandbox", function() return S.is_in_sandbox() end)

-- sysctl
print("\n--- SYSCTL ---")
local sysctls = {
  {name = "kern.ostype",  mib = {1, 1}},
  {name = "kern.osrelease", mib = {1, 2}},
  {name = "kern.version",  mib = {1, 4}},
  {name = "kern.argmax",   mib = {1, 8}},
  {name = "kern.usrstack", mib = {1, 32}},
  {name = "kern.firmware", mib = {1, 38}},
  {name = "hw.model",      mib = {6, 2}},
  {name = "hw.ncpu",       mib = {6, 3}},
  {name = "hw.pagesize",   mib = {6, 7}},
}

for _, item in ipairs(sysctls) do
  local mib_buf = mem.alloc(#item.mib * 4)
  for i, v in ipairs(item.mib) do mem.write_dword(mib_buf + (i-1)*4, v) end
  local out_buf = mem.alloc(256)
  for i = 0, 255 do mem.write_byte(out_buf + i, 0) end
  local out_len = mem.alloc(8)
  mem.write_qword(out_len, 256)
  local r = t(item.name, function() return S.sysctl(mib_buf, #item.mib, out_buf, out_len, 0, 0) end)
  if r and r == 0 then
    local actual_len = tonn(mem.read_qword(out_len))
    local num = tonn(mem.read_qword(out_buf))
    local str = ""
    for i = 0, math.min(actual_len - 1, 100) do
      local c = tonn(mem.read_byte(out_buf + i))
      if c == 0 then break end
      str = str .. string.char(c)
    end
    if #str > 0 then
      print(string.format("    = '%s'", str))
    else
      print(string.format("    = 0x%x (len=%d)", num, actual_len))
      if num > 0x80000000 and num < 0xffff000000000000 then
        print("    *** KERNEL PTR? ***")
      end
    end
  end
end

-- Device enumeration
print("\n--- DEVICES ---")
local devs = {"/dev/sbi", "/dev/srtc", "/dev/dce", "/dev/dipsw", "/dev/dmem0", "/dev/dmem1", "/dev/notification0", "/dev/console", "/dev/evlg0", "/dev/gpu0", "/dev/icc0", "/dev/sdk_eventlog"}
local open_fds = {}
for _, dp in ipairs(devs) do
  local buf = mem.alloc(128)
  for i = 1, #dp do mem.write_byte(buf + i - 1, string.byte(dp, i)) end
  mem.write_byte(buf + #dp, 0)
  local r = t("open " .. dp, function() return S.open(buf, 2, 0) end)
  if r and r >= 0 and r < 1024 then
    open_fds[#open_fds + 1] = {path = dp, fd = r}
  end
end

-- Socket test
print("\n--- SOCKET ---")
local function test_socket(name, af, st, proto)
  local r = t(name, function() return S.socket(af, st, proto) end)
  if r and r >= 0 and r < 1024 then
    S.close(r)
  end
  return r
end

test_socket("AF_INET SOCK_STREAM", 2, 1, 0)
test_socket("AF_INET SOCK_DGRAM", 2, 2, 0)
test_socket("AF_UNIX SOCK_STREAM", 1, 1, 0)
test_socket("AF_ROUTE SOCK_RAW", 17, 3, 0)

print("\n=== TEST 3 DONE ===")
