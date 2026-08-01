-- PS4 FW 13.52 - MINIMAL PROBE
-- Each section wrapped in pcall, no assumptions

local mem = rawget(_G, "memory")
local S = rawget(_G, "syscall")

local ok, err = pcall(S.resolve, {
  close = 6, pipe = 42, open = 5, read = 3, write = 4,
  getpid = 20, getuid = 24,
  sysctl = 202, mmap = 477,
  socket = 97,
  is_in_sandbox = 585,
})
print("resolve: " .. tostring(ok))

local function tonn(v)
  if v == nil then return -1 end
  if type(v) == "number" then return v end
  if type(v) == "table" and v.h ~= nil then return v.h * 4294967296 + v.l end
  local n = tonumber(tostring(v))
  return n or -1
end

print("=== MINIMAL PROBE ===")

-- Phase 1: Basic
pcall(function()
  print(string.format("getpid = %d", tonn(S.getpid())))
  print(string.format("getuid = %d", tonn(S.getuid())))
  print(string.format("is_in_sandbox = %d", tonn(S.is_in_sandbox())))
end)

-- Phase 2: Pipe + read/write
pcall(function()
  local pf = mem.alloc(8)
  local r = tonn(S.pipe(pf))
  local rd = tonn(mem.read_dword(pf))
  local wr = tonn(mem.read_dword(pf + 4))
  print(string.format("pipe=%d rd=%d wr=%d", r, rd, wr))
  local wbuf = mem.alloc(8)
  mem.write_qword(wbuf, 0x41414141)
  print(string.format("write=%d", tonn(S.write(wr, wbuf, 4))))
  local rbuf = mem.alloc(8)
  print(string.format("read=%d", tonn(S.read(rd, rbuf, 4))))
  print(string.format("data=0x%x", tonn(mem.read_dword(rbuf))))
  tonn(S.close(rd))
  tonn(S.close(wr))
end)

-- Phase 3: mmap
pcall(function()
  local m = tonn(S.mmap(0, 0x4000, 7, 0x1002, -1, 0))
  print(string.format("mmap = 0x%x", m))
end)

-- Phase 4: Device open (safe, one at a time)
pcall(function()
  print("\n--- DEVICES ---")
  local devs = {"/dev/sbi", "/dev/srtc", "/dev/dce", "/dev/dipsw", "/dev/dmem0", "/dev/console"}
  for _, dp in ipairs(devs) do
    local buf = mem.alloc(128)
    for i = 1, #dp do mem.write_byte(buf + i - 1, string.byte(dp, i)) end
    mem.write_byte(buf + #dp, 0)
    local ok2, fd = pcall(S.open, buf, 2, 0)
    if ok2 then
      fd = tonn(fd)
      if fd >= 0 and fd < 1024 then
        print(string.format("  OPEN %s fd=%d", dp, fd))
        S.close(fd)
      else
        print(string.format("  BLOCKED %s ret=%d", dp, fd))
      end
    else
      print(string.format("  CRASH %s", dp))
    end
  end
end)

-- Phase 5: Socket
pcall(function()
  print("\n--- SOCKET ---")
  local fd = tonn(S.socket(2, 1, 0))
  print(string.format("AF_INET stream = %d", fd))
  if fd >= 0 then S.close(fd) end
end)

-- Phase 6: kqueue via raw wrapper
pcall(function()
  print("\n--- KQUEUE ---")
  local w = S.syscall_wrapper[362]
  if w and type(w) == "table" then
    local wfn = w.call
    if type(wfn) == "function" then
      local ok2, kq = pcall(wfn)
      print(string.format("kqueue = %s %s", tostring(ok2), tostring(tonn(kq))))
    else
      print("no .call method")
    end
  end
end)

-- Phase 7: sysctl via wrapper
pcall(function()
  print("\n--- SYSCTL ---")
  local w = S.syscall_wrapper[202]
  if w and w.call then
    -- Build MIB for kern.ostype = {1, 1}
    local mib = mem.alloc(8)
    mem.write_dword(mib, 1)
    mem.write_dword(mib + 4, 1)
    local out = mem.alloc(256)
    for i = 0, 255 do mem.write_byte(out + i, 0) end
    local outlen = mem.alloc(8)
    mem.write_qword(outlen, 256)
    local ok2, r = pcall(w.call, mib, 2, out, outlen, 0, 0)
    print(string.format("sysctl = %s %s", tostring(ok2), tostring(tonn(r))))
    if ok2 and tonn(r) == 0 then
      local len = tonn(mem.read_qword(outlen))
      local num = tonn(mem.read_qword(out))
      print(string.format("  len=%d num=0x%x", len, num))
      local hex = ""
      for i = 0, math.min(len - 1, 31) do
        hex = hex .. string.format("%02x ", tonn(mem.read_byte(out + i)))
      end
      print(string.format("  hex: %s", hex))
    end
  end
end)

print("\n=== DONE ===")
