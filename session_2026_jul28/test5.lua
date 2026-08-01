-- PS4 FW 13.52 - MINIMAL PROBE v2
-- Every single operation in pcall, no assumptions

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

print("=== MINIMAL PROBE v2 ===")

-- Phase 1: Basic wrappers
print("\n--- BASIC ---")
pcall(function() print(string.format("getpid = %d", tonn(S.getpid()))) end)
pcall(function() print(string.format("getuid = %d", tonn(S.getuid()))) end)
pcall(function() print(string.format("sandbox = %d", tonn(S.is_in_sandbox()))) end)

-- Phase 2: Pipe + read/write
print("\n--- PIPE ---")
pcall(function()
  local pf = mem.alloc(8)
  local r = tonn(S.pipe(pf))
  local rd = tonn(mem.read_dword(pf))
  local wr = tonn(mem.read_dword(pf + 4))
  print(string.format("pipe=%d rd=%d wr=%d", r, rd, wr))
  local wbuf = mem.alloc(8)
  mem.write_dword(wbuf, 0x41414141)
  print(string.format("write=%d", tonn(S.write(wr, wbuf, 4))))
  local rbuf = mem.alloc(8)
  print(string.format("read=%d", tonn(S.read(rd, rbuf, 4))))
  print(string.format("data=0x%x", tonn(mem.read_dword(rbuf))))
  S.close(rd)
  S.close(wr)
end)

-- Phase 3: mmap
print("\n--- MMAP ---")
pcall(function()
  local m = tonn(S.mmap(0, 0x4000, 7, 0x1002, -1, 0))
  print(string.format("mmap RW = 0x%x", m))
end)

-- Phase 4: Devices (one at a time)
print("\n--- DEVICES ---")
local dev_list = {"/dev/sbi", "/dev/srtc", "/dev/dce", "/dev/dipsw", "/dev/dmem0", "/dev/console"}
for _, dp in ipairs(dev_list) do
  pcall(function()
    local buf = mem.alloc(128)
    for i = 1, #dp do mem.write_byte(buf + i - 1, string.byte(dp, i)) end
    mem.write_byte(buf + #dp, 0)
    local fd = tonn(S.open(buf, 2, 0))
    if fd >= 0 and fd < 1024 then
      print(string.format("  OPEN %s fd=%d", dp, fd))
      S.close(fd)
    else
      print(string.format("  BLOCKED %s ret=%d", dp, fd))
    end
  end)
end

-- Phase 5: Socket
print("\n--- SOCKET ---")
pcall(function()
  local fd = tonn(S.socket(2, 1, 0))
  print(string.format("AF_INET = %d", fd))
  if fd >= 0 then S.close(fd) end
end)

-- Phase 6: sysctl (use named wrapper)
print("\n--- SYSCTL ---")
pcall(function()
  local mib = mem.alloc(8)
  mem.write_dword(mib, 1)
  mem.write_dword(mib + 4, 1)
  local out = mem.alloc(256)
  for i = 0, 255 do mem.write_byte(out + i, 0) end
  local outlen = mem.alloc(8)
  mem.write_qword(outlen, 256)
  local r = tonn(S.sysctl(mib, 2, out, outlen, 0, 0))
  print(string.format("kern.ostype: ret=%d", r))
  if r == 0 then
    local len = tonn(mem.read_qword(outlen))
    local hex = ""
    for i = 0, math.min(len - 1, 31) do
      hex = hex .. string.format("%02x ", tonn(mem.read_byte(out + i)))
    end
    print(string.format("  len=%d hex=%s", len, hex))
    -- try string
    local str = ""
    for i = 0, math.min(len - 1, 63) do
      local c = tonn(mem.read_byte(out + i))
      if c == 0 then break end
      if c >= 32 and c < 127 then str = str .. string.char(c) end
    end
    if #str > 0 then print(string.format("  str='%s'", str)) end
  end
end)

-- Phase 7: kqueue via native fcall (find trampoline carefully)
print("\n--- KQUEUE ---")
pcall(function()
  local nat = rawget(_G, "native")
  -- Find syscall gadget from any wrapper
  local w = tonn(S.syscall_wrapper[20])  -- getpid wrapper
  if w <= 0 then print("no wrapper"); return end
  -- Search for 0F 05 (syscall) instruction
  for i = 0, 30 do
    local b0 = tonn(mem.read_byte(w + i))
    local b1 = tonn(mem.read_byte(w + i + 1))
    if b0 == 0x0F and b1 == 0x05 then
      local gadget = w + i
      print(string.format("  syscall at 0x%x (+%d from wrapper)", gadget, i))
      -- Test with getpid first
      local r = tonn(nat.fcall_with_rax(gadget, 20, 0, 0, 0, 0, 0, 0))
      print(string.format("  verify getpid=%d", r))
      -- Now try kqueue (362)
      local kq = tonn(nat.fcall_with_rax(gadget, 362, 0, 0, 0, 0, 0, 0))
      print(string.format("  kqueue=%d", kq))
      break
    end
  end
end)

-- Phase 8: raw wrapper exploration
print("\n--- RAW WRAPPER ---")
pcall(function()
  for _, scno in ipairs({585, 362, 363, 518, 533, 534, 535, 241, 455, 143}) do
    local w = S.syscall_wrapper[scno]
    if w then
      local addr = tonn(w)
      if addr > 0 then
        -- Check first bytes
        local hex = ""
        for i = 0, 11 do hex = hex .. string.format("%02x ", tonn(mem.read_byte(addr + i))) end
        print(string.format("  sc[%d] @ 0x%x: %s", scno, addr, hex))
      end
    end
  end
end)

print("\n=== DONE ===")
