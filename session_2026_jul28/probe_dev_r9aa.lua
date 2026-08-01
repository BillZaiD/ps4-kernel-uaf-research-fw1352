-- PS4 FW 13.52 - INFO DRAIN (r9aa): window content scan + read/FIONREAD on internal fds
-- All SAFE: no IN structs on unknown fds. read() returns -1 cleanly on non-read devices.

local mem = rawget(_G, "memory")
local S = rawget(_G, "syscall")

pcall(S.resolve, { ioctl = 54, mmap = 477, read = 3 })

local function t(v)
  if v == nil then return -1 end
  if type(v) == "number" then return v end
  if type(v) == "table" and v.h ~= nil then return v.h * 4294967296 + v.l end
  return tonumber(tostring(v)) or -1
end
local function rq(a) return t(mem.read_qword(a)) end

print("=== R9AA START ===")
pcall(function()
  local buf = mem.alloc(0x400)

  print("--- 1: FIONREAD + read() on internal fds 5,6,7 ---")
  local out = mem.alloc(0x200)
  for _, fd in ipairs({5, 6, 7}) do
    mem.write_buffer(buf, string.rep(string.char(0x00), 0x400), 0x400)
    mem.write_qword(out, 0)
    local fionread = t(S.ioctl(fd, 0x4004667f, out))
    local fion = rq(out)
    local nread = t(S.read(fd, buf, 0x100))
    local first = ""
    if nread > 0 then
      local bytes = mem.read_buffer(buf, math.min(nread, 16))
      for i = 1, #bytes do first = first .. string.format("%02x", string.byte(bytes, i)) end
    end
    print(string.format("  fd%d: FIONREAD(0x4004667f)=%d avail=%d read(0x100)=%d hex=%s",
      fd, fionread, fion, nread, first))
  end

  print("--- 2: ioctl 0x4010a802 (OUT 16B) on fd6 (fd7 known ret 0) ---")
  mem.write_buffer(out, string.rep(string.char(0x00), 0x100), 0x100)
  local r7 = t(S.ioctl(7, 0x4010a802, out))
  print(string.format("  fd7: ret=%d out0=0x%016x out1=0x%016x", r7, rq(out), rq(out + 8)))
  mem.write_buffer(out, string.rep(string.char(0x00), 0x100), 0x100)
  local r6 = t(S.ioctl(6, 0x4010a802, out))
  print(string.format("  fd6: ret=%d out0=0x%016x out1=0x%016x", r6, rq(out), rq(out + 8)))

  print("--- 3: window content scan (64KB at phys 0x2ec48000) ---")
  local buf2 = mem.alloc(0x200)
  mem.write_buffer(buf2, string.rep(string.char(0x00), 0x200), 0x200)
  mem.write_qword(buf2, 0x2ec48000)
  mem.write_qword(buf2 + 8, 0x100000)
  local rarm = t(S.ioctl(5, 0x80108002, buf2))
  local m = t(S.mmap(0x2ec48000, 0x100000, 3, 0x0001, 5, 0))
  local nz = 0
  local samples = {}
  for i = 0, 0x3fff do
    local v = rq(m + i * 8)
    if v ~= 0 then
      nz = nz + 1
      if nz <= 8 then samples[#samples + 1] = string.format("+0x%05x=0x%016x", i * 8, v) end
    end
  end
  print(string.format("  re-arm=%d mmap=0x%x non-zero qwords in 64KB: %d", rarm, m, nz))
  if #samples > 0 then
    for _, s in ipairs(samples) do print("    " .. s) end
  end
end)
print("=== R9AA DONE ===")
