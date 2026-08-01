-- PS4 FW 13.52 - DMEM ioctl-base then mmap experiment (r9s) — ONE GAME-LIFE
-- Does ioctl(5,0x80108002,{base,size}) change what mmap(fd5,off) maps?
-- Sequence: control mmap -> set{0x100000,0x100000} -> mmap@0 -> mmap@0x100000
--           -> set{0x2ec48000,0x100000} -> mmap@0x2ec48000 -> mmap@0

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

local function setstruct(a, b)
  mem.write_qword(a, 0)
  mem.write_qword(a + 8, 0)
  mem.write_qword(a + 16, 0)
  mem.write_qword(a + 24, 0)
end

print("=== R9S START ===")
pcall(function()
  local buf = mem.alloc(0x200)
  local function doioctl(base, size)
    setstruct(buf, 0)
    mem.write_qword(buf, base)
    mem.write_qword(buf + 8, size)
    return t(S.ioctl(5, 0x80108002, buf))
  end
  local function dump(m, n, tag)
    local s = string.format("  %s map=0x%x:", tag, m)
    for i = 0, n - 1 do s = s .. string.format(" 0x%016x", rq(m + i * 8)) end
    print(s)
  end

  local m0 = t(S.mmap(0, 0x100000, 3, 0x0001, 5, 0))
  dump(m0, 4, "control mmap@0")

  local r = doioctl(0x100000, 0x100000)
  print(string.format("  ioctl set{0x100000,0x100000} ret=0x%x", r))
  local m1 = t(S.mmap(0, 0x100000, 3, 0x0001, 5, 0))
  dump(m1, 4, "after set, mmap@0")
  local m2 = t(S.mmap(0x100000, 0x100000, 3, 0x0001, 5, 0))
  dump(m2, 4, "after set, mmap@0x100000")

  r = doioctl(0x2ec48000, 0x100000)
  print(string.format("  ioctl set{0x2ec48000,0x100000} ret=0x%x", r))
  local m3 = t(S.mmap(0x2ec48000, 0x100000, 3, 0x0001, 5, 0))
  dump(m3, 4, "mmap@0x2ec48000")
  local m4 = t(S.mmap(0, 0x100000, 3, 0x0001, 5, 0))
  dump(m4, 4, "mmap@0 again")
end)
print("=== R9S DONE ===")
