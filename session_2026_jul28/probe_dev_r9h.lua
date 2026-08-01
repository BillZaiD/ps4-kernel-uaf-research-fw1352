-- PS4 FW 13.52 - DMEM0 STRUCTURE CHARACTERIZATION (r9h) — SMALL LOOPS, ONE GAME-LIFE
-- r9g: 16MB mmap on fd5 = REAL non-zero direct memory with self-referencing pointers.
-- Lesson: keep loops <=32. Read targeted offsets only. Then write/readback test.

local mem = rawget(_G, "memory")
local S = rawget(_G, "syscall")

pcall(S.resolve, { mmap = 477 })

local function t(v)
  if v == nil then return -1 end
  if type(v) == "number" then return v end
  if type(v) == "table" and v.h ~= nil then return v.h * 4294967296 + v.l end
  return tonumber(tostring(v)) or -1
end
local function rq(a) return t(mem.read_qword(a)) end

print("=== R9H START ===")
pcall(function()
  local m = t(S.mmap(0, 0x1000000, 3, 0x0001, 5, 0))
  print(string.format("mmap(fd5,16MB)=0x%x", m))
  if not (m > 0x100000 and m < 0xFFFFFFFFFF) then return end

  print("--- header 0x0000-0x0100 (32 qwords) ---")
  for i = 0, 31 do
    local q = rq(m + i*8)
    print(string.format("  +0x%04x: 0x%016x", i*8, q))
  end

  print("--- sparse scan every 0x100000 (16 reads) ---")
  for i = 0, 15 do
    local q = rq(m + i*0x100000)
    print(string.format("  +0x%07x: 0x%016x", i*0x100000, q))
  end

  print("--- write/readback at +0x3000 (was zero) ---")
  local target = m + 0x3000
  local before = rq(target)
  mem.write_qword(target, 0x1352135213521352)
  local back = rq(target)
  print(string.format("  before=0x%016x after=0x%016x %s", before, back,
    (back == 0x1352135213521352) and "WRITABLE!" or "readonly/COW"))
end)
print("=== R9H DONE ===")
