-- PS4 FW 13.52 - DMEM0 PHYSICAL BASE DISCOVERY (r9j) — ONE GAME-LIFE
-- Key: is mmap(fd5, off) an ABSOLUTE physical offset? If so, offset=phys
-- maps arbitrary physical memory -> arbitrary phys R/W + KASLR bypass.
-- Test: mmap at many offsets, see which contain the descriptor table (non-zero).

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
local function rd(a) return t(mem.read_dword(a)) end

print("=== R9J START ===")

-- candidate offsets to test (physical base hypotheses)
local offsets = {
  {0x0,          "offset 0 (control)"},
  {0x1000,       "offset 4K"},
  {0x10000,      "offset 64K"},
  {0x100000,     "offset 1M"},
  {0x2ec48000,   "kernel-ptr phys (dmap0xffffffff00000000)"},
  {0xc0027600,   "descriptor base 0xc0027600"},
  {0x80000000,   "offset 2G"},
  {0x40000000,   "offset 1G (was zeros)"},
  {0x10000000,   "offset 256M"},
  {0x08000000,   "offset 128M"},
}

for _, o in ipairs(offsets) do
  pcall(function()
    local m = t(S.mmap(0, 0x2000, 3, 0x0001, 5, o[1]))
    if not (m > 0x100000 and m < 0xFFFFFFFFFF) then
      print(string.format("  %-38s FAILED ret=0x%x", o[2], m))
      return
    end
    local q0 = rq(m)
    local q1 = rq(m + 8)
    local q2 = rq(m + 0x10)
    local q3 = rq(m + 0x18)
    local sig = (q0 == 0x80000000c0012800)
    print(string.format("  %-38s map=0x%x q0=0x%016x q1=0x%016x q2=0x%016x q3=0x%016x %s",
      o[2], m, q0, q1, q2, q3, sig and "<=DESC-TABLE!" or ""))
  end)
end

print("=== R9J DONE ===")
