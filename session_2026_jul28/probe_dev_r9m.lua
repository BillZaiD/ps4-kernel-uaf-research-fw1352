-- PS4 FW 13.52 - DMEM0 PHYSICAL-ADDRESS SEMANTICS (r9m) — ONE GAME-LIFE
-- Q1: do two mmaps of the same offset share the SAME physical region?
-- Q2: does mmap offset = absolute physical address (offset 0x800000 == m+0x800000)?
-- Note: low 16 bits of each qword are unreliable (48-bit window). Compare bits[63:16].

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

print("=== R9M START ===")
pcall(function()
  local m1 = t(S.mmap(0, 0x1000000, 3, 0x0001, 5, 0))
  local m2 = t(S.mmap(0, 0x1000000, 3, 0x0001, 5, 0))
  print(string.format("m1=0x%x m2=0x%x (same offset)", m1, m2))

  local off = 0x1000
  local w = 0x1122334455660000
  mem.write_qword(m1 + off, w)
  local r1 = rq(m1 + off)
  local r2 = rq(m2 + off)
  local hi = math.floor(w / 0x10000)
  print(string.format("write 0x%016x -> m1+0x1000=0x%016x m2+0x1000=0x%016x %s",
    w, r1, r2,
    (math.floor(r1 / 0x10000) == hi) and "PERSIST" or "no-write"))

  local m3 = t(S.mmap(0x800000, 0x1000000, 3, 0x0001, 5, 0))
  local w2 = 0x8877665544330000
  mem.write_qword(m3 + off, w2)
  local r3 = rq(m3 + off)
  local r1b = rq(m1 + 0x801000)
  print(string.format("m3=0x%x write 0x%016x -> m3+0x1000=0x%016x m1+0x801000=0x%016x %s",
    m3, w2, r3, r1b,
    (math.floor(r1b / 0x10000) == math.floor(w2 / 0x10000)) and "SAME-PHYS (offset=phys!)" or "different regions"))
end)
print("=== R9M DONE ===")
