-- PS4 FW 13.52 - DMEM0 SIZE THRESHOLD SWEEP (r9k) — ONE GAME-LIFE
-- r9j: 8KB mmaps all zeros even offset 0. r9h/i: 16MB mmaps had descriptor table.
-- Test size at offset 0 to find where descriptor table appears.

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

print("=== R9K START ===")

local sizes = {
  {0x4000,    "16K"},
  {0x10000,   "64K"},
  {0x40000,   "256K"},
  {0x100000,  "1M"},
  {0x400000,  "4M"},
  {0x1000000, "16M"},
  {0x4000000, "64M"},
}

for _, s in ipairs(sizes) do
  pcall(function()
    local m = t(S.mmap(0, s[1], 3, 0x0001, 5, 0))
    if not (m > 0x100000 and m < 0xFFFFFFFFFF) then
      print(string.format("  size %-6s FAILED ret=0x%x", s[2], m))
      return
    end
    local q0 = rq(m)
    local q1 = rq(m + 8)
    local q3 = rq(m + 0x18)
    local sig = (q0 == 0x80000000c0012800)
    print(string.format("  size %-6s map=0x%x q0=0x%016x q1=0x%016x q3=0x%016x %s",
      s[2], m, q0, q1, q3, sig and "<=DESC!" or ""))
  end)
end

print("=== R9K DONE ===")
