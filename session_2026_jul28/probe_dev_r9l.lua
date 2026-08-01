-- PS4 FW 13.52 - DMEM0 WRITE PERSISTENCE + DESCRIPTOR REAPPEARANCE (r9l) — ONE GAME-LIFE
-- Q1: do descriptors reappear on a fresh 16MB offset-0 mmap in this session?
-- Q2: are writes to the mapped region persistent (true writable phys) or refreshed?

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

print("=== R9L START ===")
pcall(function()
  local m = t(S.mmap(0, 0x1000000, 3, 0x0001, 5, 0))
  print(string.format("mmap(fd5,16MB)=0x%x", m))
  if not (m > 0x100000 and m < 0xFFFFFFFFFF) then return end

  local q0 = rq(m)
  local q3 = rq(m + 0x18)
  print(string.format("q0=0x%016x q3=0x%016x %s", q0, q3,
    (q0 == 0x80000000c0012800) and "<=DESC REAPPEARED!" or "zeros (descriptor gone)"))

  print("--- write persistence tests ---")
  local addrs = {0x3000, 0x1000, 0x2000, 0x4000}
  for _, off in ipairs(addrs) do
    pcall(function()
      local target = m + off
      local b0 = rq(target)
      mem.write_qword(target, 0xAAAAAAAAAAAAAAAA)
      local a1 = rq(target)
      mem.write_qword(target, 0x123456789ABCDEF0)
      local a2 = rq(target)
      print(string.format("  +0x%04x: before=0x%016x w1=0x%016x w2=0x%016x %s", off, b0, a1, a2,
        (a2 == 0x123456789ABCDEF0) and "PERSIST" or "refreshed"))
    end)
  end
end)
print("=== R9L DONE ===")
