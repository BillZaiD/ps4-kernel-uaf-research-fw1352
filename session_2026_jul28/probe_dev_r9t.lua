-- PS4 FW 13.52 - FRESH-BOOT DESCRIPTOR CAPTURE (r9t) — ONE GAME-LIFE, SAFE
-- Fresh mmap(fd5,16MB) right after boot = one-shot descriptor table + kernel dmap ptr.
-- No ioctls. Confirms kernel ptr / phys base on the new boot.

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

print("=== R9T START ===")
pcall(function()
  local m = t(S.mmap(0, 0x1000000, 3, 0x0001, 5, 0))
  print(string.format("mmap(fd5,16MB)=0x%x", m))
  if not (m > 0x100000 and m < 0xFFFFFFFFFF) then
    print("  mmap FAILED")
    return
  end
  local q0 = rq(m)
  local q3 = rq(m + 0x18)
  print(string.format("q0=0x%016x q3=0x%016x %s", q0, q3,
    (q0 == 0x80000000c0012800) and "<=DESCRIPTOR!" or "zeros (gone/not allocated)"))
  if q0 == 0x80000000c0012800 then
    local s = "  entries:"
    for off = 0x30, 0xb0, 0x10 do s = s .. string.format(" [0x%02x]=0x%016x", off, rq(m + off)) end
    print(s)
  end

  local target = m + 0x3000
  local before = rq(target)
  mem.write_qword(target, 0x1122334455660000)
  local after = rq(target)
  print(string.format("persist check +0x3000: before=0x%016x after=0x%016x %s",
    before, after, (math.floor(after / 0x10000) == 0x112233445566) and "PERSIST" or "no"))
end)
print("=== R9T DONE ===")
