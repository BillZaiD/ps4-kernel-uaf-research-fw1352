-- PS4 FW 13.52 - REAL DMEM FD + MMAP TEST (r9f) — CAREFUL, ONE GAME-LIFE
-- r9e crashed: broad IN/INOUT ioctl sweep on real device fds killed the game.
-- LESSON: only VOID(0x2xxxxxxx)/OUT(0x8xxxxxxx) ioctls are safe on unknown fds.
-- Plan:
--  1. read cached-fd globals from libkernel .data (libk+0x58038 etc.) to ID dmem fds
--  2. mmap(MAP_SHARED=0x0001) on fds {5,6,23,24,29,30} + identified ones, read 2 qwords
--  3. ONLY the known-safe VOID ioctl 0x2000800b for sanity

local mem = rawget(_G, "memory")
local S = rawget(_G, "syscall")
local nat = rawget(_G, "native")

pcall(S.resolve, { open = 5, close = 6, ioctl = 54, mmap = 477 })

local function t(v)
  if v == nil then return -1 end
  if type(v) == "number" then return v end
  if type(v) == "table" and v.h ~= nil then return v.h * 4294967296 + v.l end
  return tonumber(tostring(v)) or -1
end
local function rb(a) return t(mem.read_byte(a)) end
local function rd(a) return t(mem.read_dword(a)) end
local function rq(a) return t(mem.read_qword(a)) end

print("=== R9F START ===")

local f = S.open.fn_addr
local libk = t(f) - 0x2750
print(string.format("libk_base=0x%x", libk))

-- 1. cached fd globals (safe: readable .data)
print("--- cached fd globals ---")
pcall(function()
  for _, base in ipairs({0x58030, 0x5b570, 0x5b000, 0x5b800}) do
    local vals = {}
    for i = 0, 7 do vals[i+1] = string.format("0x%08x", rd(libk + base + i*4)) end
    print(string.format("  @0x%x: %s", libk + base, table.concat(vals, " ")))
  end
end)

-- 2. sanity: VOID ioctl on candidate fds
local cand = {5, 6, 23, 24, 29, 30}
print("--- sanity ioctl(0x2000800b) ---")
for _, fd in ipairs(cand) do
  pcall(function()
    local buf = mem.alloc(0x100)
    for i = 0, 0xff do mem.write_byte(buf+i, 0) end
    local r = t(S.ioctl(fd, 0x2000800b, buf))
    print(string.format("  FD=%d ioctl(0x2000800b)=%d", fd, r))
  end)
end

-- 3. mmap MAP_SHARED on candidates — the prize
print("--- mmap(fd, MAP_SHARED=0x1) ---")
for _, fd in ipairs(cand) do
  pcall(function()
    local m = t(S.mmap(0, 0x4000, 3, 0x0001, fd, 0))
    if m > 0x100000 and m < 0xFFFFFFFFFF then
      local q0 = rq(m)
      local q1 = rq(m + 0x1000)
      print(string.format("  FD=%d mmap=0x%x q0=0x%016x q1=0x%016x", fd, m, q0, q1))
    else
      print(string.format("  FD=%d mmap FAILED ret=0x%x", fd, m))
    end
  end)
end

print("=== R9F DONE ===")
