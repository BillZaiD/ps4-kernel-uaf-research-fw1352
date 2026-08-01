-- PS4 FW 13.52 - DMEM QUERY IOCTLS on INTERNAL fd (r9y) — SAFE, DIAGNOSTIC
-- Uses the PUBLIC psdevwiki dmem ioctl table:
--   0x80288012 = direct_memory_query   (IOC_IN, 40B: {offset, flags, start, end, size})
--   0xc0208004 = get_direct_memory_type (INOUT, 32B: {addr, type, start, end})
-- Q: is the region we can write (phys 0x2ec48000) the GAME's own dmem buffer
--    (interpretation A) or a kernel descriptor page (interpretation B)?

local mem = rawget(_G, "memory")
local S = rawget(_G, "syscall")

pcall(S.resolve, { ioctl = 54 })

local function t(v)
  if v == nil then return -1 end
  if type(v) == "number" then return v end
  if type(v) == "table" and v.h ~= nil then return v.h * 4294967296 + v.l end
  return tonumber(tostring(v)) or -1
end
local function rq(a) return t(mem.read_qword(a)) end

print("=== R9Y START ===")
pcall(function()
  local buf = mem.alloc(0x200)
  local function fill(qw0, qw1)
    mem.write_buffer(buf, string.rep(string.char(0x00), 0x200), 0x200)
    mem.write_qword(buf, qw0)
    mem.write_qword(buf + 8, qw1)
  end

  local function qry(label, offset, flags)
    fill(offset, flags)
    local r = t(S.ioctl(5, 0x80288012, buf))
    print(string.format("  QUERY offset=0x%x flags=%d ioctl=%d -> start=0x%016x end=0x%016x size=0x%016x",
      offset, flags, r, rq(buf + 16), rq(buf + 24), rq(buf + 32)))
  end

  print("--- direct_memory_query (0x80288012) on fd5 ---")
  qry("offset=0", 0, 0)
  qry("offset=0", 0, 1)
  qry("offset=dmem", 0x2ec48000, 1)
  qry("offset=1GB", 0x40000000, 1)

  print("--- get_direct_memory_type (0xc0208004) on fd5 ---")
  fill(0x2ec48000, 0)
  local r = t(S.ioctl(5, 0xc0208004, buf))
  print(string.format("  TYPE addr=0x2ec48000 ioctl=%d type=0x%x start=0x%016x end=0x%016x",
    r, rq(buf + 8), rq(buf + 16), rq(buf + 24)))
end)
print("=== R9Y DONE ===")
