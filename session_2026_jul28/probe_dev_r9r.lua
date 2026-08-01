-- PS4 FW 13.52 - DMEM IN-STRUCT FIELD RULE + MAPPING EXPERIMENT (r9r) — ONE GAME-LIFE
-- Nail the qw0/qw1 validation rule (addr? size? alignment?), then try setting the
-- mapping base to kernel-dmap phys (0x2ec48000) and re-map.

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

print("=== R9R START ===")
pcall(function()
  local buf = mem.alloc(0x200)
  local req = 0x80108002

  local function tryq(val)
    mem.write_buffer(buf, string.rep(string.char(0x00), 0x200), 0x200)
    mem.write_qword(buf, val)
    return t(S.ioctl(5, req, buf))
  end

  print("--- boundary sweep (qw0) ---")
  local bounds = {0xFFFFF, 0x100000, 0x100001, 0x1FFFFF, 0x3FFFFFFF,
                 0x40000000, 0x7FFFFFFF, 0x80000000, 0xBFFFFFFF,
                 0x10000000, 0xFFFFFFFF, 0x100000000, 0x2ec48000}
  for _, v in ipairs(bounds) do
    print(string.format("  qw0=0x%08x -> ret=0x%x", v, tryq(v)))
  end

  print("--- mapping experiment: set base=0x2ec48000 then remap ---")
  mem.write_buffer(buf, string.rep(string.char(0x00), 0x200), 0x200)
  mem.write_qword(buf, 0x2ec48000)
  mem.write_qword(buf + 8, 0x100000)
  local r = t(S.ioctl(5, req, buf))
  print(string.format("  ioctl set(base=0x2ec48000,size=0x100000) ret=0x%x", r))

  local m = t(S.mmap(0, 0x100000, 3, 0x0001, 5, 0))
  print(string.format("  remap=0x%x", m))
  if m > 0x100000 and m < 0xFFFFFFFFFF then
    local s = "  content:"
    for i = 0, 7 do s = s .. string.format(" 0x%016x", rq(m + i * 8)) end
    print(s)
  end
end)
print("=== R9R DONE ===")
