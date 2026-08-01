-- PS4 FW 13.52 - DMEM IN-STRUCT FIELD SWEEP (r9q) — ONE GAME-LIFE
-- ioctl 0x80108002 = IOC_IN, reads 264B struct from user buffer.
-- All-zeros -> ret 0. Determine which qwords the kernel validates (ret changes).
-- Use 0x200-byte buffer so a 264B read/write stays in-bounds.

local mem = rawget(_G, "memory")
local S = rawget(_G, "syscall")

pcall(S.resolve, { ioctl = 54 })

local function t(v)
  if v == nil then return -1 end
  if type(v) == "number" then return v end
  if type(v) == "table" and v.h ~= nil then return v.h * 4294967296 + v.l end
  return tonumber(tostring(v)) or -1
end

print("=== R9Q START ===")
pcall(function()
  local buf = mem.alloc(0x200)
  local req = 0x80108002

  local function tryq(off, val)
    mem.write_buffer(buf, string.rep(string.char(0x00), 0x200), 0x200)
    mem.write_qword(buf + off, val)
    local r = t(S.ioctl(5, req, buf))
    return r
  end

  print("--- single-qword tests on fd5 ---")
  local vals = {0x1000, 0x1000000, 0x2ec48000, 0xc0027600, 0x4141414141414141}
  for _, off in ipairs({0, 8, 16, 24, 32, 40, 48, 56, 64, 72}) do
    local res = {}
    for _, v in ipairs(vals) do
      table.insert(res, string.format("0x%x:%d", v, tryq(off, v)))
    end
    print(string.format("  qw%d: %s", off / 8, table.concat(res, " ")))
  end

  print("--- two-qword combinations (addr-ish at 0/8, size at 16/24) ---")
  local combos = {
    {0, 0x2ec48000, 16, 0x1000},
    {0, 0xc0027600, 16, 0x1000},
    {8, 0x2ec48000, 24, 0x1000},
    {16, 0x2ec48000, 24, 0x1000},
    {0, 0x2ec48000, 8, 0x1000},
  }
  for _, c in ipairs(combos) do
    mem.write_buffer(buf, string.rep(string.char(0x00), 0x200), 0x200)
    mem.write_qword(buf + c[1], c[2])
    mem.write_qword(buf + c[3], c[4])
    local r = t(S.ioctl(5, req, buf))
    print(string.format("  [%d]=0x%x [%d]=0x%x -> ret=0x%x", c[1] / 8, c[2], c[3] / 8, c[4], r))
  end
end)
print("=== R9Q DONE ===")
