-- PS4 FW 13.52 - DMEM0 ESCALATION: mmap offsets + descriptor read (r9i) — ONE GAME-LIFE
-- r9h: fd5 mapping = real DMA descriptor table + kernel dmap ptr + WRITABLE.
-- Now: (A) re-dump descriptor area, (B) mmap with DIFFERENT OFFSETS to test
-- if offset controls which physical region is mapped, (C) tiny VOID/OUT ioctl set.

local mem = rawget(_G, "memory")
local S = rawget(_G, "syscall")

pcall(S.resolve, { mmap = 477, ioctl = 54 })

local function t(v)
  if v == nil then return -1 end
  if type(v) == "number" then return v end
  if type(v) == "table" and v.h ~= nil then return v.h * 4294967296 + v.l end
  return tonumber(tostring(v)) or -1
end
local function rq(a) return t(mem.read_qword(a)) end
local function rd(a) return t(mem.read_dword(a)) end

print("=== R9I START ===")
pcall(function()
  local m = t(S.mmap(0, 0x1000000, 3, 0x0001, 5, 0))
  print(string.format("mmap(fd5,16MB,off=0)=0x%x", m))
  if not (m > 0x100000 and m < 0xFFFFFFFFFF) then return end

  print("--- descriptor area 0x10-0xb8 ---")
  for i = 2, 23 do
    print(string.format("  +0x%04x: 0x%016x", i*8, rq(m + i*8)))
  end

  print("--- mmap offset=0x1000000 (16MB in) ---")
  pcall(function()
    local m2 = t(S.mmap(0, 0x1000000, 3, 0x0001, 5, 0x1000000))
    print(string.format("  mmap(off=0x1000000)=0x%x q0=0x%016x q1=0x%016x",
      m2, rq(m2), rq(m2+8)))
  end)

  print("--- mmap offset=0x40000000 (1GB in) ---")
  pcall(function()
    local m3 = t(S.mmap(0, 0x1000000, 3, 0x0001, 5, 0x40000000))
    print(string.format("  mmap(off=0x40000000)=0x%x q0=0x%016x", m3, rq(m3)))
  end)

  print("--- VOID/OUT ioctls on fd5 ---")
  local reqs = {0x2000800b, 0x80108002, 0x80108015, 0x80108017}
  for _, req in ipairs(reqs) do
    pcall(function()
      local buf = mem.alloc(0x100)
      for i = 0, 0xff do mem.write_byte(buf+i, 0) end
      local r = t(S.ioctl(5, req, buf))
      local hx = ""
      for i = 0, 7 do hx = hx .. string.format("%02x", t(mem.read_byte(buf+i))) end
      print(string.format("  ioctl(fd5,0x%08x)=%d buf0-7=%s", req, r, hx))
    end)
  end
end)
print("=== R9I DONE ===")
