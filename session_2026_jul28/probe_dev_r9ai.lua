-- PS4 FW 13.52 - STRUCTURED DECODE (r9ai): GPU VM table + region A records
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
local function d32(a) local v = t(mem.read_qword(a)) % 4294967296 return v end

print("=== R9AI START ===")
pcall(function()
  local buf = mem.alloc(0x200)
  mem.write_buffer(buf, string.rep(string.char(0x00), 0x200), 0x200)
  mem.write_qword(buf, 0x2ec48000)
  mem.write_qword(buf + 8, 0x100000)
  local rarm = t(S.ioctl(5, 0x80108002, buf))
  local m = t(S.mmap(0x2ec48000, 0x100000, 3, 0x0001, 5, 0))
  print("arm=" .. rarm)

  print("-- GPU VM/desc table @0x2a0-0x3e8 (qwords) --")
  for off = 0x2a0, 0x3e8, 8 do
    print(string.format("%03x: %016x", off, rq(m + off)))
  end

  print("-- region A records @0x800-0xbc0 (20B rec: d0 d1 d2 d3 d4) --")
  for off = 0x800, 0xbc0, 20 do
    local d0 = d32(m + off)
    local d1 = d32(m + off + 4)
    local d2 = d32(m + off + 8)
    local d3 = d32(m + off + 12)
    local d4 = d32(m + off + 16)
    print(string.format("%03x: %08x %08x %08x %08x %08x", off, d0, d1, d2, d3, d4))
  end
end)
print("=== R9AI DONE ===")
