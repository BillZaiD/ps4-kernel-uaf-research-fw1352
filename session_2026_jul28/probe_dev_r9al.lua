-- PS4 FW 13.52 - FINAL CAPTURE (r9al): region A head + 0xf140-0xf260
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
print("=== R9AL START ===")
pcall(function()
  local buf = mem.alloc(0x400)
  mem.write_buffer(buf, string.rep(string.char(0x00), 0x400), 0x400)
  mem.write_qword(buf, 0x2ec48000)
  mem.write_qword(buf + 8, 0x100000)
  local rarm = t(S.ioctl(5, 0x80108002, buf))
  local m = t(S.mmap(0x2ec48000, 0x100000, 3, 0x0001, 5, 0))
  print("arm=" .. rarm)
  print("-- region A 0x800-0x8d0 --")
  for off = 0x800, 0x8d0, 8 do
    print(string.format("%03x %016x", off, rq(m + off)))
  end
  print("-- region 0xf140-0xf260 --")
  for off = 0xf140, 0xf260, 8 do
    print(string.format("%05x %016x", off, rq(m + off)))
  end
end)
print("=== R9AL DONE ===")
