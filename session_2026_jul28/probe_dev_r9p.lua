-- PS4 FW 13.52 - DMEM FD7 ioctl 0x4010a802 input sweep (r9p) — ONE GAME-LIFE
-- fd=7 is the leak-fn fd (ioctl 0x4010a802 returns 0). Sweep input qwords to trigger output.

local mem = rawget(_G, "memory")
local S = rawget(_G, "syscall")

pcall(S.resolve, { ioctl = 54 })

local function t(v)
  if v == nil then return -1 end
  if type(v) == "number" then return v end
  if type(v) == "table" and v.h ~= nil then return v.h * 4294967296 + v.l end
  return tonumber(tostring(v)) or -1
end
local function rq(a) return t(mem.read_qword(a)) end

print("=== R9P START ===")
pcall(function()
  local buf = mem.alloc(0x40)

  print("--- fd7 0x4010a802 qword0 sweep (qword1=0) ---")
  local inputs0 = {0, 1, 2, 3, 4, 8, 0x10, 0x20, 0x100, 0x1000, 0x10000, 0x1000000}
  for _, iv in ipairs(inputs0) do
    pcall(function()
      mem.write_qword(buf, iv)
      mem.write_qword(buf + 8, 0)
      local r = t(S.ioctl(7, 0x4010a802, buf))
      local o0, o1 = rq(buf), rq(buf + 8)
      if o0 ~= 0 or o1 ~= 0 then
        print(string.format("  in0=0x%08x ret=0x%x out0=0x%016x out1=0x%016x <=DATA", iv, r, o0, o1))
      end
    end)
  end

  print("--- fd7 0x4010a802 qword1 sweep (qword0=0) ---")
  local inputs1 = {1, 2, 3, 0x10, 0x1000, 0x100000}
  for _, iv in ipairs(inputs1) do
    pcall(function()
      mem.write_qword(buf, 0)
      mem.write_qword(buf + 8, iv)
      local r = t(S.ioctl(7, 0x4010a802, buf))
      local o0, o1 = rq(buf), rq(buf + 8)
      if o0 ~= 0 or o1 ~= 0 then
        print(string.format("  in1=0x%08x ret=0x%x out0=0x%016x out1=0x%016x <=DATA", iv, r, o0, o1))
      end
    end)
  end

  print("--- fd7 0x4010a802 paired qwords ---")
  local pairs = {{0x1000000, 0x1000000}, {0x12345678, 0x87654321}, {0x80000000, 0x1}, {0xFFFFFFFF, 0xFFFFFFFF}}
  for _, pr in ipairs(pairs) do
    pcall(function()
      mem.write_qword(buf, pr[1])
      mem.write_qword(buf + 8, pr[2])
      local r = t(S.ioctl(7, 0x4010a802, buf))
      local o0, o1 = rq(buf), rq(buf + 8)
      print(string.format("  in=(0x%08x,0x%08x) ret=0x%x out0=0x%016x out1=0x%016x",
        pr[1], pr[2], r, o0, o1))
    end)
  end

  print("--- fd5 OUT ioctls with 0x00 prefill ---")
  for _, req in ipairs({0x80108002, 0x80108015, 0x80108017}) do
    pcall(function()
      mem.write_buffer(buf, string.rep(string.char(0x00), 0x40), 0x40)
      local r = t(S.ioctl(5, req, buf))
      local s = string.format("fd5 req=0x%08x ret=0x%x:", req, r)
      for i = 0, 3 do s = s .. string.format(" 0x%016x", rq(buf + i * 8)) end
      print(s)
    end)
  end
end)
print("=== R9P DONE ===")
