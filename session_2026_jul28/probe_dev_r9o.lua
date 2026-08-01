-- PS4 FW 13.52 - FIND LEAK-FD + FULL OUT-IOCTL DUMP (r9o) — ONE GAME-LIFE
-- Scan fds 0..40 for the fd where ioctl(fd,0x4010a802,buf) returns 0 (the leak fn's cached fd).
-- Re-test OUT ioctls with 0xAA prefill, dump full 4 qwords.

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

print("=== R9O START ===")
pcall(function()
  local buf = mem.alloc(0x40)

  print("--- fd scan for ioctl 0x4010a802 success ---")
  local found = {}
  for fd = 0, 40 do
    pcall(function()
      mem.write_qword(buf, 0x12345678)
      mem.write_qword(buf + 8, 0)
      local r = t(S.ioctl(fd, 0x4010a802, buf))
      if r == 0 then
        table.insert(found, fd)
        print(string.format("  fd=%d ret=0x0 out0=0x%016x out1=0x%016x <=SUCCESS",
          fd, rq(buf), rq(buf + 8)))
      end
    end)
  end
  if #found == 0 then print("  no fd returned 0") end

  print("--- OUT ioctls, 0xAA prefill, full 32B dump ---")
  for _, fd in ipairs({5, 6}) do
    for _, req in ipairs({0x80108002, 0x80108015, 0x80108017}) do
      pcall(function()
        mem.write_buffer(buf, string.rep(string.char(0xAA), 0x40), 0x40)
        local r = t(S.ioctl(fd, req, buf))
        local s = string.format("fd=%d req=0x%08x ret=0x%x:", fd, req, r)
        for i = 0, 3 do s = s .. string.format(" 0x%016x", rq(buf + i * 8)) end
        print(s)
      end)
    end
  end
end)
print("=== R9O DONE ===")
