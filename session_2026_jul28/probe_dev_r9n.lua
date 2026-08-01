-- PS4 FW 13.52 - DMEM IOCTL INOUT SWEEP on real fds (r9n) — ONE GAME-LIFE
-- ioctl 0x4010a802 = INOUT 16B (used by libkernel leak fn). Control input, read output.
-- Plus OUT ioctls 0x80108002/0x80108015/0x80108017 with prefilled buffers.

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

print("=== R9N START ===")
pcall(function()
  local buf = mem.alloc(0x40)
  mem.write_buffer(buf, string.rep(string.char(0x41), 0x40), 0x40)

  local inputs = {0, 1, 2, 3, 0x10, 0x100, 0x1000000, 0xFFFFFFFF, 0x8002000b, 0x2000800b}
  for _, fd in ipairs({5, 6}) do
    for _, iv in ipairs(inputs) do
      pcall(function()
        mem.write_qword(buf, iv)
        mem.write_qword(buf + 8, 0)
        local r = t(S.ioctl(fd, 0x4010a802, buf))
        local o0 = rq(buf)
        local o1 = rq(buf + 8)
        print(string.format("fd=%d in=0x%08x ret=0x%x out0=0x%016x out1=0x%016x%s",
          fd, iv, r, o0, o1,
          (o0 ~= 0 or o1 ~= 0) and " <=LEAK?" or ""))
      end)
    end
  end

  print("--- OUT ioctls ---")
  for _, fd in ipairs({5, 6}) do
    for _, req in ipairs({0x80108002, 0x80108015, 0x80108017}) do
      pcall(function()
        mem.write_buffer(buf, string.rep(string.char(0xCC), 0x40), 0x40)
        local r = t(S.ioctl(fd, req, buf))
        local o0 = rq(buf)
        local o1 = rq(buf + 8)
        print(string.format("fd=%d req=0x%08x ret=0x%x out0=0x%016x out1=0x%016x%s",
          fd, req, r, o0, o1,
          (o0 ~= 0xCCCCCCCCCCCCCCCC) and " <=WRITTEN!" or ""))
      end)
    end
  end
end)
print("=== R9N DONE ===")
