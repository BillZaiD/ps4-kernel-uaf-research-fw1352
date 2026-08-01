-- PS4 FW 13.52 - REAL FD IDENTIFICATION + IOCTL SWEEP (r9e) — SAFE, ONE GAME-LIFE
-- r9d found real responding fds: 5,6,23,24,29,30 (ioctl 0x2000800b -> 0),
-- 14 (constant 0x8037F284). Identify them + find which ioctls return real data.

local mem = rawget(_G, "memory")
local S = rawget(_G, "syscall")

pcall(S.resolve, { open = 5, close = 6, ioctl = 54, fcntl = 92 })

local function t(v)
  if v == nil then return -1 end
  if type(v) == "number" then return v end
  if type(v) == "table" and v.h ~= nil then return v.h * 4294967296 + v.l end
  return tonumber(tostring(v)) or -1
end
local function rb(a) return t(mem.read_byte(a)) end
local function rd(a) return t(mem.read_dword(a)) end

print("=== R9E START ===")

local fds = {5, 6, 14, 23, 24, 29, 30}

-- identify fds via fcntl
print("--- fcntl identity ---")
for _, fd in ipairs(fds) do
  pcall(function()
    local getfl = t(S.fcntl(fd, 3, 0))
    local getfd = t(S.fcntl(fd, 1, 0))
    print(string.format("  FD=%d F_GETFL=0x%x F_GETFD=0x%x", fd, getfl, getfd))
  end)
end

-- broad sweep of real libkernel ioctls on responding fds
local reqs = {
  0x2000800b, 0x40048806, 0x40086418, 0x40026417, 0x40086489, 0x40046419,
  0x4008641a, 0x4008641b, 0x4008641c, 0xc0106601, 0x40084516, 0xc0044507,
  0xc0044508, 0xc0044511, 0xc0085306, 0xc008530d, 0xc0105301, 0x40105303,
  0xc008a502, 0x4004a501, 0xc010801a, 0x40047463, 0x40047477, 0xc0044507,
  0x40048806, 0x80108002, 0xc018800e, 0xc018800f, 0xc0208004, 0x802c7414,
  0x4004a501, 0xc01866ba, 0x801066b8, 0xc02066b9, 0x800466b6,
}

print("--- ioctl sweep (ret != -1 and ret != 0 with all-zero buf only shown for ret>0) ---")
for _, fd in ipairs(fds) do
  for _, req in ipairs(reqs) do
    pcall(function()
      local buf = mem.alloc(0x100)
      for i = 0, 0xff do mem.write_byte(buf+i, 0) end
      local r = t(S.ioctl(fd, req, buf))
      local nz = false
      for i = 0, 15 do if rb(buf+i) ~= 0 then nz = true break end end
      if r ~= -1 then
        local tag = "ALLZERO"
        if nz then tag = "DATA!" end
        local hx = ""
        for i = 0, 15 do hx = hx .. string.format("%02x ", rb(buf+i)) end
        print(string.format("  FD=%d ioctl(0x%08x)=%d [%s]", fd, req, r, tag))
        if nz then print("    " .. hx) end
      elseif nz then
        print(string.format("  FD=%d ioctl(0x%08x)=-1 BUT BUF MODIFIED", fd, req))
        local hx = ""
        for i = 0, 15 do hx = hx .. string.format("%02x ", rb(buf+i)) end
        print("    " .. hx)
      end
    end)
  end
end

print("=== R9E DONE ===")
