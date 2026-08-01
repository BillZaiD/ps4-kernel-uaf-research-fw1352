-- PS4 FW 13.52 - REAL FD HUNT (r9d) — SAFE, ONE GAME-LIFE
-- Key insight (r9c): internal libkernel open gives REAL device fds
-- (dipsw ioctl worked, dmem0 reached driver 0x80020001) while game S.open fd=22
-- gives -1 on all ioctls. Hypothesis: cached internal fds are usable.
-- Plan: call dmem init (caches /dev/dmem0/1/2 fds), then scan ALL fds 0..48
-- with the key ioctls; any non-(-1) response = real device fd found.

local mem = rawget(_G, "memory")
local S = rawget(_G, "syscall")
local nat = rawget(_G, "native")

pcall(S.resolve, { open = 5, close = 6, ioctl = 54, getpid = 20 })

local function t(v)
  if v == nil then return -1 end
  if type(v) == "number" then return v end
  if type(v) == "table" and v.h ~= nil then return v.h * 4294967296 + v.l end
  return tonumber(tostring(v)) or -1
end
local function rb(a) return t(mem.read_byte(a)) end

print("=== R9D START ===")

local f = S.open.fn_addr
local libk = t(f) - 0x2750
print(string.format("libk_base=0x%x", libk))

-- ensure dmem fds are cached
pcall(function()
  local ok, ret = pcall(nat.fcall, libk + 0x16ff0, 0, 0, 0, 0, 0, 0)
  print(string.format("dmem init ret=%s", tostring(ret)))
end)

local function dump(buf, n)
  local hx = ""
  for i = 0, n-1 do hx = hx .. string.format("%02x ", rb(buf+i)) end
  return hx
end

-- request codes to probe on each fd
local reqs = {0x2000800b, 0x40048806, 0x40086418, 0x40026417, 0xc0106601}
local reqname = {[0x2000800b]="dmem0_info", [0x40048806]="dipsw", [0x40086418]="dmem864", [0x40026417]="dmem264", [0xc0106601]="dce_ver"}

print("--- fd scan (ioctl ret != -1) ---")
for fd = 0, 48 do
  for _, req in ipairs(reqs) do
    pcall(function()
      local buf = mem.alloc(0x100)
      for i = 0, 0xff do mem.write_byte(buf+i, 0) end
      local r = t(S.ioctl(fd, req, buf))
      if r ~= -1 then
        print(string.format("  FD=%d ioctl(%s)=%d", fd, reqname[req] or string.format("0x%08x", req), r))
        print("    " .. dump(buf, 32))
      end
    end)
  end
end

print("=== R9D DONE ===")
