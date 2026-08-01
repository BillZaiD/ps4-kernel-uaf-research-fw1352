-- PS4 FW 13.52 - LIVE CONTENT CAPTURE (r9ac): double-scan same mapping, dump big runs
-- Detects whether window content changes (live ring buffer) and dumps it.

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

local function scan(m, lo, hi)
  local runs = {}
  local inrun, runstart
  for i = lo, hi do
    local v = rq(m + i * 8)
    if v ~= 0 then
      if not inrun then inrun = true runstart = i end
    elseif inrun then
      runs[#runs + 1] = { runstart * 8, (i - 1) * 8 }
      inrun = false
    end
  end
  if inrun then runs[#runs + 1] = { runstart * 8, hi * 8 } end
  return runs
end

print("=== R9AC START ===")
pcall(function()
  local buf = mem.alloc(0x200)
  mem.write_buffer(buf, string.rep(string.char(0x00), 0x200), 0x200)
  mem.write_qword(buf, 0x2ec48000)
  mem.write_qword(buf + 8, 0x100000)
  local rarm = t(S.ioctl(5, 0x80108002, buf))
  local m = t(S.mmap(0x2ec48000, 0x100000, 3, 0x0001, 5, 0))
  print(string.format("  re-arm=%d mmap=0x%x", rarm, m))

  local s1 = scan(m, 0, 0x1fff)
  local s2 = scan(m, 0, 0x1fff)
  local changed = 0
  local a1 = mem.alloc(0x2000 * 8)
  for i = 0, 0x1fff do mem.write_qword(a1 + i * 8, rq(m + i * 8)) end
  for i = 0, 0x1fff do
    if rq(m + i * 8) ~= rq(a1 + i * 8) then changed = changed + 1 end
  end

  print(string.format("  scan1 runs: %d, scan2 runs: %d, changed qwords between passes: %d", #s1, #s2, changed))
  print("  --- scan2 non-zero runs in first 64KB ---")
  for idx, r in ipairs(s2) do
    if idx > 30 then print(string.format("    ... %d more", #s2 - 30)) break end
    print(string.format("    run %2d: +0x%06x..+0x%06x (%d B)", idx, r[1], r[2], r[2] - r[1] + 8))
  end
end)
print("=== R9AC DONE ===")
