-- PS4 FW 13.52 - DMEM0 MAPPING SCAN (r9g) — THE PRIZE PUSH, ONE GAME-LIFE
-- r9f: fd=5 = real /dev/dmem0; mmap(fd5, MAP_SHARED) SUCCEEDED.
-- Now: scan mapped content, try larger mapping, test write/readback.

local mem = rawget(_G, "memory")
local S = rawget(_G, "syscall")

pcall(S.resolve, { open = 5, close = 6, mmap = 477 })

local function t(v)
  if v == nil then return -1 end
  if type(v) == "number" then return v end
  if type(v) == "table" and v.h ~= nil then return v.h * 4294967296 + v.l end
  return tonumber(tostring(v)) or -1
end
local function rb(a) return t(mem.read_byte(a)) end
local function rq(a) return t(mem.read_qword(a)) end

print("=== R9G START ===")

print("[G1] scan mapped 0x4000 for non-zero")
pcall(function()
  local m = t(S.mmap(0, 0x4000, 3, 0x0001, 5, 0))
  print(string.format("  mmap(fd5)=0x%x", m))
  if not (m > 0x100000 and m < 0xFFFFFFFFFF) then return end
  local nz = 0
  local first = -1
  for i = 0, 0x3fff, 8 do
    local q = rq(m + i)
    if q ~= 0 then
      if nz < 12 then print(string.format("    +0x%04x: 0x%016x", i, q)) end
      nz = nz + 1
      if first < 0 then first = i end
    end
  end
  print(string.format("  nonzero qwords: %d (first @+0x%04x)", nz, first))
end)

print("[G2] larger mmap 16MB + sparse scan")
pcall(function()
  local m = t(S.mmap(0, 0x1000000, 3, 0x0001, 5, 0))
  print(string.format("  mmap(fd5,16MB)=0x%x", m))
  if not (m > 0x100000 and m < 0xFFFFFFFFFF) then return end
  local nz = 0
  for i = 0, 0xfffffff, 0x1000 do
    local q = rq(m + i)
    if q ~= 0 then
      if nz < 12 then print(string.format("    +0x%08x: 0x%016x", i, q)) end
      nz = nz + 1
    end
  end
  print(string.format("  nonzero at 0x1000-steps: %d", nz))
end)

print("[G3] write/readback on mapped region")
pcall(function()
  local m = t(S.mmap(0, 0x4000, 3, 0x0001, 5, 0))
  if not (m > 0x100000 and m < 0xFFFFFFFFFF) then return end
  local target = m + 0x100
  mem.write_qword(target, 0x1352135213521352)
  local back = rq(target)
  print(string.format("  wrote 0x1352135213521352 @0x%x read back 0x%016x %s", target, back,
    (back == 0x1352135213521352) and "MATCH (RW!)" or "MISMATCH"))
end)

print("=== R9G DONE ===")
