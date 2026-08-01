------------------------------------------------------------
PS4 FW 13.52 - DEVICE ENUMERATOR & IOCTL FUZZER
Tests all 17+ device nodes with multiple ioctl patterns

Strategy:
  1. Try to open each device
  2. For each open device, test multiple ioctl codes
  3. Check for kernel pointer leaks in returned data
  4. Check for buffer modifications (info leaks)
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
-- DEVICE LIST
------------------------------------------------------------
local devices = {
  "/dev/sbi",
  "/dev/dce",
  "/dev/dmem0", "/dev/dmem1", "/dev/dmem2",
  "/dev/dipsw",
  "/dev/gbase",
  "/dev/sflash0",
  "/dev/srtc",
  "/dev/console",
  "/dev/notification0", "/dev/notification1",
  "/dev/icc0", "/dev/icc1", "/dev/icc2", "/dev/icc3",
  "/dev/evlg0",
  "/dev/sdk_eventlog",
  "/dev/gpu0", "/dev/gpu1", "/dev/gpu2",
  "/dev/aci0", "/dev/acp0",
  "/dev/dfb0",
  "/dev/hmd0", "/dev/hmd1",
  "/dev/neuron0",
  "/dev/rng0",
  "/dev/tee0",
  "/dev/uarta0", "/dev/uartb0",
  "/dev/wlan0",
  "/dev/bt0",
  "/dev/nfc0",
  "/dev/usb0", "/dev/usb1",
  "/dev/vdec0", "/dev/venc0",
  "/dev/aenc0", "/dev/dec0",
  "/dev/mux0",
  "/dev/camera0", "/dev/camera1",
  "/dev/sensor0",
  "/dev/microphone0",
  "/dev/spk0",
  "/dev/vsh0",
}

------------------------------------------------------------
-- IOCTL CODES TO TEST
------------------------------------------------------------
local ioctl_codes = {
  -- From libkernel analysis
  0xc008a801, 0xc010a801, 0xc020a801,
  0xc008a802, 0xc010a802, 0xc020a802,
  0x8008a801, 0x8010a801, 0x8020a801,
  0x4008a801, 0x4010a801, 0x4020a801,

  -- /dev/srtc patterns
  0x40105303, 0x80105303, 0xc0105303,

  -- GPU/Graphics
  0xc0408001, 0xc0408002, 0xc0408003,
  0xc0108004, 0xc0108005, 0xc0108006,

  -- Sound
  0xc0105301, 0xc0105302, 0xc0105304,

  -- Camera/Sensors
  0xc0109901, 0xc0109902, 0xc0109903,

  -- Touch/Input
  0xc0107401, 0xc0107402, 0xc0107403,

  -- NFC/Security
  0xc0109201, 0xc0109202, 0xc0109203,

  -- Network
  0xc0104501, 0xc0104502, 0xc0104503,

  -- Filesystem
  0xc0106601, 0xc0106602, 0xc0106603,

  -- Memory management
  0xc0188008, 0xc0288012, 0xc0408013,
}

------------------------------------------------------------
-- MAIN
------------------------------------------------------------
print("============================================")
print("PS4 FW 13.52 - DEVICE IOCTL FUZZER")
print("============================================")

local open_devices = {}
local kernel_leaks = {}
local buffer_mods = {}

-- Phase 1: Open all devices
print("\n=== PHASE 1: Device Enumeration ===")
for _, dev_path in ipairs(devices) do
  local path_buf = memory.alloc(64)
  for i = 1, #dev_path do
    memory.write_byte(path_buf + i - 1, string.byte(dev_path, i))
  end
  memory.write_byte(path_buf + #dev_path, 0)

  local fd = s(5, path_buf, 0, 0)
  if fd >= 0 and fd < 1024 then
    table.insert(open_devices, {path=dev_path, fd=fd})
    print(string.format("  OPEN: %s (fd=%d)", dev_path, fd))
  else
    print(string.format("  BLOCKED: %s", dev_path))
  end
end

print(string.format("\n  Opened %d/%d devices", #open_devices, #devices))

-- Phase 2: Fuzz each device
print("\n=== PHASE 2: IOCTL Fuzzing ===")
for _, dev in ipairs(open_devices) do
  print(string.format("\n  --- %s (fd=%d) ---", dev.path, dev.fd))

  for _, req in ipairs(ioctl_codes) do
    local buf = memory.alloc(64)
    for i = 0, 63 do memory.write_byte(buf + i, 0) end

    -- Fill with marker
    for i = 0, 15 do
      memory.write_byte(buf + i, 0x41 + (i % 26))
    end

    local r = s(54, dev.fd, req, buf)
    if r == 0 then
      -- Check for kernel pointers
      local has_kptr = false
      for i = 0, 7 do
        local val = read_qw(buf + i * 8)
        if val >= 0xFFFFFFFF80000000 and val <= 0xFFFFFFFFFFFFFFFF then
          table.insert(kernel_leaks, {dev=dev.path, req=req, offset=i*8, value=val})
          has_kptr = true
        end
      end

      -- Check for buffer modification
      local modified = false
      for i = 0, 15 do
        local expected = 0x41 + (i % 26)
        if memory.read_byte(buf + i) ~= expected then
          modified = true
          break
        end
      end

      if has_kptr then
        print(string.format("    *** KERNEL PTR: ioctl(0x%x) in %s ***", req, dev.path))
      elseif modified then
        table.insert(buffer_mods, {dev=dev.path, req=req})
        print(string.format("    MODIFIED: ioctl(0x%x)", req))
      end
    end
  end
end

-- Summary
print("\n============================================")
print("RESULTS")
print("============================================")

if #kernel_leaks > 0 then
  print(string.format("\n*** KERNEL POINTER LEAKS: %d ***", #kernel_leaks))
  for _, leak in ipairs(kernel_leaks) do
    print(string.format("  %s ioctl(0x%x) offset %d = 0x%x",
      leak.dev, leak.req, leak.offset, leak.value))
  end
else
  print("\nNo kernel pointer leaks found")
end

if #buffer_mods > 0 then
  print(string.format("\n*** BUFFER MODIFICATIONS: %d ***", #buffer_mods))
  for _, mod in ipairs(buffer_mods) do
    print(string.format("  %s ioctl(0x%x)", mod.dev, mod.req))
  end
else
  print("\nNo buffer modifications detected")
end

-- Cleanup
for _, dev in ipairs(open_devices) do
  s(6, dev.fd)
end

print("\n============================================")
print("Send results to Termux for analysis")
print("============================================")
