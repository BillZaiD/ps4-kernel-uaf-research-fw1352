print("=== PS4 FW 13.52 MINIMAL TEST ===")
print("If you see this, Lua execution works!")

-- Test 1: Basic globals
print("\n--- Globals ---")
print("memory: " .. type(memory))
print("native: " .. type(native))
print("syscall: " .. type(syscall))
print("lua: " .. type(lua))
print("kernel: " .. type(kernel))

-- Test 2: syscall.syscall_wrapper
print("\n--- Syscall Wrappers ---")
if syscall and syscall.syscall_wrapper then
  print("syscall.syscall_wrapper type: " .. type(syscall.syscall_wrapper))
  -- Test known wrappers
  local known = {[20]="getpid", [24]="getuid", [42]="pipe", [362]="kqueue"}
  for n, name in pairs(known) do
    local addr = syscall.syscall_wrapper[n]
    if addr then
      print(string.format("  sc[%d] (%s) = type=%s", n, name, type(addr)))
      if type(addr) == "table" and addr.h then
        print(string.format("    .h=%s .l=%s", tostring(addr.h), tostring(addr.l)))
      end
    else
      print(string.format("  sc[%d] (%s) = nil", n, name))
    end
  end
else
  print("syscall.syscall_wrapper NOT FOUND")
end

-- Test 3: native.fcall
print("\n--- Native fcall ---")
if native and native.fcall then
  print("native.fcall: " .. type(native.fcall))
else
  print("native.fcall NOT FOUND")
end

-- Test 4: memory operations
print("\n--- Memory ---")
local ptr = memory.alloc(64)
print(string.format("alloc(64) = 0x%x", ptr))
memory.write_byte(ptr, 0x41)
memory.write_byte(ptr+1, 0x42)
local b0 = memory.read_byte(ptr)
local b1 = memory.read_byte(ptr+1)
print(string.format("write/read byte: %d %d (expect 65 66)", b0, b1))

-- Test 5: Try getpid via raw syscall using native.fcall + wrapper
print("\n--- Syscall Test: getpid ---")
local getpid_addr = syscall.syscall_wrapper[20]
if getpid_addr and type(getpid_addr) == "table" then
  -- Convert uint64 to number
  local fn_addr = getpid_addr.h * 4294967296 + getpid_addr.l
  print(string.format("getpid fn_addr = 0x%x", fn_addr))
  local ok, ret = pcall(native.fcall, fn_addr, 0, 0, 0, 0, 0, 0)
  if ok then
    print(string.format("getpid() = %d", ret))
  else
    print("getpid CRASH: " .. tostring(ret))
  end
else
  print("getpid wrapper not found")
end

-- Test 6: Try getuid
print("\n--- Syscall Test: getuid ---")
local getuid_addr = syscall.syscall_wrapper[24]
if getuid_addr and type(getuid_addr) == "table" then
  local fn_addr = getuid_addr.h * 4294967296 + getuid_addr.l
  print(string.format("getuid fn_addr = 0x%x", fn_addr))
  local ok, ret = pcall(native.fcall, fn_addr, 0, 0, 0, 0, 0, 0)
  if ok then
    print(string.format("getuid() = %d", ret))
  else
    print("getuid CRASH: " .. tostring(ret))
  end
end

-- Test 7: try direct syscall via raw instruction (if wrapper available)
print("\n--- kqueue test ---")
local kqueue_addr = syscall.syscall_wrapper[362]
if kqueue_addr and type(kqueue_addr) == "table" then
  local fn_addr = kqueue_addr.h * 4294967296 + kqueue_addr.l
  print(string.format("kqueue fn_addr = 0x%x", fn_addr))
  local ok, ret = pcall(native.fcall, fn_addr, 0, 0, 0, 0, 0, 0)
  if ok then
    print(string.format("kqueue() = %d", ret))
    if ret >= 0 and ret < 1024 then
      -- close it
      local close_addr = syscall.syscall_wrapper[6]
      if close_addr and type(close_addr) == "table" then
        local ca = close_addr.h * 4294967296 + close_addr.l
        native.fcall(ca, ret, 0, 0, 0, 0, 0)
      end
    end
  else
    print("kqueue CRASH: " .. tostring(ret))
  end
end

-- Test 8: lua primitives
print("\n--- Lua Primitives ---")
if lua.addrof then
  local s = lua.create_str("test123")
  print("create_str: " .. type(s))
  if s then
    local addr = lua.addrof(s)
    print(string.format("addrof(str) = type=%s", type(addr)))
    if type(addr) == "table" then
      print(string.format("  .h=%s .l=%s", tostring(addr.h), tostring(addr.l)))
    end
  end
end

-- Test 9: Device open via raw syscall
print("\n--- Device Access ---")
local dev_tests = {"/dev/sbi", "/dev/srtc", "/dev/dce", "/dev/dipsw", "/dev/dmem0", "/dev/notification0"}
local open_addr = syscall.syscall_wrapper[5]
if open_addr and type(open_addr) == "table" then
  local open_fn = open_addr.h * 4294967296 + open_addr.l
  local close_addr = syscall.syscall_wrapper[6]
  local close_fn = nil
  if close_addr and type(close_addr) == "table" then
    close_fn = close_addr.h * 4294967296 + close_addr.l
  end
  for _, dp in ipairs(dev_tests) do
    local buf = memory.alloc(64)
    for i = 1, #dp do memory.write_byte(buf + i - 1, string.byte(dp, i)) end
    memory.write_byte(buf + #dp, 0)
    local ok, fd = pcall(native.fcall, open_fn, buf, 2, 0)
    if ok and type(fd) == "number" and fd >= 0 and fd < 1024 then
      print(string.format("  OPEN %s fd=%d", dp, fd))
      if close_fn then pcall(native.fcall, close_fn, fd, 0, 0, 0, 0, 0) end
    else
      print(string.format("  BLOCKED %s fd=%s", dp, tostring(fd)))
    end
  end
end

-- Test 10: fork test
print("\n--- Fork Test ---")
local fork_addr = syscall.syscall_wrapper[241]
if fork_addr and type(fork_addr) == "table" then
  local fn = fork_addr.h * 4294967296 + fork_addr.l
  print(string.format("fork fn_addr = 0x%x", fn))
  print("SKIP: fork may crash loader")
end

print("\n=== END OF TEST ===")
