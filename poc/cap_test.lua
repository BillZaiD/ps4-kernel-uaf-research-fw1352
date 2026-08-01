-- Test file I/O + socket + execute capabilities
print("=== Capability Test ===\n")

-- Test io
print("--- io Test ---")
local ok1, f = pcall(io.open, "/savedata0/test_write.txt", "w")
if ok1 and f then
  f:write("hello from fuzzer")
  f:close()
  print("  io.open WRITE: WORKS")
  
  local ok2, f2 = pcall(io.open, "/savedata0/test_write.txt", "r")
  if ok2 and f2 then
    local content = f2:read("*a")
    f2:close()
    print("  io.open READ: " .. content)
    -- Clean up
    os.remove("/savedata0/test_write.txt")
  end
else
  local err = tostring(f)
  print("  io.open WRITE: FAILED - " .. err)
end

-- Test os.execute
print("\n--- os.execute Test ---")
local ok3, r3 = pcall(os.execute, "echo test")
if ok3 then
  print("  os.execute: WORKS (exit=" .. tostring(r3) .. ")")
else
  print("  os.execute: FAILED - " .. tostring(r3))
end

-- Test io.popen
print("\n--- io.popen Test ---")
local ok4, p = pcall(io.popen, "echo popen_test")
if ok4 and p then
  local result = p:read("*a")
  p:close()
  print("  io.popen: " .. (result or "nil"))
else
  print("  io.popen: FAILED - " .. tostring(p))
end

-- Test socket syscall
print("\n--- Socket Syscall Test ---")
local wt = syscall.syscall_wrapper
local ok5, sockfd = pcall(native.fcall, wt[97], 2, 1, 0)  -- AF_INET(2), SOCK_STREAM(1), 0
if ok5 then
  if type(sockfd) == "table" then
    print(string.format("  SC97 (socket): h=0x%x l=0x%x", sockfd.h or 0, sockfd.l or 0))
  else
    print("  SC97 (socket): " .. tostring(sockfd))
  end
else
  print("  SC97 (socket): FAILED - " .. tostring(sockfd))
end

-- Test if we can bind a port
print("\n--- bind test ---")
-- First get a socket
local ok6, fd = pcall(native.fcall, wt[97], 2, 1, 0)
if ok6 and type(fd) == "table" and fd.h == 0 and fd.l > 0 then
  local sd = fd.l
  print(string.format("  Got socket fd=%d", sd))
  
  -- Try bind to port 8888
  local sockaddr = memory.alloc(16)
  -- AF_INET(2) at byte 0, port at byte 2, IP at byte 4
  -- Port 8888 = 0x22b8 → bytes: b8 22 (network byte order)
  memory.write_byte(sockaddr, 2)     -- AF_INET low
  memory.write_byte(sockaddr+1, 0)   -- AF_INET high
  memory.write_byte(sockaddr+2, 0xb8)  -- port 8888 hi
  memory.write_byte(sockaddr+3, 0x22)  -- port 8888 lo
  -- IP 127.0.0.1
  memory.write_byte(sockaddr+4, 127)
  memory.write_byte(sockaddr+5, 0)
  memory.write_byte(sockaddr+6, 0)
  memory.write_byte(sockaddr+7, 1)
  -- rest zeros
  
  local ok7, bind_r = pcall(native.fcall, wt[99], sd, sockaddr, 16)
  if ok7 and type(bind_r) == "table" then
    print(string.format("  SC99 (bind): h=0x%x l=0x%x", bind_r.h or 0, bind_r.l or 0))
    if bind_r.l == 0 then
      print("  BIND SUCCESS! Port 8888 is open!")
    end
  end
  
  -- Try listen
  local ok8, listen_r = pcall(native.fcall, wt[100], sd, 5)
  if ok8 and type(listen_r) == "table" then
    print(string.format("  SC100 (listen): h=0x%x l=0x%x", listen_r.h or 0, listen_r.l or 0))
  end
  
else
  print("  Socket creation failed")
end

print("\nDone.")
