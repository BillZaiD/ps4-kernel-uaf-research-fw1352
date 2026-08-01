-- Fix sockaddr_in and test bind properly
print("=== Socket Bind Test (Fixed) ===\n")

local wt = syscall.syscall_wrapper

-- Create socket
local ok1, s = pcall(native.fcall, wt[97], 2, 1, 0)
if not ok1 or type(s) ~= "table" then
  print("Socket creation failed")
  return
end
local fd = s.l
print(string.format("Socket fd: %d", fd))

-- Build sockaddr_in manually (16 bytes)
-- struct sockaddr_in { u_char sin_len; u_char sin_family; u_short sin_port; struct in_addr sin_addr; char sin_zero[8]; }
local sa = memory.alloc(16)
memory.write_byte(sa, 16)        -- sin_len = sizeof(sockaddr_in)
memory.write_byte(sa+1, 2)       -- sin_family = AF_INET
-- sin_port = 8888 = 0x22B8, network byte order = 0xB822
memory.write_byte(sa+2, 0xB8)
memory.write_byte(sa+3, 0x22)
-- sin_addr = 127.0.0.1 = 0x0100007F (network byte order)
memory.write_byte(sa+4, 127)
memory.write_byte(sa+5, 0)
memory.write_byte(sa+6, 0)
memory.write_byte(sa+7, 1)
-- sin_zero = zeros (already zero from alloc)

-- Debug: read back sockaddr
print("sockaddr bytes:")
for i = 0, 15 do
  local b = memory.read_byte(sa + i)
  local v = 0
  if type(b) == "table" then v = b.l or 0 else v = b or 0 end
  if v ~= 0 then
    print(string.format("  [%d] = 0x%02x (%d)", i, v, v))
  end
end

-- Try bind with correct structure
print("\nBinding to 127.0.0.1:8888 ...")
local ok2, br = pcall(native.fcall, wt[99], fd, sa, 16)
local bh, bl = 0, 0
if ok2 and type(br) == "table" then
  bh, bl = br.h or 0, br.l or 0
  print(string.format("bind: h=0x%x l=0x%x", bh, bl))
elseif ok2 then
  print("bind: " .. tostring(br))
else
  print("bind FAILED: " .. tostring(br))
end

if bl == 0 then
  print("*** BIND SUCCESS! Port 8888 is listening! ***")
  
  -- Try listen
  local ok3, lr = pcall(native.fcall, wt[100], fd, 5)
  if ok3 then
    print("listen: OK")
    
    -- Try accept (non-blocking)
    print("Trying accept...")
    local ok4, ar = pcall(native.fcall, wt[101], fd, 0, 0, 0)
    if ok4 and type(ar) == "table" then
      print(string.format("accept: h=0x%x l=0x%x", ar.h or 0, ar.l or 0))
    end
  end
else
  print("Bind failed. Trying alternative port/service...")
  
  -- Try different ports
  for _, port in ipairs({8080, 8000, 9999, 31337, 1337, 80, 443}) do
    local p_hi = math.floor(port / 256)
    local p_lo = port % 256
    -- network byte order: hi then lo
    memory.write_byte(sa+2, p_lo)
    memory.write_byte(sa+3, p_hi)
    
    local ok, r = pcall(native.fcall, wt[99], fd, sa, 16)
    if ok and type(r) == "table" and r.l == 0 then
      print(string.format("Port %d: BIND SUCCESS!", port))
      break
    elseif ok and type(r) == "table" then
      print(string.format("Port %d: %s", port, r.l == 0xFFFFFFFF and "denied" or "0x" .. string.format("%x", r.l)))
    end
  end
  
  -- Try to check socket options
  print("\nTrying SO_REUSEADDR...")
  local one = memory.alloc(4)
  memory.write_byte(one, 1) -- setsockopt value = 1
  local ok_so, so_r = pcall(native.fcall, wt[105], fd, 1, 2, one, 4)  -- SOL_SOCKET=1, SO_REUSEADDR=2
  if ok_so and type(so_r) == "table" then
    print(string.format("setsockopt: h=0x%x l=0x%x", so_r.h or 0, so_r.l or 0))
  end
  
  -- Retry bind with reuseaddr
  local ok_rb, rb_r = pcall(native.fcall, wt[99], fd, sa, 16)
  if ok_rb and type(rb_r) == "table" and rb_r.l == 0 then
    print("Bind succeeded after SO_REUSEADDR!")
  end
end

-- Close socket
pcall(native.fcall, wt[6], fd)
print("\nDone.")
