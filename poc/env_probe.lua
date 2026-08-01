-- Probe: networking + filesystem + browser capabilities
print("=== Environment Probe ===\n")

-- Check if we can list files in savedata
local function exists(name)
  local ok, err = pcall(function() return _G[name] end)
  return ok and _G[name] ~= nil
end

-- Check for file operations
print("--- File Operations ---")
local file_ops = {"io", "os", "lfs", "lua.open", "lua.read_file", "lua.write_file", "lua.load_file"}
for _, name in ipairs(file_ops) do
  local parts = {}
  for p in name:gmatch("%w+") do table.insert(parts, p) end
  local obj = _G
  local found = true
  for _, p in ipairs(parts) do
    if type(obj) == "table" then obj = obj[p] else found = false; break end
  end
  print(string.format("  %s: %s", name, found and type(obj) or "nil"))
end

-- Check for networking
print("\n--- Networking ---")
local net_ops = {"socket", "net", "http", "curl", "url", "https"}
for _, name in ipairs(net_ops) do
  print(string.format("  %s: %s", name, exists(name) and type(_G[name]) or "nil"))
end

-- Check net.* sub-modules
if _G.net and type(_G.net) == "table" then
  print("  net contents:")
  for k, v in pairs(_G.net) do
    print(string.format("    net.%s = %s", k, type(v)))
  end
end

-- Check for browser/WebKit
print("\n--- Browser/WebKit ---")
local browser_ops = {"webkit", "browser", "OpenBrowser", "launch_browser", "sceScreenShot"}
for _, name in ipairs(browser_ops) do
  print(string.format("  %s: %s", name, exists(name) and type(_G[name]) or "nil"))
end

-- Check if we can execute shell commands
print("\n--- Shell/Execute ---")
local exec_ops = {"os.execute", "io.popen", "dynlib_load_prx", "syscall.syscall_wrapper[594]"}
for _, name in ipairs(exec_ops) do
  local parts = {}
  for p in name:gmatch("%w+") do table.insert(parts, p) end
  local obj = _G
  local found = true
  for _, p in ipairs(parts) do
    if type(obj) == "table" then
      local num = tonumber(p)
      obj = obj[num or p]
    else found = false; break end
  end
  print(string.format("  %s: %s", name, found and type(obj) or "nil"))
end

-- Check if we can open a TCP server
print("\n--- TCP Sockets ---")
local function check_tcp()
  local sock = socket or net and net.socket
  if sock then
    print("  socket library FOUND")
    for k, v in pairs(sock) do print(string.format("    socket.%s = %s", k, type(v))) end
  else
    print("  socket library: nil")
  end
  -- Try syscall socket operations
  local wt = syscall.syscall_wrapper
  print(string.format("  SC97 (socket): %s", wt[97] and "exists" or "nil"))
  print(string.format("  SC98 (connect): %s", wt[98] and "exists" or "nil"))
  print(string.format("  SC99 (bind): %s", wt[99] and "exists" or "nil"))
  print(string.format("  SC100 (listen): %s", wt[100] and "exists" or "nil"))
  print(string.format("  SC396 (socket): %s", wt[396] and "exists" or "nil"))
end
check_tcp()

print("\nDone.")
