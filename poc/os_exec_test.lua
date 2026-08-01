-- Test os.execute capabilities for save data modification + network
print("=== os.execute Deep Test ===\n")

-- Test if we can write to savedata via shell redirect
print("--- File Write via shell ---")
local r1 = os.execute("echo 'print(\"injected\")' > /savedata0/injected.lua")
print(string.format("  echo write: %s", (r1 == 0 and "OK" or "FAILED (" .. tostring(r1) .. ")")))

-- Read it back via framework loader (the framework uses dofile)
local ok, injected = pcall(dofile, "/savedata0/injected.lua")
if ok then
  print("  dofile injected.lua: WORKS!")
else
  print("  dofile injected.lua: FAILED - " .. tostring(injected))
end

-- Test network tools
print("\n--- Network Tools ---")
local cmds = {
  "which curl 2>/dev/null; echo ---; which nc 2>/dev/null; echo ---; which python 2>/dev/null",
}
for _, cmd in ipairs(cmds) do
  os.execute(cmd)
end

-- Test if we can create a background process
print("\n--- Background Process ---")
local r2 = os.execute("sleep 5 &")
print(string.format("  sleep &: %s", (r2 == 0 and "OK" or tostring(r2))))

-- Test ifconfig
print("\n--- ifconfig ---")
os.execute("ifconfig 2>/dev/null")

-- Test netstat
print("\n--- netstat ---")
os.execute("netstat -tlnp 2>/dev/null")

-- Test ps
print("\n--- ps ---")
os.execute("ps aux 2>/dev/null | head -20")

-- Test ls savedata
print("\n--- ls savedata ---")
os.execute("ls -la /savedata0/ 2>/dev/null")

print("\nDone.")
