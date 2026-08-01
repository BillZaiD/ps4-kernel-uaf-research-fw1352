-- Enumerate available syscalls
print("=== SYSCTL WRAPPER SCAN ===")
local S = rawget(_G, "syscall")
for k, v in pairs(S) do
  if type(k) == "string" then
    print(string.format("  %s = %s", k, type(v)))
  end
end
print("\n=== syscall_wrapper TABLE ===")
if S.syscall_wrapper then
  for k, v in pairs(S.syscall_wrapper) do
    if type(v) == "table" then
      print(string.format("  sc[%s] h=%s l=%s", tostring(k), tostring(v.h), tostring(v.l)))
    elseif type(v) == "function" then
      print(string.format("  sc[%s] = function", tostring(k)))
    else
      print(string.format("  sc[%s] = %s", tostring(k), type(v)))
    end
  end
end
print("\n=== DONE ===")
