-- Debug uint64 return value format
local wt = syscall.syscall_wrapper

print("=== Debug return value format ===\n")

local function run_raw(sc)
  local w = wt[sc]
  if not w then return nil end
  local ok, ret = pcall(native.fcall, w, 0, 0, 0, 0, 0, 0)
  if not ok then print("pcall failed for SC" .. tostring(sc)); return nil end
  return ret
end

-- Test several syscalls
for _, sc in ipairs({20, 24, 585, 600, 609, 624}) do
  local ret = run_raw(sc)
  if ret then
    print("SC" .. tostring(sc) .. " return type: " .. type(ret))
    if type(ret) == "table" then
      for k, v in pairs(ret) do
        print(string.format("  %s = %s (type %s)", tostring(k), tostring(v), type(v)))
      end
    else
      print("  value = " .. tostring(ret))
    end
  end
end

-- Check what native.fcall actually returns
print("\n=== Test with getpid (SC20) ===")
local ret = run_raw(20)
if ret then
  print("type: " .. type(ret))
  if type(ret) == "table" then
    print(string.format("h=%s l=%s", tostring(ret.h), tostring(ret.l)))
  end
end

-- Try the uint64 conversion function directly
print("\n=== Using uint64() conversion ===")
local getpid_result = run_raw(20)
if getpid_result then
  print("raw ret: " .. tostring(getpid_result))
  -- Try different conversion methods
  local conv1 = uint64(getpid_result)
  print("uint64(): " .. tostring(conv1))
  if type(conv1) == "table" then
    print("  h=" .. tostring(conv1.h) .. " l=" .. tostring(conv1.l))
  end
  print("tonumber(): " .. tostring(uint64(getpid_result):tonumber()))
end

print("\n[+] Done")
