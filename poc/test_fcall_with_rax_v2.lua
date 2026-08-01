-- Test native.fcall_with_rax vs anti-check
print("=== fcall_with_rax anti-check bypass test ===\n")

local function hll_to_num(t)
  if type(t) ~= "table" then return t end
  return (t.h or 0) * 4294967296 + (t.l or 0)
end

local function fmt_addr(v)
  if type(v) == "table" then
    return string.format("0x%08x%08x", v.h or 0, v.l or 0)
  end
  return string.format("0x%x", v)
end

-- Normal call via wrapper
local wt = syscall.syscall_wrapper
print("--- Normal call SC585 (via wrapper) ---")
local ok, ret = pcall(native.fcall, wt[585], 0, 0, 0, 0, 0, 0)
if ok and type(ret) == "table" then
  print("SC585 wrapper: " .. fmt_addr(ret))
end

-- Check fcall_with_rax
if native.fcall_with_rax then
  print("\nnative.fcall_with_rax: EXISTS")
  
  -- Find raw syscall gadget at libkernel offset 0x2ba7
  -- Pattern: 49 89 ca (mov r10,rcx) + 0f 05 (syscall) + c3 (ret)
  local libk_hll = libkernel_base
  local libk = hll_to_num(libk_hll)
  print("libkernel_base: " .. fmt_addr(libk_hll))
  
  local gadget = libk + 0x2ba7
  print("raw syscall gadget: 0x" .. string.format("%x", gadget))
  
  -- Verify gadget bytes
  local b = memory.read_buffer(gadget, 5)
  local hex = ""
  for i = 1, #b do local by = string.byte(b, i); if type(by) == "table" then by = by.l end; hex = hex .. string.format("%02x", tonumber(by) or 0) end
  print("gadget bytes: " .. hex)
  
  -- Test 1: call SC585 with fcall_with_rax
  print("\n--- fcall_with_rax(gadget, 585, 0, 0, 0, 0, 0, 0) ---")
  local ok1, r1 = pcall(function()
    return native.fcall_with_rax(gadget, 585, 0, 0, 0, 0, 0, 0)
  end)
  if ok1 then
    if type(r1) == "table" then
      print("OK: " .. fmt_addr(r1))
    else
      print("OK: " .. tostring(r1))
    end
  else
    print("FAIL: " .. tostring(r1))
  end
  
  -- Test 2: arbitrary RAX (999 - not a real syscall)
  print("\n--- fcall_with_rax(gadget, 999, 0, 0, 0, 0, 0, 0) ---")
  local ok2, r2 = pcall(function()
    return native.fcall_with_rax(gadget, 999, 0, 0, 0, 0, 0, 0)
  end)
  if ok2 then
    if type(r2) == "table" then
      print("OK: " .. fmt_addr(r2))
    else
      print("OK: " .. tostring(r2))
    end
  else
    print("FAIL: " .. tostring(r2))
  end
  
  -- Test 3: SC596 (dynlib_process_needed_modules)
  print("\n--- fcall_with_rax(gadget, 596, 0, 0, 0, 0, 0, 0) ---")
  local ok3, r3 = pcall(function()
    return native.fcall_with_rax(gadget, 596, 0, 0, 0, 0, 0, 0)
  end)
  if ok3 then
    if type(r3) == "table" then
      print("OK: " .. fmt_addr(r3)) 
    else
      print("OK: " .. tostring(r3))
    end
  else
    print("FAIL: " .. tostring(r3))
  end
else
  print("\nnative.fcall_with_rax: NOT AVAILABLE")
  print("native functions:")
  for k, v in pairs(native) do
    print("  native." .. k .. " = " .. type(v))
  end
end

print("\nDone.")
