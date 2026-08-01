-- Focused analysis of SC602 (and 606, 617, 620)
print("=== SC602, SC606, SC617, SC620 Deep Analysis ===\n")

local wt = syscall.syscall_wrapper

local function run_raw(sc, a1, a2, a3, a4)
  local w = wt[sc]
  if not w then return nil end
  local ok, ret = pcall(native.fcall, w, a1 or 0, a2 or 0, a3 or 0, a4 or 0, 0, 0)
  if not ok then return nil end
  return ret
end

local function hl_str(v)
  if not v or type(v) ~= "table" then return tostring(v) end
  local h = v.h or 0
  local l = v.l or 0
  return string.format("h=%d(0x%x) l=%d(0x%x)", h, h, l, l)
end

-- SC602: test with different argument patterns
print("=== SC602: arg patterns ===")
local test_buf = memory.alloc(0x100)

-- Vary buffer + size
print("  --- buffer + size ---")
local sizes = {0, 1, 4, 0x10, 0x40, 0x100, 0x200}
for _, sz in ipairs(sizes) do
  local ret = run_raw(602, test_buf, sz, 0, 0)
  if ret then
    print(string.format("    buf,sz=0x%x: %s", sz, hl_str(ret)))
  end
end

-- Vary a3 + a4
print("  --- a3, a4 variations ---")
for a3 = 0, 3 do
  for a4 = 0, 3 do
    local ret = run_raw(602, 0, 0, a3, a4)
    if ret and type(ret) == "table" and (ret.h ~= 0 or ret.l ~= 0) then
      if not (ret.h == -1 and ret.l == 4294967295) then
        print(string.format("    a1=0,a2=0,a3=%d,a4=%d: %s", a3, a4, hl_str(ret)))
      end
    end
  end
end

-- Test with only a1
print("  --- single arg tests ---")
local args = {0, 1, -1, 0xFFFFFFFF, 0x1000, 0x100000, 0xDEAD, 0xBEEF, 0x1337, 0x539, 0xDE, 0xEE}
for _, a1 in ipairs(args) do
  local ret = run_raw(602, a1, 0, 0, 0)
  if ret then
    if type(ret) == "table" and ret.h == 0 and ret.l == 0 then
      -- success - skip
    else
      print(string.format("    a1=0x%x: %s", a1, hl_str(ret)))
    end
  end
end

-- Check if SC602 writes to buffer at specific sizes
print("\n  --- buffer content after SC602 call ---")
for _, sz in ipairs({0, 1, 4, 8, 0x10, 0x40, 0x100}) do
  local buf = memory.alloc(0x100)
  for i = 0, 0xFF do memory.write_byte(buf + i, 0xBB) end
  
  local ret = run_raw(602, buf, sz, 0, 0)
  
  local mods = {}
  for i = 0, 0x3F do
    local b_raw = memory.read_byte(buf + i)
    local b_val = b_raw and b_raw.l or 0
    if b_val ~= 0xBB then
      table.insert(mods, {i, b_val})
    end
  end
  
  if #mods > 0 then
    print(string.format("    sz=0x%x ret=%s: %d bytes modified", sz, hl_str(ret), #mods))
    for _, m in ipairs(mods) do
      local c = m[2] >= 32 and m[2] < 127 and string.char(m[2]) or "."
      print(string.format("      [0x%x] = 0x%02x (%s)", m[1], m[2], c))
    end
  else
    print(string.format("    sz=0x%x ret=%s: no changes", sz, hl_str(ret)))
  end
end

-- SC606, 617, 620: test 
print("\n=== SC606, 617, 620: arg patterns ===")
for _, sc in ipairs({606, 617, 620}) do
  print(string.format("  --- SC%03d ---", sc))
  
  -- Test different arg combinations
  local tests = {
    {0, 0, 0, 0},
    {test_buf, 0x40, 0, 0},
    {1, 0, 0, 0},
    {-1, 0, 0, 0},
    {test_buf, 0, 0, 0},
    {0, 0, test_buf, 0x40},
  }
  
  for _, t in ipairs(tests) do
    local ret = run_raw(sc, t[1], t[2], t[3], t[4])
    if ret then
      print(string.format("    args=(%s,%s,%s,%s): %s", 
        t[1] == test_buf and "buf" or string.format("0x%x", t[1]),
        string.format("0x%x", t[2]),
        t[3] == test_buf and "buf" or string.format("0x%x", t[3]),
        string.format("0x%x", t[4]),
        hl_str(ret)))
    end
  end
end

print("\n[+] Done")
