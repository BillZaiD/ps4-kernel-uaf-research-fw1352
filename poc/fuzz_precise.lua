-- Precise fuzzing with proper uint64 handling (avoid Lua double precision loss)
print("=== Precise Sony Syscall Fuzzing ===\n")

local wt = syscall.syscall_wrapper

local function run_raw(sc, a1, a2, a3, a4, a5, a6)
  local w = wt[sc]
  if not w then return nil end
  local ok, ret = pcall(native.fcall, w, a1 or 0, a2 or 0, a3 or 0, a4 or 0, a5 or 0, a6 or 0)
  if not ok then return nil end
  return ret  -- return raw uint64 table
end

-- Check if value is -1 (0xFFFFFFFFFFFFFFFF)
local function is_minus1(v)
  return type(v) == "table" and v.h == 0xFFFFFFFF and v.l == 0xFFFFFFFF
end

local function is_zero(v)
  return type(v) == "table" and v.h == 0 and v.l == 0
end

local function is_error(v)
  -- Common PS4 error codes in uint64 format
  -- Return true if high 32 bits are 0xFFFFFFFF
  return type(v) == "table" and v.h == 0xFFFFFFFF
end

local function format_val(v)
  if type(v) ~= "table" then return tostring(v) end
  return string.format("0x%08x%08x", v.h or 0, v.l or 0)
end

local function fmt_hl(h, l)
  return string.format("0x%08x%08x", h, l)
end

-- Test SC600-SC677 with zero args
print("=== SC600-SC677 with zero args ===")
for sc = 600, 677 do
  local ret = run_raw(sc, 0, 0, 0, 0, 0, 0)
  if ret and type(ret) == "table" then
    local is_err = ret.h == 0xFFFFFFFF
    local is_n1 = ret.h == 0xFFFFFFFF and ret.l == 0xFFFFFFFF
    local is_0 = ret.h == 0 and ret.l == 0
    local desc = ""
    if is_n1 then desc = "(-1)"
    elseif is_0 then desc = "(0)"
    elseif is_err then 
      local err_code = -1 - (0xFFFFFFFF - ret.l)  -- convert to negative number
      if err_code == -999 then desc = "(ERR -999)"
      elseif err_code == -1 then desc = "(ERR -1)"  -- h == 0xFFFFFFFF but l != 0xFFFFFFFF
      else desc = "(ERR " .. err_code .. ")" end
    else desc = "(0x" .. string.format("%x", ret.l) .. ")" end
    
    if not is_n1 and not is_0 then
      print(string.format("  SC%03d -> %s %s", sc, format_val(ret), desc))
    end
  end
end

-- Focus on SC609, SC614, SC621 specifically
print("\n=== SC609/614/621 detailed ===")
for _, sc in ipairs({609, 614, 621}) do
  local ret = run_raw(sc, 0, 0, 0, 0, 0, 0)
  if ret and type(ret) == "table" then
    print(string.format("  SC%03d: h=0x%08x l=0x%08x", sc, ret.h, ret.l))
    print(string.format("  -> Full: %s", format_val(ret)))
  end
end

-- Now test with buffer+size patterns, track L bit
print("\n=== SC638/SC657: buffer content (using raw uint64) ===")

local function test_buffer_write(sc, size)
  local buf = memory.alloc(0x100)
  -- Fill with known pattern
  for i = 0, 0xFF do memory.write_byte(buf + i, 0xAA) end
  
  local ret = run_raw(sc, buf, size, 0, 0, 0, 0)
  
  -- Check raw bytes in buffer using direct read (not tonumber)
  local modified = false
  for i = 0, math.min(size - 1, 0xFF) do
    local b_raw = memory.read_byte(buf + i)  -- returns uint64 table
    local b_low = b_raw and b_raw.l or 0
    if b_low ~= 0xAA then
      if not modified then
        print(string.format("  SC%03d sz=0x%x ret=%s:", sc, size, format_val(ret)))
        modified = true
      end
      print(string.format("    [0x%x] was 0xAA now 0x%02x", i, b_low))
    end
  end
  
  if not modified then
    print(string.format("  SC%03d sz=0x%x ret=%s: no changes", sc, size, format_val(ret)))
  end
end

for _, sc in ipairs({638, 657}) do
  for _, sz in ipairs({0, 0x10, 0x40, 0x100}) do
    test_buffer_write(sc, sz)
  end
end

-- Test with specific size value to see pattern
print("\n=== SC638/SC657: return value vs size ===")
for sc = 636, 660 do
  if wt[sc] then
    local ret_buf = run_raw(sc, memory.alloc(0x40), 0x40, 0, 0, 0, 0)
    local ret_zero = run_raw(sc, 0, 0, 0, 0, 0, 0)
    
    local b_desc = ""
    if ret_buf and type(ret_buf) == "table" then
      if is_minus1(ret_buf) then b_desc = "buf:-1"
      elseif is_zero(ret_buf) then b_desc = "buf:0"
      elseif ret_buf.h == 0xFFFFFFFF then b_desc = "buf:err"
      else b_desc = "buf:" .. format_val(ret_buf) end
    end
    
    local z_desc = ""
    if ret_zero and type(ret_zero) == "table" then
      if is_minus1(ret_zero) then z_desc = "zero:-1"
      elseif is_zero(ret_zero) then z_desc = "zero:0"
      elseif ret_zero.h == 0xFFFFFFFF then z_desc = "zero:err"
      else z_desc = "zero:" .. format_val(ret_zero) end
    end
    
    if b_desc ~= "buf:-1" or z_desc ~= "zero:-1" then
      print(string.format("  SC%03d: %s | %s", sc, z_desc, b_desc))
    end
  end
end

print("\n[+] Done")
