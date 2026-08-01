-- Precise check of SC609, SC614, SC621 etc. using raw h/l format
print("=== Precise syscall check ===\n")

local wt = syscall.syscall_wrapper

local function run_raw(sc, a1, a2, a3, a4)
  local w = wt[sc]
  if not w then return nil end
  local ok, ret = pcall(native.fcall, w, a1 or 0, a2 or 0, a3 or 0, a4 or 0, 0, 0)
  if not ok then return nil end
  return ret
end

-- Target: SC600-SC677
print("=== SC600-SC677 raw h/l ===")
for sc = 600, 677 do
  if wt[sc] then
    local r_zero = run_raw(sc, 0, 0, 0, 0)
    local r_buf = run_raw(sc, memory.alloc(0x40), 0x40, 0, 0)
    
    if r_zero and type(r_zero) == "table" and r_buf and type(r_buf) == "table" then
      -- Only show if not simple -1 for both
      local z_is_n1 = (r_zero.h == -1 or r_zero.h == 4294967295) and r_zero.l == 4294967295
      local b_is_n1 = (r_buf.h == -1 or r_buf.h == 4294967295) and r_buf.l == 4294967295
      
      if not (z_is_n1 and b_is_n1) then
        print(string.format("  SC%03d zero: h=%d(%08x) l=%d(%08x)", sc, r_zero.h, r_zero.h, r_zero.l, r_zero.l))
        print(string.format("        buf: h=%d(%08x) l=%d(%08x)", r_buf.h, r_buf.h , r_buf.l, r_buf.l))
      end
    end
  end
end

-- Detailed check of SC609, 614, 621
print("\n=== SC609, SC614, SC621 ===")
for _, sc in ipairs({609, 614, 621, 600, 624, 638, 657}) do
  local r = run_raw(sc, 0, 0, 0, 0)
  if r and type(r) == "table" then
    local h_unsigned = r.h < 0 and (r.h + 4294967296) or r.h
    print(string.format("  SC%03d: h=%d(%08x) l=%d(%08x) full=0x%08x%08x", 
      sc, r.h, h_unsigned, r.l, r.l, h_unsigned, r.l))
  end
end

-- Now check all Sony syscalls for non-standard return values
print("\n=== All Sony syscalls scan ===")
for sc = 585, 677 do
  if wt[sc] then
    local r = run_raw(sc, 0, 0, 0, 0)
    if r and type(r) == "table" then
      local h_unsigned = r.h < 0 and (r.h + 4294967296) or r.h
      local is_n1 = h_unsigned == 0xFFFFFFFF and r.l == 0xFFFFFFFF
      local is_0 = h_unsigned == 0 and r.l == 0
      
      if not is_n1 and not is_0 then
        print(string.format("  SC%03d: 0x%08x%08x", sc, h_unsigned, r.l))
      end
    end
  end
end

-- Test with different buffer sizes to see if any syscall writes
print("\n=== Buffer content check (all Sony syscalls) ===")
for sc = 600, 677 do
  if wt[sc] then
    for _, sz in ipairs({0, 0x40}) do
      if sz > 0 then
        local buf = memory.alloc(sz + 16)
        for i = 0, sz + 15 do memory.write_byte(buf + i, i % 256) end
        
        local ret = run_raw(sc, buf, sz, 0, 0)
        
        -- Check first few bytes
        local changed = false
        for i = 0, math.min(15, sz - 1) do
          local b_raw = memory.read_byte(buf + i)
          if b_raw and type(b_raw) == "table" and b_raw.l ~= (i % 256) then
            changed = true
            break
          end
        end
        
        if changed then
          print(string.format("  SC%03d sz=0x%x: BUFFER MODIFIED!", sc, sz))
          for i = 0, math.min(63, sz - 1) do
            local b_raw = memory.read_byte(buf + i)
            local b = b_raw and b_raw.l or 0
            if b ~= (i % 256) then
              io.write(string.format("    [0x%x] was 0x%02x now 0x%02x\n", i, i % 256, b))
            end
          end
        end
      end
    end
  end
end

print("\n[+] Done")
