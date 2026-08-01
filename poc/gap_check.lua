-- Examine the gap between SC596 and SC598
print("=== Gap analysis ===\n")

local base = libkernel_base

-- Get actual wrapper addresses from table
local w596 = syscall.syscall_wrapper[596]
local w597 = syscall.syscall_wrapper[597]
local w598 = syscall.syscall_wrapper[598]

print(string.format("SC596 -> 0x%x", tonumber(tostring(w596):sub(3), 16) or 0))
if w597 then
    print(string.format("SC597 -> 0x%x", tonumber(tostring(w597):sub(3), 16) or 0))
else
    print("SC597 -> NIL (no wrapper)")
end
print(string.format("SC598 -> 0x%x", tonumber(tostring(w598):sub(3), 16) or 0))

-- Read 64 bytes starting from the gap
local gap_start = libkernel_base + 0x1d50
local b = memory.read_buffer(gap_start, 64)
local hex = ""
for i = 1, #b do hex = hex .. string.format("%02x", string.byte(b, i)) end

print(string.format("\nBytes from 0x1d50-0x1d8f:"))
for i = 0, 3 do
    local line = string.format("  0x%04x: ", 0x1d50 + i*16)
    for j = 1, 16 do
        local idx = i*16 + j
        if idx <= #hex/2 then
            line = line .. hex:sub(idx*2-1, idx*2) .. " "
        end
    end
    print(line)
end

-- Mark where wrappers start
print(string.format("\nSC596 wrapper: 0x1d50 (15 bytes: 0x1d50-0x1d5e)"))
print(string.format("SC597 wrapper address in table: %s", w597 and "exists" or "nil"))

-- Check what's at SC597 (if w597 != nil)
if w597 then
    local b597 = memory.read_buffer(w597, 32)
    local hex597 = ""
    for i = 1, #b597 do hex597 = hex597 .. string.format("%02x", string.byte(b597, i)) end
    print(string.format("SC597 wrapper bytes: %s", hex597))
end

-- Now check if there's a gap in the NUMBERS: 
-- The syscall table maps numbers to addresses. Let's find ALL wrappers
-- and see which numbers are missing
print("\n--- All wrappers from 585-677 (sorted by address) ---")
local entries = {}
for i = 585, 677 do
    local addr = syscall.syscall_wrapper[i]
    if addr then
        table.insert(entries, {num=i, addr=addr})
    end
end
table.sort(entries, function(a,b) 
    local ah = a.addr.h * 4294967296 + a.addr.l
    local bh = b.addr.h * 4294967296 + b.addr.l
    return ah < bh
end)

local prev_num = -1
local prev_addr = 0
for _, e in ipairs(entries) do
    local addr_num = e.addr.h * 4294967296 + e.addr.l
    local gap = addr_num - prev_addr
    local delta = e.num - prev_num
    if prev_num ~= -1 and delta ~= 1 and (gap > 64 or gap < 0) then
        print(string.format("  GAP: SC%03d->SC%03d (gap %d bytes)", prev_num, e.num, gap))
    end
    print(string.format("  SC%03d @ 0x%x (delta %d bytes)", e.num, addr_num, gap))
    prev_num = e.num
    prev_addr = addr_num
end

print("\n--- verif: does the wrapper at SC597 position actually exist? ---")
-- Check if any address in the table has mov rax, 0x255 (597)
for i = 585, 677 do
    local addr = syscall.syscall_wrapper[i]
    if addr then
        local b = memory.read_buffer(addr, 7)
        local b1 = string.byte(b, 1) or 0
        local b2 = string.byte(b, 2) or 0
        local b3 = string.byte(b, 3) or 0
        if b1 == 0x48 and b2 == 0xc7 and b3 == 0xc0 then
            local sc_num = string.byte(b, 4) + string.byte(b, 5)*256 + string.byte(b, 6)*65536 + string.byte(b, 7)*16777216
            if sc_num == 597 then
                print(string.format("  FOUND: SC%03d wrapper @ 0x%x is actually syscall %d!", i, addr_num, sc_num))
            end
        end
    end
end

print("\nDone!")
