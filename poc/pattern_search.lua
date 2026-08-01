-- Efficient search using read_buffer chunks
print("=== Efficient gadget search ===\n")

local base = libkernel_base

-- Read libkernel in 64KB chunks
local function search_pattern(pattern_str, max_offset)
    max_offset = max_offset or 0x50000
    local chunk_size = 0x10000  -- 64KB
    local results = {}
    local pat_len = #pattern_str
    
    for chunk_start = 0, max_offset - 1, chunk_size do
        local chunk_end = math.min(chunk_start + chunk_size + pat_len, max_offset)
        local len = chunk_end - chunk_start
        
        local data = memory.read_buffer(base + chunk_start, len)
        if data and #data > 0 then
            -- Search within chunk
            local pos = 1
            while true do
                pos = data:find(pattern_str, pos, 1)  -- plain match
                if not pos then break end
                table.insert(results, chunk_start + pos - 1)
                pos = pos + 1
                if #results >= 50 then break end
            end
        end
    end
    return results
end

-- Pattern 1: syscall; ret = 0f 05 c3
print("--- syscall; ret (0f 05 c3) ---")
local r1 = search_pattern("\x0f\x05\xc3", 0x50000)
print(string.format("Found %d", #r1))

-- Pattern 2: mov r10, rcx; syscall; ret = 49 89 ca 0f 05 c3
print("\n--- mov r10, rcx; syscall; ret (49 89 ca 0f 05 c3) ---")
local r2 = search_pattern("\x49\x89\xca\x0f\x05\xc3", 0x50000)
print(string.format("Found %d", #r2))
for i, off in ipairs(r2) do
    -- Show context
    local ctx = memory.read_buffer(base + off - 4, 16)
    local hex = ""
    for j = 1, #ctx do hex = hex .. string.format("%02x", string.byte(ctx, j)) end
    print(string.format("  0x%x: %s", off, hex))
    if i >= 10 then break end
end

-- Pattern 3: mov rax, ...; mov r10, rcx; syscall = complete wrapper
print("\n--- Full syscall wrappers ---")
local r3 = search_pattern("\x49\x89\xca\x0f\x05\x72", 0x50000)  -- mov r10, rcx; syscall; jb
print(string.format("Found %d", #r3))
for i, off in ipairs(r3) do
    -- Read backwards to find mov rax, imm32
    local ctx = memory.read_buffer(base + off - 8, 20)
    local hex = ""
    for j = 1, #ctx do hex = hex .. string.format("%02x", string.byte(ctx, j)) end
    
    -- Try to extract syscall number from mov rax instruction
    local b1 = string.byte(ctx, 5) or 0  -- byte at off-4
    local b2 = string.byte(ctx, 6) or 0
    local b3 = string.byte(ctx, 7) or 0
    local b4 = string.byte(ctx, 8) or 0
    
    if b1 == 0x48 and b2 == 0xc7 and b3 == 0xc0 then
        -- mov rax, imm32 at off-4
        local num = string.byte(ctx, 9) or 0  -- syscall number low byte
        local num2 = string.byte(ctx, 10) or 0
        local num3 = string.byte(ctx, 11) or 0
        local num4 = string.byte(ctx, 12) or 0
        local sc_num = num + num2 * 256 + num3 * 65536 + num4 * 16777216
        print(string.format("  0x%x: SC%03d: %s", off, sc_num, hex))
    elseif b1 == 0xb8 then
        -- mov eax, imm32 at off-1
        local num = b2
        local num2 = b3
        local num3 = b4
        local num4 = string.byte(ctx, 9) or 0
        local sc_num = num + num2 * 256 + num3 * 65536 + num4 * 16777216
        print(string.format("  0x%x: SC%03d (eax): %s", off, sc_num, hex))
    else
        print(string.format("  0x%x: ??? %s", off, hex))
    end
    
    if i >= 10 then break end
end

print("\nDone!")
