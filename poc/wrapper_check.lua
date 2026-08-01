-- Check actual syscall wrapper bytes
print("=== Actual wrapper bytes ===\n")

local base = libkernel_base

-- Get wrapper addresses from syscall table
local wt = syscall.syscall_wrapper

-- Read wrapper bytes for several syscalls
local function show_wrapper(name, addr)
    local b = memory.read_buffer(addr, 32)
    local hex = ""
    for i = 1, #b do hex = hex .. string.format("%02x", string.byte(b, i)) end
    print(string.format("  %s: %s", name, hex))
end

print("--- SC20 (getpid) ---")
show_wrapper("SC20", wt[20])

print("--- SC585 ---")
show_wrapper("SC585", wt[585])

print("--- SC596 ---")
show_wrapper("SC596", wt[596])

print("--- SC598 ---")
show_wrapper("SC598", wt[598])

print("--- SC602 ---")
show_wrapper("SC602", wt[602])

print("--- SC624 ---")
show_wrapper("SC624", wt[624])

print("\n--- Check if mov rax is used ---")
-- Check if the wrappers use mov rax, imm64 or mov eax, imm32
-- mov rax, imm64: 48 b8 XX XX XX XX XX XX XX XX (10 bytes)
-- mov eax, imm32: b8 XX XX XX XX (5 bytes)
-- mov rax, imm32: 48 c7 c0 XX XX XX 00 (7 bytes)

for _, num in ipairs({20, 585, 596, 598, 602, 624}) do
    local addr = wt[num]
    if addr then
        local b = memory.read_buffer(addr, 8)
        local hex = ""
        for i = 1, #b do hex = hex .. string.format("%02x", string.byte(b, i)) end
        local b1 = string.byte(b, 1) or 0
        local desc = ""
        if b1 == 0xB8 then
            local syscall_num = string.byte(b, 2) or 0
            desc = string.format("mov eax, %d", syscall_num)
        elseif b1 == 0x48 and string.byte(b, 2) == 0xB8 then
            desc = "mov rax, imm64"
        elseif b1 == 0x48 and string.byte(b, 2) == 0xC7 and string.byte(b, 3) == 0xC0 then
            local num_bytes = {string.byte(b, 4), string.byte(b, 5), string.byte(b, 6), string.byte(b, 7)}
            local sc_num = num_bytes[1] + num_bytes[2]*256 + num_bytes[3]*65536 + num_bytes[4]*16777216
            desc = string.format("mov rax, %d (48 c7 c0)", sc_num)
        else
            desc = "unknown"
        end
        print(string.format("  SC%03d (0x%x): %s -> %s", num, tonumber(tostring(addr):sub(3), 16) or 0, hex, desc))
    end
end

print("\nDone!")
