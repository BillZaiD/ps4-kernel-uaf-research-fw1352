-- Deep analysis of SC602 boolean behavior
local wt = syscall.syscall_wrapper

local function sc(num, a1, a2, a3, a4, a5, a6)
    local w = wt[num]
    if not w then return "NO_W" end
    local ok, ret = pcall(native.fcall, w, a1 or 0, a2 or 0, a3 or 0, a4 or 0, a5 or 0, a6 or 0)
    if not ok then return "CRASH" end
    if type(ret) == "table" then return ret.h * 4294967296 + ret.l end
    if type(ret) == "number" then return ret end
    return 0
end

print("=== SC602 argument range test ===\n")
print("--- Small values ---")
for i = 0, 10 do
    local r = sc(602, i)
    print(string.format("  a1=%d -> 0x%x", i, r))
end

print("\n--- Powers of 2 ---")
local val = 1
for shift = 0, 31 do
    local r = sc(602, val)
    print(string.format("  a1=2^%d = %d -> 0x%x", shift, val, r))
    val = val * 2
end

print("\n--- Negative values (u32) ---")
for _, val in ipairs({0x80000000, 0xFFFFFFFF, 0x7FFFFFFF, 0x80000001}) do
    local r = sc(602, val)
    print(string.format("  a1=0x%x -> 0x%x", val, r))
end

print("\n--- With 2nd argument ---")
for a1 = 0, 3 do
    for a2 = 0, 3 do
        local r = sc(602, a1, a2)
        print(string.format("  a1=%d a2=%d -> 0x%x", a1, a2, r))
    end
end

print("\n--- Check if other returning-0 syscalls respond to args ---")
local function test_arg_response(syscall_num)
    local r0 = sc(syscall_num, 0)
    local r1 = sc(syscall_num, 0, 0)
    local r2 = sc(syscall_num, 1)
    local r3 = sc(syscall_num, 0, 1)
    local r4 = sc(syscall_num, -1)
    local different = (r0 ~= r1 or r1 ~= r2 or r2 ~= r3 or r3 ~= r4)
    print(string.format("  SC%03d: 0=%x 0,0=%x 1=%x 0,1=%x -1=%x diff=%s", 
        syscall_num, r0, r1, r2, r3, r4, tostring(different)))
end

print("\n--- All 6: arg response check ---")
for _, n in ipairs({596, 599, 602, 606, 617, 620}) do
    test_arg_response(n)
end

print("\nDone!")
