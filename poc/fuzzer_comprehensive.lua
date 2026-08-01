-- comprehensive syscall fuzzer
local wrapper_table = syscall.syscall_wrapper
local wrapper74 = wrapper_table[74]  -- mprotect

-- test a syscall with specific args
local function test_syscall(num, a1, a2, a3, a4, a5, a6)
    local w = wrapper_table[num]
    if not w then return "NO_WRAP" end
    local ok, ret = pcall(native.fcall, w, a1 or 0, a2 or 0, a3 or 0, a4 or 0, a5 or 0, a6 or 0)
    if not ok then return "LUA_ERR" end
    local rh, rl = 0, 0
    if type(ret) == "table" then rh, rl = ret.h or 0, ret.l or 0
    elseif type(ret) == "number" then rl = ret end
    return "R:" .. string.format("%x%08x", rh, rl)
end

print("=== Sony Custom Syscall Fuzzer ===\n")

-- Test all syscalls with zero args first
print("--- Zero args ---")
for num = 585, 677 do
    local result = test_syscall(num, 0, 0, 0, 0, 0, 0)
    if result ~= "NO_WRAP" then
        print("syscall " .. num .. ": " .. result)
    end
end

-- For syscalls that returned something specific (not -1), try with specific args
print("\n--- Targeted tests ---")
local interesting = {}
for num = 585, 677 do
    local w = wrapper_table[num]
    if w then
        local ok, ret = pcall(native.fcall, w, 0, 0, 0, 0, 0, 0)
        if ok then
            local rh, rl = 0, 0
            if type(ret) == "table" then rh, rl = ret.h or 0, ret.l or 0 end
            if rl ~= 0xffffffff or rh ~= 0xffffffff then
                table.insert(interesting, num)
            end
        end
    end
end

-- Try the interesting ones with non-zero args
for _, num in ipairs(interesting) do
    local w = wrapper_table[num]
    -- try with different patterns
    local patterns = {
        {1, 1, 1, 1, 1, 1},
        {0x41414141, 0, 0, 0, 0, 0},
        {0, 0x41414141, 0, 0, 0, 0},
        {0xffffffff, 0xffffffff, 0, 0, 0, 0},
    }
    for pi, pat in ipairs(patterns) do
        local result = test_syscall(num, pat[1], pat[2], pat[3], pat[4], pat[5], pat[6])
        print("syscall " .. num .. " pat" .. pi .. ": " .. result)
    end
end

print("\nDone!")
