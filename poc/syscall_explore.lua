-- Systematic exploration of the 6 successful syscalls
local wt = syscall.syscall_wrapper

-- Syscall runner
local function sc(num, a1, a2, a3, a4, a5, a6)
    local w = wt[num]
    if not w then return "NO_W" end
    local ok, ret = pcall(native.fcall, w, a1 or 0, a2 or 0, a3 or 0, a4 or 0, a5 or 0, a6 or 0)
    if not ok then return "CRASH" end
    if type(ret) == "table" then
        local v = ret.h * 4294967296 + ret.l
        return v
    elseif type(ret) == "number" then return ret end
    return 0
end

-- Test each of the 6 interesting syscalls with various args
local targets = {596, 599, 602, 606, 617, 620}
local test_cases = {
    {name="zero", args={}},
    {name="int:1", args={1}},
    {name="int:0xFF", args={0xFF}},
    {name="int:-1", args={0xFFFFFFFF}},
    {name="ptr:alloc(0x40)", args={memory.alloc(0x40)}},
    {name="ptr+0x100", args={memory.alloc(0x100), 0x100}},
    {name="2ints:1,1", args={1, 1}},
    {name="int,ptr", args={0xBA, memory.alloc(0x40)}},
    {name="ptr,ptr", args={memory.alloc(0x40), memory.alloc(0x40)}},
}

for _, n in ipairs(targets) do
    print(string.format("=== SC%03d ===", n))
    for _, tc in ipairs(test_cases) do
        local args = tc.args
        local r = sc(n, args[1], args[2], args[3], args[4], args[5], args[6])
        print(string.format("  %15s -> 0x%x", tc.name, r))
    end
    print("")
end

-- Also check consistency: does repeated call give same result?
print("=== Consistency check (10x calls) ===")
for _, n in ipairs(targets) do
    local results = {}
    for i = 1, 10 do
        results[i] = sc(n)
    end
    local consistent = true
    for i = 2, 10 do
        if results[i] ~= results[1] then consistent = false; break end
    end
    print(string.format("  SC%03d: consistent=%s val=0x%x", n, tostring(consistent), results[1]))
end

print("\nDone!")
