-- Systematic fuzz of Sony custom syscalls (585-677)
print("=== Sony Custom Syscall Systematic Fuzz ===\n")

local wt = syscall.syscall_wrapper

local function fuzz_syscall(num, args)
    local w = wt[num]
    if not w then return "NO_W" end
    
    local ok, ret = pcall(native.fcall, w, args[1] or 0, args[2] or 0, args[3] or 0, args[4] or 0, args[5] or 0, args[6] or 0)
    if not ok then return "CRASH" end
    
    if type(ret) == "table" then
        local v = ret.h * 4294967296 + ret.l
        if v == 0 then return "0"
        elseif v == 0xFFFFFFFFFFFFFFFF then return "-1"
        elseif v < 0x1000 then return string.format("SM(%d)", v)
        elseif v > 0xFFFFFFFF80000000 then return "NEG"
        else return string.format("0x%x", v) end
    end
    return "?"
end

-- Test patterns
local patterns = {
    {name="zero", args={0, 0, 0, 0, 0, 0}},
    {name="a1buf", args={memory.alloc(0x40), 0, 0, 0, 0, 0}},
    {name="a1buf+s", args={memory.alloc(0x40), 0x40, 0, 0, 0, 0}},
    {name="a1=1", args={1, 0, 0, 0, 0, 0}},
    {name="a1=-1", args={0xFFFFFFFF, 0, 0, 0, 0, 0}},
    {name="a1=100", args={100, 0, 0, 0, 0, 0}},
    {name="a1=buf,a2=s", args={memory.alloc(0x100), 0x100, 0, 0, 0, 0}},
    {name="a1=s,a2=buf", args={0x100, memory.alloc(0x100), 0, 0, 0, 0}},
    {name="pid+buf", args={186, memory.alloc(0x100), 0x100, 0, 0, 0}},
    {name="buf+buf", args={memory.alloc(0x40), memory.alloc(0x40), 0, 0, 0, 0}},
}

-- Only test syscalls that exist
local available = {}
for num = 585, 677 do
    if wt[num] then table.insert(available, num) end
end
print(string.format("Testing %d syscalls with %d patterns each\n", #available, #patterns))

-- Track interesting results
local interesting = {}

for _, num in ipairs(available) do
    local results = {}
    local has_non_std = false
    
    for _, p in ipairs(patterns) do
        local r = fuzz_syscall(num, p.args)
        results[#results + 1] = r
        if r ~= "0" and r ~= "-1" and r ~= "CRASH" then
            has_non_std = true
        end
    end
    
    -- Print if any result is non-standard
    if has_non_std then
        print(string.format("SC%03d:", num))
        for i, p in ipairs(patterns) do
            print(string.format("  %12s -> %s", p.name, results[i]))
        end
        table.insert(interesting, num)
    end
end

print("\n--- Interesting syscalls ---")
if #interesting > 0 then
    for _, n in ipairs(interesting) do print(string.format("  SC%03d", n)) end
else
    print("  None found (all returned -1 or 0)")
end

print("\nDone!")
