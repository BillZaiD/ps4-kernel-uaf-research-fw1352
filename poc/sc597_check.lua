-- Check syscall 597 (FSC2H) availability
print("=== SC597 FSC2H Check ===\n")

local wt = syscall.syscall_wrapper

-- Check if SC597 exists
print(string.format("SC597 wrapper: %s", tostring(wt[597])))
print(string.format("SC598 wrapper: %s", tostring(wt[598])))

-- Also check surrounding syscalls
print("\n--- Surrounding syscalls ---")
for n = 589, 600 do
    if wt[n] then
        print(string.format("  SC%03d: available", n))
    else
        print(string.format("  SC%03d: NOT available", n))
    end
end

-- List all Sony syscalls (585-677) that are available
print("\n--- All Sony syscalls (585-677) ---")
local available = {}
local missing = {}
for n = 585, 677 do
    if wt[n] then
        table.insert(available, n)
    else
        table.insert(missing, n)
    end
end

print(string.format("Available: %d", #available))
print(string.format("Missing: %d", #missing))
if #missing > 0 then
    print("Missing numbers:")
    local runs = {}
    local start = missing[1]
    local prev = start
    for i = 2, #missing + 1 do
        local m = missing[i]
        if m ~= prev + 1 then
            table.insert(runs, string.format("%d-%d", start, prev))
            if m then start = m end
            prev = m
        else
            prev = m
        end
    end
    for _, r in ipairs(runs) do print("  " .. r) end
end

print("\nDone!")
