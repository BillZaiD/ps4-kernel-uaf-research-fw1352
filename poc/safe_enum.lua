--[[
    safe_enum.lua
    Safe enumeration of PS4 Lua environment - NO risky memory reads
]]
local mem = rawget(_G, "memory")
local S = rawget(_G, "syscall")
local nat = rawget(_G, "native")

local function tonn(v)
    if v == nil then return 0 end
    if type(v) == "table" and v.h then return v.h * 4294967296 + v.l end
    return tonumber(tostring(v or 0)) or 0
end

local function toaddr(v)
    if v == nil then return 0 end
    if type(v) == "table" and v.h then return v.h * 4294967296 + v.l end
    return tonumber(tostring(v))
end

print("[+] Safe Environment Enumeration\n")

-- Step 1: Enumerate all global variables
print("[*] Global variables:\n")
for k, v in pairs(_G) do
    local t = type(v)
    if t == "function" then
        print(string.format("  %s()", k))
    elseif t == "table" then
        print(string.format("  %s = table", k))
    else
        print(string.format("  %s = %s", k, t))
    end
end

-- Step 2: Deep-dive into 'native' table
print("\n[*] native table contents:\n")
if nat then
    for k, v in pairs(nat) do
        local t = type(v)
        if t == "function" then
            print(string.format("  native.%s()", k))
        elseif t == "table" then
            print(string.format("  native.%s = table", k))
        else
            print(string.format("  native.%s = %s", k, tostring(v)))
        end
    end
end

-- Step 3: Check 'syscall' table beyond syscall_wrapper
print("\n[*] syscall table contents:\n")
if S then
    for k, v in pairs(S) do
        local t = type(v)
        if t == "function" then
            print(string.format("  syscall.%s()", k))
        elseif t == "table" then
            print(string.format("  syscall.%s = table (size=%d)", k, #v))
        else
            print(string.format("  syscall.%s = %s", k, tostring(v)))
        end
    end
end

-- Step 4: Check 'memory' table
print("\n[*] memory table contents:\n")
if mem then
    for k, v in pairs(mem) do
        local t = type(v)
        if t == "function" then
            print(string.format("  memory.%s()", k))
        elseif t == "table" then
            print(string.format("  memory.%s = table", k))
        else
            print(string.format("  memory.%s = %s", k, tostring(v)))
        end
    end
end

-- Step 5: Count total syscall wrappers
print("\n[*] Syscall wrapper count:\n")
local count = 0
for sc = 0, 2000 do
    local addr = toaddr(S.syscall_wrapper[sc])
    if addr and addr < 0xFFFFFFFFFFFF then
        count = count + 1
    end
end
print(string.format("  Total wrappers found: %d\n", count))

-- Step 6: Check for any other interesting globals
print("\n[*] Checking for common PS4 Lua globals:\n")
local checks = {"process", "module", "kernel", "pmon", "prx", "substitute", 
                "printf", "format", "error", "assert", "pcall", "xpcall",
                "load", "loadfile", "dofile", "require", "package"}
for _, name in ipairs(checks) do
    if _G[name] ~= nil then
        print(string.format("  %s = %s", name, type(_G[name])))
    end
end

-- Step 7: Do safe syscall probing - find which wrappers exist
print("\n[*] Syscall wrapper ranges:\n")
local ranges = {}
local start = -1
for sc = 0, 2000 do
    local addr = toaddr(S.syscall_wrapper[sc])
    local exists = (addr and addr < 0xFFFFFFFFFFFF)
    if exists and start == -1 then
        start = sc
    elseif not exists and start ~= -1 then
        table.insert(ranges, string.format("  [%d-%d]", start, sc-1))
        start = -1
    end
end
if start ~= -1 then
    table.insert(ranges, string.format("  [%d-...]", start))
end
for _, r in ipairs(ranges) do
    print(r)
end

print("\n[+] Safe enumeration complete - game alive")
