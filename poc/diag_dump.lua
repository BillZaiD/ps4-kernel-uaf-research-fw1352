-- diagnostic: check libkernel base and memory access
local mem = rawget(_G, "memory")
local S = rawget(_G, "syscall")

local function tonn(v)
    if v == nil then return 0 end
    if type(v) == "table" and v.h then return v.h * 4294967296 + v.l end
    return tonumber(tostring(v or 0)) or 0
end

local lb = tonn(libkernel_base)
print("LB:" .. lb)

-- test reading at base
local b0 = tonn(mem.read_byte(lb))
local b1 = tonn(mem.read_byte(lb + 1))
print("BYTES:" .. b0 .. "," .. b1)

-- test check_memory_access
local cm1 = check_memory_access(lb, 4)
print("CM1:" .. tostring(cm1))

-- test reading the wrapper
local w = tonn(S.syscall_wrapper[454])
print("W:" .. w)
local cm2 = check_memory_access(w, 4)
print("CM2:" .. tostring(cm2))
