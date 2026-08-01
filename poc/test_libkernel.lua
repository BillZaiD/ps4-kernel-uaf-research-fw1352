-- find libkernel_base value and test mprotect on executable memory
local lb = libkernel_base
print("libkernel_base type: " .. type(lb) .. " h=" .. tostring(lb.h) .. " l=" .. tostring(lb.l))
print("libkernel_base addr: 0x" .. string.format("%x%08x", lb.h, lb.l))

-- Also check what the memory.lua reports
print("\n-- Trying mprotect on a known area --")
local wrapper74 = syscall.syscall_wrapper[74]
if wrapper74 then
    local test_addr = fcall.chain.stack_base
    print("stack_base: 0x" .. string.format("%x%08x", test_addr.h, test_addr.l))
    local ok, ret = pcall(native.fcall, wrapper74, test_addr, 0x1000, 7)
    print("mprotect stack RWX: " .. tostring(ok) .. " " .. tostring(ret))
end

-- Try reading from libkernel via memory.read_buffer
print("\n-- Reading from libkernel --")
local mem = rawget(_G, "memory")
if mem and mem.read_buffer then
    local data = mem.read_buffer(lb, 16)
    if data then
        local s = ""
        for i = 1, #data do
            s = s .. string.format("%02x ", string.byte(data, i))
        end
        print("First 16 bytes: " .. s)
    end
end
