-- try to write to libkernel code page and test mprotect properly
print("libkernel_base: 0x" .. string.format("%x%08x", libkernel_base.h, libkernel_base.l))

-- offset with NOP sled (0x464 into libkernel)
local target_addr = {h = libkernel_base.h, l = libkernel_base.l + 0x464}
print("target: 0x" .. string.format("%x%08x", target_addr.h, target_addr.l))

-- try native.write_buffer to write to libkernel
if type(native.write_buffer) == "function" then
    local test_data = string.char(0x90, 0x90)
    local ok, err = pcall(native.write_buffer, target_addr, test_data)
    print("write_buffer to libkernel: " .. tostring(ok) .. " " .. tostring(err or ""))
end

-- try lua.write_qword (if available)
if lua and lua.write_qword then
    local ok, err = pcall(lua.write_qword, target_addr, 0x9090909090909090)
    print("lua.write_qword: " .. tostring(ok))
end

-- Read back to see if write worked
local mem = rawget(_G, "memory")
if mem and mem.read_buffer then
    local data = mem.read_buffer(target_addr, 8)
    if data then
        local s = ""
        for i = 1, #data do
            s = s .. string.format("%02x ", string.byte(data, i))
        end
        print("read back: " .. s)
    end
end
