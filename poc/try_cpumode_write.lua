-- Try writing to cpumode sysctls
print("=== CPU mode manipulation ===\n")

-- Helper: write a sysctl with a 4-byte value
function write_sysctl(name, value)
    local buf = memory.alloc(4)
    memory.write_dword(buf, value)
    
    local ok, err = pcall(function()
        return sysctlbyname(name, nil, 0, buf, 4)
    end)
    
    return ok and err == true
end

-- Read current values
function read_sysctl_num(name)
    local buf = memory.alloc(8)
    local buf_size = memory.alloc(8)
    memory.write_qword(buf_size, 8)
    
    local ok, err = pcall(function()
        return sysctlbyname(name, buf, buf_size, nil, 0)
    end)
    
    if ok and err == true then
        local size = memory.read_qword(buf_size):tonumber()
        if size >= 1 then
            local val = 0
            for i = 1, math.min(size, 4) do
                local byte = memory.read_byte(buf + i - 1)
                val = val + (byte.l or byte) * 256^(i-1)
            end
            return val
        end
    end
    return nil
end

-- Read current cpumode values
print("Current values:")
print(string.format("  kern.cpumode = %d", read_sysctl_num("kern.cpumode") or -1))
print(string.format("  kern.cpumode_game = %d", read_sysctl_num("kern.cpumode_game") or -1))

-- Try writing kern.cpumode_game to 2 (devkit-like)
print("\nWriting kern.cpumode_game = 2...")
local w1 = write_sysctl("kern.cpumode_game", 2)
print(string.format("  Result: %s", tostring(w1)))
print(string.format("  New value: %d", read_sysctl_num("kern.cpumode_game") or -1))

-- Try writing kern.cpumode to 2
print("\nWriting kern.cpumode = 2...")
local w2 = write_sysctl("kern.cpumode", 2)
print(string.format("  Result: %s", tostring(w2)))
print(string.format("  New value: %d", read_sysctl_num("kern.cpumode") or -1))

print("\nDone!")
return "ok"
