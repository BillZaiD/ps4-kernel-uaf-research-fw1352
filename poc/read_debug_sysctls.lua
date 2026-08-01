-- Try to read and write debug sysctls
print("=== Debug sysctl write attempt ===\n")

-- Helper: read a sysctl value as number
function read_sysctl_num(name)
    local buf = memory.alloc(8)
    local buf_size = memory.alloc(8)
    memory.write_qword(buf_size, 8)
    
    local ok, err = pcall(function()
        return sysctlbyname(name, buf, buf_size, nil, 0)
    end)
    
    if ok and err == true then
        local size = memory.read_qword(buf_size):tonumber()
        if size >= 1 and size <= 8 then
            local val = 0
            for i = 1, size do
                local byte = memory.read_byte(buf + i - 1)
                val = val + (byte.l or byte) * 256^(i-1)
            end
            return val
        end
    end
    return nil
end

-- Helper: write a sysctl with a numeric value
function write_sysctl_num(name, value)
    local buf = memory.alloc(4)
    memory.write_dword(buf, value)
    
    local ok, err = pcall(function()
        return sysctlbyname(name, nil, 0, buf, 4)
    end)
    
    return ok and err == true
end

-- Test each debug sysctl
local targets = {
    "machdep.rcmgr_sl_debugger",
    "machdep.rcmgr_debug_menu",
    "machdep.rcmgr_debug_menu_for_psm",
    "machdep.rcmgr_debug_menu_mini",
    "machdep.rcmgr_flaged_updater",
    "machdep.rcmgr_force_update",
    "machdep.rcmgr_fake_finalize",
    "machdep.rcmgr_intdev",
    "machdep.rcmgr_psm_intdev",
    "machdep.rcmgr_special_i",
    "kern.cpumode",
}

for _, name in ipairs(targets) do
    local val = read_sysctl_num(name)
    if val ~= nil then
        print(string.format("  %s = %d (0x%x)", name, val, val))
    else
        print(string.format("  %s = (unreadable)", name))
    end
end

print("\nDone!")
return "ok"
