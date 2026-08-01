-- Read interesting sysctls properly with buffer
print("=== Read interesting sysctls ===\n")

-- sysctlbyname(name, oldp, oldp_len, newp, newp_len)
-- Returns boolean (success/fail)

local sysctls_to_check = {
    "kern.sdk_version",
    "kern.cpumode",
    "kern.cpumode_game",
    "machdep.tsc_freq",
    "machdep.idps",
    "machdep.openpsid",
    "machdep.curr_manumode",
    "machdep.hwfeature_for_decid",
    "machdep.rcmgr_sl_debugger",
    "machdep.rcmgr_debug_menu",
    "machdep.rcmgr_debug_menu_for_psm",
    "machdep.rcmgr_debug_menu_mini",
    "machdep.rcmgr_flaged_updater",
    "machdep.rcmgr_force_update",
    "machdep.rcmgr_special_i",
    "machdep.rcmgr_fake_finalize",
    "machdep.rcmgr_intdev",
    "machdep.rcmgr_psm_intdev",
}

for _, name in ipairs(sysctls_to_check) do
    local buf = memory.alloc(256)
    local buf_size = memory.alloc(8)
    memory.write_qword(buf_size, 256)
    
    local ok, err = pcall(function()
        return sysctlbyname(name, buf, buf_size, nil, 0)
    end)
    
    if ok and err == true then
        local size_read = memory.read_qword(buf_size)
        local val = memory.read_buffer(buf, size_read:tonumber())
        if val and #val > 0 then
            -- Try to interpret as string
            local null_pos = val:find("\0")
            if null_pos then
                val = val:sub(1, null_pos - 1)
            end
            
            -- Also try as number
            local num = 0
            if #val <= 8 then
                num = 0
                for i = 1, #val do
                    num = num + string.byte(val, i) * 256^(i-1)
                end
            end
            
            if #val <= 8 and num > 0 and num < 0xffffffff then
                print(string.format("  %s = 0x%x (%d) | '%s'", name, num, num, val:gsub("[^%w%p%s]", "?")))
            else
                print(string.format("  %s = '%s' (#%d bytes)", name, val:gsub("[^%w%p%s]", "?"), #val))
            end
        else
            print(string.format("  %s = (empty)", name))
        end
    elseif ok then
        print(string.format("  %s = (result=%s)", name, tostring(err)))
    else
        print(string.format("  %s = ERROR: %s", name, tostring(err)))
    end
end

print("\nDone!")
return "ok"
