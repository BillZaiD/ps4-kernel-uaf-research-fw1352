-- test syscall helper functions
local function test()
    if type(syscall.do_sanity_check) == "function" then
        local ok, ret = pcall(syscall.do_sanity_check)
        print("sanity_check: " .. tostring(ok) .. " " .. tostring(ret))
    end
    
    if type(syscall.collect_info) == "function" then
        local ok, ret = pcall(syscall.collect_info)
        print("collect_info: " .. tostring(ok) .. " " .. tostring(ret))
    end
    
    -- check if check_jailbroken works
    if type(check_jailbroken) == "function" then
        local ok, ret = pcall(check_jailbroken)
        print("check_jailbroken: " .. tostring(ok) .. " " .. tostring(ret))
    end
    
    -- check if is_jailbroken works
    if type(is_jailbroken) == "function" then
        local ok, ret = pcall(is_jailbroken)
        print("is_jailbroken: " .. tostring(ok) .. " " .. tostring(ret))
    end
    
    -- check is_kernel_rw_available
    if type(is_kernel_rw_available) == "function" then
        local ok, ret = pcall(is_kernel_rw_available)
        print("is_kernel_rw_available: " .. tostring(ok) .. " " .. tostring(ret))
    end
end

test()
