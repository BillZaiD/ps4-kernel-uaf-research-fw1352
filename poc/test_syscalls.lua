-- test is_in_sandbox and mmap
local function test()
    local ok, ret
    local m = memory

    -- test is_in_sandbox
    print("=== is_in_sandbox ===")
    if syscall.is_in_sandbox and type(syscall.is_in_sandbox) == "table" and syscall.is_in_sandbox.fn_addr then
        local fn = syscall.is_in_sandbox.fn_addr
        local num = syscall.is_in_sandbox.syscall_no
        print("fn_addr=" .. tostring(fn) .. " syscall_no=" .. tostring(num))
        -- try calling the wrapper
        local wrapper = syscall.syscall_wrapper[num]
        if wrapper then
            ok, ret = pcall(wrapper.call or wrapper, fn.call)
            print("pcall result: ok=" .. tostring(ok) .. " ret=" .. tostring(ret))
        end
    end

    -- test mmap
    print("\n=== mmap ===")
    if type(syscall.mmap.call) == "function" then
        ok, ret = pcall(syscall.mmap.call, 0, 0x4000, 7, 0x1002, -1, 0)
        print("mmap: " .. tostring(ok) .. " " .. tostring(ret))
    end

    -- try calling via syscall_wrapper directly
    print("\n=== syscall_wrapper[585] ===")
    local w585 = syscall.syscall_wrapper[585]
    if w585 then
        for k, v in pairs(w585) do
            print("  " .. tostring(k) .. " = " .. tostring(v))
        end
        if type(w585.call) == "function" then
            ok, ret = pcall(w585.call)
            print("raw call: " .. tostring(ok) .. " " .. tostring(ret))
        end
    end
end

test()
