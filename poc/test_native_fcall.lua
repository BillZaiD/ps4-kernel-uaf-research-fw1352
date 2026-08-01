-- test native.fcall to call is_in_sandbox
local function test()
    -- First, let's understand how native.fcall works
    -- The syscall wrapper for syscall 585 is at:
    local wrapper585 = syscall.syscall_wrapper[585]
    print("wrapper585 type: " .. type(wrapper585))
    print("wrapper585: h=" .. tostring(wrapper585.h) .. " l=" .. tostring(wrapper585.l))

    -- Get the actual address from the uint64
    -- The uint64 stores the pointer as {h=hi32, l=lo32}
    local addr_hi = wrapper585.h
    local addr_lo = wrapper585.l
    local addr_str = string.format("0x%x%08x", addr_hi, addr_lo)
    print("syscall585 addr: " .. addr_str)

    -- Now try using native.fcall to call it
    -- native.fcall should take fn_addr, arg1, arg2, ...
    local ok, ret = pcall(native.fcall, wrapper585, 0, 0, 0, 0, 0)
    print("native.fcall result: " .. tostring(ok) .. " " .. tostring(ret))

    -- Also try setting the fn_addr in fcall.arg_addr
    if fcall.arg_addr then
        fcall.arg_addr.fn_addr = wrapper585
        fcall.arg_addr.rdi = 0 -- no rdi argument needed
        print("fcall.arg_addr set")
    end
end

test()
