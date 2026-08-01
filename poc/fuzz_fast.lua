-- fuzz Sony custom syscalls (585-677)
local function test()
    local wrapper_table = syscall.syscall_wrapper
    if not wrapper_table then print("no wrapper table") return end
    
    -- test specific syscalls with controlled args
    local test_syscalls = {20, 24, 585, 586, 587, 588, 591, 594, 595}
    
    for _, num in ipairs(test_syscalls) do
        local wrapper = wrapper_table[num]
        if not wrapper then
            print("syscall " .. num .. ": no wrapper")
        else
            -- try with zero args
            local ok, ret = pcall(native.fcall, wrapper, 0, 0, 0, 0, 0, 0)
            if ok then
                local rh, rl = 0, 0
                if type(ret) == "table" then rh, rl = ret.h or 0, ret.l or 0
                elseif type(ret) == "number" then rl = ret end
                print("syscall " .. num .. ": OK ret=0x" .. string.format("%x%08x", rh, rl))
            else
                print("syscall " .. num .. ": ERR " .. tostring(ret))
            end
        end
    end
    
    -- also test special Sony custom syscalls
    print("\n--- Extended fuzz ---")
    local extended = {[592]=1, [593]=1, [596]=1, [598]=1, [600]=1, [602]=1}
    for num, _ in pairs(extended) do
        local wrapper = wrapper_table[num]
        if wrapper then
            local ok, ret = pcall(native.fcall, wrapper, 0, 0, 0, 0, 0, 0)
            print("syscall " .. num .. ": " .. (ok and "OK" or "ERR"))
        end
    end
    
    -- verify game still alive
    print("\nalive: " .. tostring(pcall(native.fcall, wrapper_table[20], 0, 0, 0, 0, 0, 0)))
end

test()
