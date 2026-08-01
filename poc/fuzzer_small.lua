-- minimal fuzzer: test each syscall one at a time, report results
for num = 585, 600 do
    local w = syscall.syscall_wrapper[num]
    if w then
        local ok, ret = pcall(native.fcall, w, 0, 0, 0, 0, 0, 0)
        if ok then
            local rh, rl = 0, 0
            if type(ret) == "table" then
                rh, rl = ret.h or 0, ret.l or 0
            else
                rl = tonumber(ret) or 0
            end
            print("SC" .. num .. "=0x" .. string.format("%x%08x", rh, rl))
        else
            print("SC" .. num .. "=ERR")
        end
    end
end
print("OK")
