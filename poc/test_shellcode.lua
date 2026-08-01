-- write simple shellcode and execute it
local function test()
    -- x86-64 shellcode: call getpid (syscall 20) and return
    -- mov rax, 20
    -- syscall
    -- ret
    local shellcode = string.char(
        0x48, 0xc7, 0xc0, 0x14, 0x00, 0x00, 0x00,  -- mov rax, 20
        0x0f, 0x05,                                    -- syscall
        0xc3                                            -- ret
    )

    -- mmap RWX memory
    local wrapper477 = syscall.syscall_wrapper[477]
    local ok, mmap_addr = pcall(native.fcall, wrapper477, 0, 0x4000, 7, 0x1002, -1, 0)
    if not ok then print("mmap failed: " .. tostring(mmap_addr)) return end
    print("mmap: 0x" .. string.format("%x", mmap_addr))

    -- write shellcode using lua's write_buffer
    local wb = native.write_buffer 
    ok = pcall(wb, mmap_addr, shellcode)
    print("write_buffer result: " .. tostring(ok))

    -- call the shellcode
    local wrapper = {h = bit64.lshr(mmap_addr, 32), l = bit64.band(mmap_addr, 0xffffffff)}
    local ok2, ret = pcall(native.fcall, wrapper, 0, 0, 0, 0, 0)
    print("shellcode returned: " .. tostring(ret))
end

test()
