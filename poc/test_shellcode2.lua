-- test shellcode with proper uint64 handling
local function test()
    -- mmap RWX memory
    local wrapper477 = syscall.syscall_wrapper[477]
    local ok, mmap_addr = pcall(native.fcall, wrapper477, 0, 0x4000, 7, 0x1002, -1, 0)
    if not ok then print("mmap failed: " .. tostring(mmap_addr)) return end
    print("mmap type: " .. type(mmap_addr))

    -- convert uint64 to printable address
    if type(mmap_addr) == "table" then
        print("mmap addr: 0x" .. string.format("%x", mmap_addr.h) .. string.format("%08x", mmap_addr.l))
    end

    -- x86-64 shellcode: getpid (syscall 20)
    local shellcode = string.char(
        0x48, 0xc7, 0xc0, 0x14, 0x00, 0x00, 0x00,
        0x0f, 0x05,
        0xc3
    )

    -- try native.write_buffer
    if type(native.write_buffer) == "function" then
        local ok2 = pcall(native.write_buffer, mmap_addr, shellcode)
        print("native.write_buffer: " .. tostring(ok2))
    end

    -- try calling the shellcode
    local ok3, ret = pcall(native.fcall, mmap_addr, 0, 0, 0, 0, 0)
    print("shellcode result: " .. tostring(ok3) .. " " .. tostring(ret))
end

test()
