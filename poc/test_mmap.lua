-- test mmap and mprotect via native.fcall
local function test()
    local nf = native.fcall
    local function call_syscall(syscall_num, arg1, arg2, arg3, arg4, arg5, arg6)
        local wrapper = syscall.syscall_wrapper[syscall_num]
        if not wrapper then return nil, "no wrapper" end
        -- the wrapper is a uint64 that holds the address of mov eax, N; syscall; ret
        -- but we need a full function call, not just the stub
        -- use native.fcall to call the stub
        local ok, ret = pcall(nf, wrapper, arg1, arg2, arg3, arg4, arg5, arg6)
        if not ok then return nil, ret end
        return ret, nil
    end

    -- syscall 477 = mmap (FreeBSD syscall)
    -- void *mmap(void *addr, size_t len, int prot, int flags, int fd, off_t offset)
    -- prot = 7 = PROT_READ|PROT_WRITE|PROT_EXEC
    -- flags = 0x1002 = MAP_PRIVATE|MAP_ANONYMOUS
    print("=== Testing mmap ===")
    local addr, err = call_syscall(477, 0, 0x4000, 7, 0x1002, -1, 0)
    if addr then
        print("mmap returned: " .. tostring(addr))
    else
        print("mmap failed: " .. tostring(err))
    end

    -- Also try via the syscall.mmap table
    print("\n=== Testing syscall.mmap ===")
    local fn_addr = syscall.mmap.fn_addr
    if fn_addr then
        local ok, ret = pcall(nf, fn_addr, 0, 0x4000, 7, 0x1002, -1, 0)
        print("fn_addr call: " .. tostring(ok) .. " " .. tostring(ret))
    end

    -- test getpid first (syscall 20)
    print("\n=== Testing getpid (syscall 20) ===")
    local pid, err2 = call_syscall(20)
    if pid then
        print("PID: " .. tostring(pid))
    else
        print("getpid failed: " .. tostring(err2))
    end

    -- test getuid (syscall 24)
    print("\n=== Testing getuid (syscall 24) ===")
    local uid, err3 = call_syscall(24)
    if uid then
        print("UID: " .. tostring(uid))
    else
        print("getuid failed: " .. tostring(err3))
    end
end

test()
