-- Test raw gadget and wrapper at +0x2ba0
print("=== Raw gadget debugging ===\n")

local base = libkernel_base

-- Wrapper at +0x2ba0 (syscall 454)
local wrapper454 = base + 0x2ba0
-- Raw gadget at +0x2ba7
local raw_gadget = base + 0x2ba7

print(string.format("libkernel_base: 0x%x", base.h * 4294967296 + base.l))

-- Read bytes
local bw = memory.read_buffer(wrapper454, 16)
local br = memory.read_buffer(raw_gadget, 8)
local function hex(b)
    local h = ""
    for i = 1, #b do h = h .. string.format("%02x", string.byte(b, i)) end
    return h
end
print(string.format("wrapper @ +0x2ba0: %s", hex(bw)))
print(string.format("raw @ +0x2ba7:    %s", hex(br)))

-- Check if syscall_wrapper[454] exists
print(string.format("\nsyscall_wrapper[454] = %s", tostring(syscall.syscall_wrapper[454] or "nil")))

-- Test 1: native.fcall with wrapper at +0x2ba0 (syscall 454)
print("\nTest 1: native.fcall(wrapper454, 0, 0, 0, 0, 0, 0)...")
print("  (this calls syscall 454 with all zero args)")
local ok1, r1 = pcall(function()
    return native.fcall(wrapper454, 0, 0, 0, 0, 0, 0)
end)
if ok1 then
    local v = (type(r1) == "table") and (r1.h * 4294967296 + r1.l) or (r1 or -1)
    print(string.format("  Result: 0x%x (%d)", v, v))
else
    print("  ERROR (expected): " .. tostring(r1))
end

-- Test 2: native.fcall with raw gadget at +0x2ba7 (mov r10, rcx; syscall; ret)
-- This will execute syscall with whatever RAX happens to be
print("\nTest 2: native.fcall(raw_gadget, 0, 0, 0, 0, 0, 0)...")
print("  (this skips mov rax, so uses RAX from whatever was set)")
local ok2, r2 = pcall(function()
    return native.fcall(raw_gadget, 0, 0, 0, 0, 0, 0)
end)
if ok2 then
    local v = (type(r2) == "table") and (r2.h * 4294967296 + r2.l) or (r2 or -1)
    print(string.format("  Result: 0x%x (%d)", v, v))
else
    print("  ERROR: " .. tostring(r2))
end

-- Test 3: Compare with fcall_with_rax (explicit rax=454) using the wrapper
print("\nTest 3: fcall_with_rax(wrapper454, 454, 0, 0, 0, 0, 0, 0)...")
local ok3, r3 = pcall(function()
    return native.fcall_with_rax(wrapper454, 454, 0, 0, 0, 0, 0, 0)
end)
if ok3 then
    local v = (type(r3) == "table") and (r3.h * 4294967296 + r3.l) or (r3 or -1)
    print(string.format("  Result: 0x%x (%d)", v, v))
else
    print("  ERROR: " .. tostring(r3))
end

print("\nDone!")
return "ok"
