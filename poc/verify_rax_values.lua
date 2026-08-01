-- Verify retval_addr[2] values and compare
print("=== Verify rax values ===\n")

-- Test native.fcall_with_rax path manually
-- The value stored in retval_addr[2] should be the rax parameter

-- Let's compare what happens with different rax values
-- by calling fcall_with_rax and checking results

-- First, call through wrapper (known working) with different rax
local w585 = syscall.syscall_wrapper[585]

-- native.fcall: rax=nil → 0 → wrapper sets to 585
local r1 = native.fcall(w585, 0, 0, 0, 0, 0, 0)
local v1 = (type(r1) == "table") and (r1.h * 4294967296 + r1.l) or (r1 or -1)
print(string.format("native.fcall(w585, ...): %d (rax=nil, wrapper→585)", v1))

-- fcall_with_rax with explicit 585
local r2 = native.fcall_with_rax(w585, 585, 0, 0, 0, 0, 0, 0)
local v2 = (type(r2) == "table") and (r2.h * 4294967296 + r2.l) or (r2 or -1)
print(string.format("fcall_with_rax(w585, 585, ...): %d (rax=585, wrapper→585)", v2))

-- Now try with a WRAPPER for syscall 20 but use rax=585 through trampoline
-- THIS is the key test: does setting rax=585 ACTUALLY work?
local tramp = syscall.syscall_wrapper[20] + 7

-- First confirm trampoline with rax=20 works
local r3 = native.fcall_with_rax(tramp, 20, 0, 0, 0, 0, 0, 0)
local v3 = (type(r3) == "table") and (r3.h * 4294967296 + r3.l) or (r3 or -1)
print(string.format("fcall_with_rax(tramp, 20, ...): 0x%x (%d) (rax=20, trampoline→20)", v3, v3))

-- Now check by calling syscall 596 via trampoline with rax=596
-- SC596(0) should return 0 (we saw this earlier)
local r4 = native.fcall_with_rax(tramp, 596, 0, 0, 0, 0, 0, 0)
local v4 = (type(r4) == "table") and (r4.h * 4294967296 + r4.l) or (r4 or -1)
print(string.format("fcall_with_rax(tramp, 596, ...): 0x%x (%d) (rax=596, trampoline→596)", v4, v4))

-- Same with SC598
local r5 = native.fcall_with_rax(tramp, 598, 0, 0, 0, 0, 0, 0)
local v5 = (type(r5) == "table") and (r5.h * 4294967296 + r5.l) or (r5 or -1)
print(string.format("fcall_with_rax(tramp, 598, ...): 0x%x (%d) (rax=598, trampoline→598)", v5, v5))

-- Now try SC602 - this one is also boolean (0 for arg=0)
local r6 = native.fcall_with_rax(tramp, 602, 0, 0, 0, 0, 0, 0)
local v6 = (type(r6) == "table") and (r6.h * 4294967296 + r6.l) or (r6 or -1)
print(string.format("fcall_with_rax(tramp, 602, ...): 0x%x (%d) (rax=602, trampoline→602)", v6, v6))

-- Final try: SC585 again but with DIFFERENT wrapper's trampoline
-- Use wrapper[596] + 7 instead of wrapper[20] + 7
local tramp2 = syscall.syscall_wrapper[596] + 7
local b = memory.read_buffer(tramp2, 6)
local hex = ""
for i = 1, #b do hex = hex .. string.format("%02x", string.byte(b, i)) end
print(string.format("\nTrampoline2 (w596+7): %s", hex))

print("\nAll trampoline tests done!")
return "ok"
