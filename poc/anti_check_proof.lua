-- Prove the anti-exploitation theory
print("=== Anti-check theory verification ===\n")

-- Theory: Sony kernel checks if RAX matches the mov rax, N 
-- that precedes the syscall instruction (at RCX - 9)

-- Test: Call rax=20 through WRAPPER[585]'s trampoline
-- This should FAIL because wrapper585 has mov rax, 585, not 20
local w585_tramp = syscall.syscall_wrapper[585] + 7
local b = memory.read_buffer(w585_tramp, 6)
local hex = ""
for i = 1, #b do hex = hex .. string.format("%02x", string.byte(b, i)) end
print(string.format("w585 trampoline @ +7: %s", hex))

print("\nTest: fcall_with_rax(w585_tramp, 20, 0, 0, 0, 0, 0, 0)...")
print("  (rax=20 but wrapper585 has mov rax, 585)")
print("  If this hangs → anti-check CONFIRMED")
local r = native.fcall_with_rax(w585_tramp, 20, 0, 0, 0, 0, 0, 0)
local v = (type(r) == "table") and (r.h * 4294967296 + r.l) or (r or -1)
print(string.format("  Result: 0x%x (%d)", v, v))
print("  If we get here → anti-check DISPROVED")

print("\nDone!")
return "ok"
