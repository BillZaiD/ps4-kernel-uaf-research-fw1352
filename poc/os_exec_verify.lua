-- Verify if os.execute actually executes commands
print("=== os.execute Verification ===\n")

-- Test 1: command that should fail
local r1 = os.execute("exit 42")
print(string.format("  exit 42: %d (should be 42 if real, 0 if stub)", r1))

local r2 = os.execute("exit 0")
print(string.format("  exit 0: %d (should be 0)", r2))

local r3 = os.execute("nonexistent_command_xyz")
print(string.format("  bad cmd: %d (should be non-zero if real)", r3))

-- Test 2: side effect via memory mapped file
-- Can we use dd to write to /dev/null?
local r4 = os.execute("dd if=/dev/zero of=/dev/null bs=1024 count=1 2>/dev/null")
print(string.format("  dd test: %d", r4))

-- Test 3: Can we start a TCP connection via shell?
-- curl to localhost:9026
local r5 = os.execute("echo '' | nc 127.0.0.1 9026 2>/dev/null &")
print(string.format("  nc test: %d", r5))

-- Test 4: Can we read /proc/self/status?
local r6 = os.execute("cat /proc/self/status 2>/dev/null > /tmp/proc_test 2>/dev/null")
print(string.format("  proc test: %d", r6))

-- Test 5: Check if /data or /tmp is writable
local r7 = os.execute("touch /tmp/test_write 2>/dev/null")
print(string.format("  touch /tmp: %d", r7))

local r8 = os.execute("touch /data/data/test_write 2>/dev/null")
print(string.format("  touch /data: %d", r8))

-- Test 6: List directories  
print("\n--- ls checks (output not captured, only exit code) ---")
print(string.format("  ls /: %d", os.execute("ls / > /dev/null 2>/dev/null")))
print(string.format("  ls /savedata0/: %d", os.execute("ls /savedata0/ > /dev/null 2>/dev/null")))
print(string.format("  ls /proc/: %d", os.execute("ls /proc/ > /dev/null 2>/dev/null")))

-- Test 7: Check if internet access works
print(string.format("  ping localhost: %d", os.execute("ping -c 1 127.0.0.1 > /dev/null 2>&1")))
print(string.format("  ping google: %d", os.execute("ping -c 1 8.8.8.8 > /dev/null 2>&1")))

print("\nDone.")
