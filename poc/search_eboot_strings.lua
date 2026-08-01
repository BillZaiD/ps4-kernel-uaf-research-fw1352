-- Search for interesting strings in eboot binary
local luaB = uint64(eboot_addrofs.luaB_auxwrap):tonumber()
local eboot_base = luaB - 0x1a7420

print("EBOOT base: 0x" .. string.format("%x", eboot_base))

-- Read first 256KB of binary (at minimum to find key sections)
local size = 0x40000
print("Reading " .. tostring(size) .. " bytes of eboot...")
local ok, buf = pcall(memory.read_buffer, eboot_base, size)
if not ok or not buf then
  print("Failed to read: " .. tostring(buf))
  return
end
print("Got " .. tostring(#buf) .. " bytes")

-- Search for keywords in the buffer
local keywords = {
  "syscall", "ioctl", "debug", "/dev/", "kernel", "exploit",
  "dma", "prx", "rpc", "socket", "server", "port", "shell",
  "backdoor", "test", "cmd", "module", "service", "klog",
  "kprintf", "kthread", "sysctl", "alloc", "free", "mprotect",
  "mmap", "sdk", "cpumode", "rcmgr", "fsc2h", "goldhen",
  "hen", "payload", "libc", "savedata", "/app0", "sandbox",
  "tty", "console", "panic", "assert", "dump", "crash"
}

print("\n=== Interesting strings found ===")
for _, kw in ipairs(keywords) do
  local start = 1
  local count = 0
  while true do
    local pos = buf:find(kw, start, true)  -- plain match
    if not pos then break end
    count = count + 1
    if count <= 5 then  -- show first 5 matches
      -- Get context around the match
      local ctx_start = math.max(1, pos - 4)
      local ctx_end = math.min(#buf, pos + #kw + 16)
      local ctx = buf:sub(ctx_start, ctx_end)
      print(string.format("  [%s] at offset 0x%x: %s", kw, pos - 1, ctx:gsub("[^%w%p%s]", ".")))
    end
    start = pos + 1
  end
  if count > 0 then
    print(string.format("  [%s] total: %d occurrences", kw, count))
  end
end

-- Try to identify the game engine
print("\n=== Game engine detection ===")
local engine_keywords = {
  "Unity", "Unreal", "CriWare", "CriAtom", "Mono", "IL2CPP",
  "GameEngine", "PhyreEngine", "Orochi3", "YEBIS",
  "libc", "libSce", "SceLib", "libkernel", "SceSyslib"
}
for _, kw in ipairs(engine_keywords) do
  local pos = buf:find(kw, 1, true)
  while pos do
    local ctx = buf:sub(math.max(1, pos-2), pos + #kw + 10)
    print(string.format("  [%s] at 0x%x: %s", kw, pos-1, ctx:gsub("[^%w%p%s]", ".")))
    pos = buf:find(kw, pos + 1, true)
  end
end

print("[+] Done")
