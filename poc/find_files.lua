-- Comprehensive search for kernel/module files
print("=== Deep Filesystem Search ===\n")

-- First explore directory structure
local function list_dir(path)
    -- Try open + getdents approach (syscall 78 = getdirentries)
    -- Or just try known files
    
    -- Try file_exists on various patterns
    local results = {}
    for _, p in ipairs(path) do
        if file_exists(p) then
            table.insert(results, p)
        end
    end
    return results
end

-- Search through module directory structure
local base_dirs = {
    "/system/common/",
    "/system/",
    "/system/common/lib/",
    "/system/common/module/",
    "/system/common/plugins/",
    "/system_ex/",
    "/system_ex/common/",
}

-- Use command approach: list directories via writing files
-- Actually we can't do that since os.execute is a stub
-- Let's try to read known files

local function try_path(name, paths)
    print(string.format("--- %s ---", name))
    for _, p in ipairs(paths) do
        local exists = file_exists(p)
        if exists then
            print(string.format("  FOUND: %s", p))
            -- Try to read first 16 bytes
            local ok, f = pcall(io.open, p, "r")
            if ok and f then
                local h = f:read(16)
                f:close()
                if h then
                    local hex = ""
                    for i = 1, #h do hex = hex .. string.format("%02x", string.byte(h, i)) end
                    print(string.format("    magic: %s", hex))
                    if h:sub(1,4) == "\x7fELF" then
                        print(string.format("    -> ELF binary!"))
                    end
                end
            end
        end
    end
    print("")
end

-- Search for kernel
try_path("kernel", {
    "/system/common/module/kernel.elf",
    "/system/common/module/kernel.sprx",
    "/system/common/module/kernel",
    "/system/kernel.elf",
    "/system/kernel.sprx",
    "/boot/kernel.elf",
    "/boot/kernel",
    "/boot/kernel.sprx",
    "/kernel.elf",
    "/system/common/lib/kernel.elf",
})

-- Search for libkernel
try_path("libkernel", {
    "/system/common/lib/libkernel.sprx",
    "/system/common/lib/libkernel.elf",
    "/system/common/lib/libkernel.so",
    "/system/common/lib/libkernel.sel",
    "/system/lib/libkernel.sprx",
    "/lib/libkernel.sprx",
    "/system/common/module/libkernel.sprx",
})

-- Search for SceSysmodule
try_path("SceSysmodule", {
    "/system/common/lib/libSceSysmodule.sprx",
    "/system/common/lib/libSceSysmodule.elf",
    "/system/common/module/libSceSysmodule.sprx",
})

-- Search for key system files  
try_path("system libs", {
    "/system/common/lib/libSceLibcInternal.sprx",
    "/system/common/lib/libSceLibkernelInternal.sprx",
    "/system/common/lib/libSceShellCoreUtil.sprx",
    "/system/common/lib/libSceSysCore.sprx",
    "/system/common/lib/libc.sprx",
    "/system/common/lib/libSceIme.sprx",
    "/system/common/lib/libSceGnmDriver.sprx",
})

-- Search for files with 'elf' or 'sprx' extension
local sprx_paths = {}
for _, base in ipairs({"/system/common/lib/", "/system/common/module/"}) do
    -- We can't enumerate directories, so check known names
    local names = {
        "libkernel", "libSceLibcInternal", "libSceSysmodule",
        "libSceLibkernelInternal", "libSceShellCoreUtil", "libSceSysCore",
        "libSceGnmDriver", "libSceIme", "libc", "libSceFiber",
        "libSceUlt", "libSceJson", "libSceNpCommerce2",
    }
    for _, n in ipairs(names) do
        for _, ext in ipairs({".sprx", ".elf", ".so"}) do
            local p = base .. n .. ext
            if file_exists(p) then
                print(string.format("  FOUND: %s", p))
            end
        end
    end
end

-- Also check game dir for config files
print("\n--- Game directory ---")
local game_files = {
    "/app0/eboot.bin",
    "/app0/param.sfo",
    "/app0/playgo-chunk-list.xml",
    "/app0/playgo-manifest.xml",
}
for _, p in ipairs(game_files) do
    if file_exists(p) then
        print(string.format("  FOUND: %s", p))
    end
end

print("\nDone!")
