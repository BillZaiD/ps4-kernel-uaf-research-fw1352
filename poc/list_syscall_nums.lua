-- enumerate all syscall numbers
for name, tbl in pairs(syscall) do
    if type(tbl) == "table" and tbl.syscall_no then
        print(name .. " = " .. tbl.syscall_no)
    end
end
