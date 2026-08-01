print("hello from PS4")
print("libkernel_base=" .. tostring(libkernel_base))
print("test=1")
local wt = syscall.syscall_wrapper
print("wt type=" .. type(wt))
print("wt[585]=" .. tostring(wt[585]))
print("done!!")
