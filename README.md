# WipeyInjector

wipet's fun dll injector

creds to nullexception

uses CreateRemoteThread() & RtlCreateUserThread() undocumented api function

tested on command prompt, notepad and minecraft (java) using windows 7 sp1

anyone can use this code without my permission in a program

# how it works

it adjusts the debug privilege token, then creates a handle to the process using a process ID,

which is later used to allocate memory for the dll path into the process and to create a

thread for the dll using CreateRemoteThread(). if it fails, it tries to use RtlCreateUserThread()

instead at the end of the function. it returns the dll thread's exit code.

# troubleshooting

make sure the dll, injector & target program all have the same architecture (32-bit or 64-bit),

otherwise the injector won't work: both CreateRemoteThread() and RtlCreateUserThread() will

return error code 5 (access denied). also check if the target program's PID is valid

if you get invalid handles.
