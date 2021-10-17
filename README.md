# WipeyInjector

Thanks to @NullExceptionTSB for helping me with this!\
This uses CreateRemoteThread() and the undocumented API function RtlCreateUserThread().\
Tested on Command Prompt, Notepad and Java runtime using Windows 7 SP1

# Details

This injector adjusts the debug privilege token, then creates a handle to the process using a process ID.\
That handle is later used to write memory containing the DLL path into the process, and to create a thread for it using CreateRemoteThread().\
If it fails, it tries to use RtlCreateUserThread() instead.

# Troubleshooting

Make sure the DLL, injector & target program all have the same architecture (x86 or x64), otherwise the injector won't work.\
Both CreateRemoteThread() and RtlCreateUserThread() will return error code 5, access denied.\
You should also check if the target program's PID is valid if OpenProcess() returns an invalid handle.
