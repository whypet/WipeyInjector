#include <iostream>
#include <Windows.h>
#include <winternl.h>

#define PCVOID const void *
#define INLINE inline

typedef CLIENT_ID* PCLIENT_ID;

typedef NTSTATUS(NTAPI* RtlAdjustPrivilegeDef) (IN ULONG Privilege, IN BOOLEAN Enable, IN BOOLEAN CurrentThread, OUT PBOOLEAN Enabled);
typedef NTSTATUS(NTAPI* RtlCreateUserThreadDef) (
	HANDLE,
	PSECURITY_DESCRIPTOR,
	BOOLEAN, ULONG,
	PULONG, PULONG,
	PVOID, PVOID,
	PHANDLE, PCLIENT_ID
);

DWORD ProcessInjectDll(DWORD dwProcId, const WCHAR szDllPath[]) {
	HMODULE hModuleNtDll = GetModuleHandleW(L"ntdll.dll");

	BOOLEAN bEnabled;
	RtlAdjustPrivilegeDef RtlAdjustPrivilege = (RtlAdjustPrivilegeDef)GetProcAddress(hModuleNtDll, "RtlAdjustPrivilege");
	RtlAdjustPrivilege(0x00000014, TRUE, FALSE, &bEnabled);

	if (!NT_SUCCESS(RtlAdjustPrivilege(0x00000014, TRUE, FALSE, &bEnabled))) {
		std::cout << "Failed to adjust debug privilege; NT_SUCCESS() returned FALSE, bEnabled = " << (bEnabled == 0 ? "FALSE" : "TRUE") <<
			", GetLastError() returned " << std::dec << GetLastError() << ".\n";
		return -1;
	} else if (!bEnabled) {
		std::cout << "Failed to adjust debug privilege; bEnabled = " << (bEnabled == 0 ? "FALSE" : "TRUE") <<
			", GetLastError() returned " << std::dec << GetLastError() << ".\n";
		return -1;
	} else {
		std::cout << "Successfully adjusted debug privilege (0x00000014), bEnabled = " << (bEnabled == 0 ? "FALSE" : "TRUE") << "\n";
	}

	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcId);
	BOOL bIsWow64;
	IsWow64Process(hProc, &bIsWow64);
	std::cout << "GetLastError() returned " << std::dec << GetLastError() <<
		"; OpenProcess() returned handle 0x" << std::hex << hProc <<
		"\nProcess ID " << std::dec << dwProcId << ", architecture " << (bIsWow64 == 0 ? "x86" : "x64") << "\n";

	SIZE_T dwPathLen = (wcslen(szDllPath) + 1) * sizeof(WCHAR);
	PVOID pDllAlloc = VirtualAllocEx(hProc, nullptr, dwPathLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	std::cout << "GetLastError() returned " << std::dec << GetLastError() <<
		"; VirtualAllocEx() returned pointer 0x" << std::hex << pDllAlloc << "\n";

	SIZE_T dwBytesWritten;
	BOOL bWritten = WriteProcessMemory(hProc, pDllAlloc, szDllPath, dwPathLen, &dwBytesWritten);
	std::cout << "GetLastError() returned " << std::dec << GetLastError() <<
		"; WriteProcessMemory() returned " << (bEnabled == 0 ? "FALSE" : "TRUE") << " with " << std::dec << dwBytesWritten << " bytes written\n";

	RtlCreateUserThreadDef RtlCreateUserThread = (RtlCreateUserThreadDef)GetProcAddress(hModuleNtDll, "RtlCreateUserThread");
	std::cout << "GetLastError() returned " << std::dec << GetLastError() <<
		"; GetProcAddress() returned pointer 0x" << std::hex << RtlCreateUserThread << "\n";
	FreeLibrary(hModuleNtDll);

	if (!RtlCreateUserThread) {
		std::cout << "Failed to import RtlCreateUserThread entry point; RtlCreateUserThread = 0, GetLastError() returned " << std::dec << GetLastError() << ".\n";
		return -1;
	}
	
	HANDLE hThread;
	HMODULE hModuleKernel32 = GetModuleHandleW(L"Kernel32.dll");
	hThread = CreateRemoteThread(hProc, nullptr, 0, (PTHREAD_START_ROUTINE)GetProcAddress(hModuleKernel32, "LoadLibraryW"), pDllAlloc, 0, nullptr);
	
	if (!hThread || GetThreadId(hThread) == 0) {
		std::cout << "Failed to create thread using CreateRemoteThread(); hThread = 0x" << std::hex << hThread << ", GetLastError() returned " << std::dec << GetLastError() << ".\nTrying RtlCreateUserThread method...\n";
		RtlCreateUserThread(hProc, nullptr, FALSE, 0, nullptr, nullptr, (PVOID)GetProcAddress(hModuleKernel32, "LoadLibraryW"), pDllAlloc, &hThread, nullptr);
		
		if (!hThread || GetThreadId(hThread) == 0) {
			std::cout << "Failed to create thread using RtlCreateUserThread(); hThread = 0x" << std::hex << hThread << ", GetLastError() returned " << std::dec << GetLastError() << ".\n";
			return -1;
		} else
			std::cout << "RtlCreateUserThread() returned thread handle 0x" << std::hex << hThread << " with thread ID " << std::dec << GetThreadId(hThread) << "\n";
	} else
		std::cout << "CreateRemoteThread() returned thread handle 0x" << std::hex << hThread << " with thread ID " << std::dec << GetThreadId(hThread) << "\n";

	FreeLibrary(hModuleKernel32);
	WaitForSingleObject(hThread, INFINITE);
	DWORD dwExitCode;
	GetExitCodeThread(hThread, &dwExitCode);

	std::cout << "GetLastError() returned " << std::dec << GetLastError() <<
		"; Thread returned exit code " << std::dec << dwExitCode << "\n";

	VirtualFreeEx(hProc, pDllAlloc, dwPathLen, MEM_RELEASE);
	return dwExitCode;
}

INT32 main() {
	const DWORD dwProcId = 8740;
	const WCHAR szDllPath[] = L"D:\\Visual Studio Projects\\DllTest\\x64\\Release\\DllTest.dll";
	ProcessInjectDll(dwProcId, szDllPath);
	std::cin.get();

	return 0;
}
