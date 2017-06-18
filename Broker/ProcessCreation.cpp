#include "stdafx.h"
#include "ProcessCreation.h"
#include <windows.h>
#include <stdio.h>



int InjectDll(HANDLE hProcess)
{
	HANDLE hThread;
	char   szLibPath[_MAX_PATH];
	void*  pLibRemote = 0;	// the address (in the remote process) where
							// szLibPath will be copied to;
	DWORD  hLibModule = 0;	// base adress of loaded module (==HMODULE);

	HMODULE hKernel32 = ::GetModuleHandle(TEXT("Kernel32"));


	// Get full path of "LibSpy.dll"
	//if (!GetModuleFileName(hInst, szLibPath, _MAX_PATH))
	//	return false;
	//strcpy(strstr(szLibPath, ".exe"), ".dll");


	// 1. Allocate memory in the remote process for szLibPath
	// 2. Write szLibPath to the allocated memory
	pLibRemote = ::VirtualAllocEx(hProcess, NULL, sizeof(szLibPath), MEM_COMMIT, PAGE_READWRITE);
	if (pLibRemote == NULL)
		return false;
	::WriteProcessMemory(hProcess, pLibRemote, (void*)szLibPath, sizeof(szLibPath), NULL);


	// Load "LibSpy.dll" into the remote process 
	// (via CreateRemoteThread & LoadLibrary)
	hThread = ::CreateRemoteThread(hProcess, NULL, 0,
		(LPTHREAD_START_ROUTINE) ::GetProcAddress(hKernel32, "LoadLibraryA"),
		pLibRemote, 0, NULL);
	if (hThread == NULL)
		goto JUMP;

	::WaitForSingleObject(hThread, INFINITE);

	// Get handle of loaded module
	::GetExitCodeThread(hThread, &hLibModule);
	::CloseHandle(hThread);

JUMP:
	::VirtualFreeEx(hProcess, pLibRemote, sizeof(szLibPath), MEM_RELEASE);
	if (hLibModule == NULL)
		return false;


	// Unload "LibSpy.dll" from the remote process 
	// (via CreateRemoteThread & FreeLibrary)
	hThread = ::CreateRemoteThread(hProcess,
		NULL, 0,
		(LPTHREAD_START_ROUTINE) ::GetProcAddress(hKernel32, "FreeLibrary"),
		(void*)hLibModule,
		0, NULL);
	if (hThread == NULL)	// failed to unload
		return false;

	::WaitForSingleObject(hThread, INFINITE);
	::GetExitCodeThread(hThread, &hLibModule);
	::CloseHandle(hThread);

	// return value of remote FreeLibrary (=nonzero on success)
	return hLibModule;
}

