#include "stdafx.h"
#include "ProcessCreation.h"
#include "Utils.h"
#include "TokenUtils.h"




HANDLE CreateRestrictedJobObject() {
	
	/// Local variables, initilization is near use.
	SECURITY_ATTRIBUTES security_attributes;
	JOBOBJECT_BASIC_UI_RESTRICTIONS uiRestriction;
	JOBOBJECT_BASIC_LIMIT_INFORMATION basicLimits;
	JOBOBJECT_EXTENDED_LIMIT_INFORMATION extLimit;

	/// Create the job Object
	ZeroMemory(&security_attributes, sizeof(SECURITY_ATTRIBUTES));
	security_attributes.nLength = sizeof(SECURITY_ATTRIBUTES);
	security_attributes.bInheritHandle = FALSE;
	HANDLE job = CreateJobObject(&security_attributes, NULL);
	if (!job) {
		ErrorExit(L"CreateRestrictedJobObject");
	}

	/// Add UI restriction
	ZeroMemory(&uiRestriction, sizeof(JOBOBJECT_BASIC_UI_RESTRICTIONS));
	uiRestriction.UIRestrictionsClass |= JOB_OBJECT_UILIMIT_DESKTOP;
	uiRestriction.UIRestrictionsClass |= JOB_OBJECT_UILIMIT_DISPLAYSETTINGS;
	uiRestriction.UIRestrictionsClass |= JOB_OBJECT_UILIMIT_EXITWINDOWS;
	uiRestriction.UIRestrictionsClass |= JOB_OBJECT_UILIMIT_HANDLES;
	uiRestriction.UIRestrictionsClass |= JOB_OBJECT_UILIMIT_READCLIPBOARD;
	uiRestriction.UIRestrictionsClass |= JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS;
	uiRestriction.UIRestrictionsClass |= JOB_OBJECT_UILIMIT_WRITECLIPBOARD;
	uiRestriction.UIRestrictionsClass |= JOB_OBJECT_UILIMIT_GLOBALATOMS;
	if (!SetInformationJobObject(job, JobObjectBasicUIRestrictions, &uiRestriction, sizeof(JOBOBJECT_BASIC_UI_RESTRICTIONS))) {
		int err = GetLastError();
		TerminateJobObject(job, EXIT_FAILURE);
		CloseHandle(job);
		SetLastError(err);
		ErrorExit(L"CreateRestrictedJobObject");
	}

	/// Restrict information
	ZeroMemory(&basicLimits, sizeof(JOBOBJECT_BASIC_LIMIT_INFORMATION));
	basicLimits.LimitFlags = JOB_OBJECT_LIMIT_ACTIVE_PROCESS | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
	/// Limit to single process.
	basicLimits.ActiveProcessLimit = 1;

	ZeroMemory(&extLimit, sizeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
	extLimit.BasicLimitInformation = basicLimits;
	if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &extLimit, sizeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION))) {
		int err = GetLastError();
		TerminateJobObject(job, EXIT_FAILURE);
		CloseHandle(job);
		SetLastError(err);
		ErrorExit(L"CreateRestrictedJobObject");
	}
	return job;
}




BOOL CreateProcessWithExplicitTokenSuspended(
	__in WCHAR * pathToFile,
	__in PWSTR pszCommandLine,
	__in HANDLE token,
	__in LPWSTR fullDesktopName,
	__out PROCESS_INFORMATION * pi)
{
	//assume we get all the params NULLABLE
	STARTUPINFO si = { sizeof(si) };
	si.lpDesktop = fullDesktopName;

	if (!CreateProcessAsUser(token,
		pathToFile,
		pszCommandLine,
		NULL,
		NULL,
		TRUE,
		CREATE_SUSPENDED | CREATE_BREAKAWAY_FROM_JOB /*| DETACHED_PROCESS*/,
		NULL,
		NULL,
		&si, pi))

	{
		ErrorExit(L"CreateProcessWithExplicitTokenSuspended");
	}

	return TRUE;
}




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






BOOL initializeProcessWithImpersonationToken(PROCESS_INFORMATION pi, HANDLE impersonationToken) {
	CONTEXT ctx = { 0 };
	ctx.ContextFlags = CONTEXT_ALL;

	if (!GetThreadContext(pi.hThread, &ctx))
		return FALSE;

	DWORD old;
	if (!VirtualProtectEx(pi.hProcess, (LPVOID)ctx.Eax, 2, PAGE_EXECUTE_READWRITE, &old))
		ErrorExit(L"virtual protect");

	//replace the entry point to jmp -2 
	byte code[2];
	SIZE_T read;
	DWORD entry = ctx.Eax;
	if (!ReadProcessMemory(pi.hProcess, (LPVOID)ctx.Eax, code, 2, &read))
		ErrorExit(L"virtual protect");
	if (!WriteProcessMemory(pi.hProcess, (LPVOID)ctx.Eax, "\xEB\xFE", 2, &read))
		ErrorExit(L"virtual protect");

	//impersonate with another token
	if (!(SetThreadToken(&pi.hThread, impersonationToken)))
		ErrorExit(L"virtual protect");

	//resume thread to finish initialization
	if (ResumeThread(pi.hThread) == -1)
		ErrorExit(L"Resume thread");
	DWORD message = GetLastError();

	// wait until the thread stuck at entry point
	CONTEXT context;
	GetThreadContext(pi.hThread, &context);

	for (unsigned int i = 0; i < 50 && context.Eip != entry; ++i)
	{
		Sleep(100);

		// read the thread context
		context.ContextFlags = CONTEXT_CONTROL;
		GetThreadContext(pi.hThread, &context);
	}
	if (context.Eip != (DWORD)entry)
	{
		// wait timed out
		ErrorExit(L"entry point blockade timed out");
	}

	// inject our dll to the process using remote thread, our dll will do reverttoself
	//Inject_CreateRemoteThread(Payload, hProcess);

	// pause and restore original entry point
	SuspendThread(pi.hThread);
	if (!WriteProcessMemory(pi.hProcess, (LPVOID)entry, code, 2, &read))
		ErrorExit(L"WriteProcessMemory");

	return TRUE;
}




BOOL setNewWindowStationAndDesktop() {

	/// Define the local veriables.
	SECURITY_ATTRIBUTES saWS = { 0 };
	SECURITY_ATTRIBUTES saD = { 0 };
	HDESK lastDesktop;
	HWINSTA lastWindowStation;
	int err = 0;

	/// Copy the current desktop security attributes and updtae the last
	lastDesktop = GetThreadDesktop(GetCurrentThreadId());
	if (lastDesktop == NULL || !GetSecurityAttributes(GetThreadDesktop(GetCurrentThreadId()), &saD)) {
		ErrorExit(L"setNewWindowStationAndDesktop");
	}

	/// Copy security attributes and update last
	lastWindowStation = GetProcessWindowStation();
	if (!GetSecurityAttributes(lastWindowStation, &saWS)) {
		ErrorExit(L"setNewWindowStationAndDesktop");
	}

	//create new window station
	HWINSTA winsta = CreateWindowStation(NULL, NULL, WINSTA_ALL_ACCESS, &saWS);
	if (!winsta) {
		winsta = OpenWindowStation(NULL, NULL, GENERIC_ALL);
	}
	if (!winsta) {
		ErrorExit(L"setNewWindowStationAndDesktop - OpenWindowStation");
	}

	//set the new winstation to current process in order to make the desktop part of this station
	if (!SetProcessWindowStation(winsta)) {
		ErrorExit(L"setNewWindowStationAndDesktop - SetProcessWindowStation");
	}

	//Open a new Desktop in the new station and it to the current thread
	wchar_t* desktop_name = L"SandBoxHiddenDesktop";		//TODO: add name which change
	HDESK hidden_desktop = OpenDesktopW(desktop_name, NULL, TRUE, GENERIC_ALL);
	if (!hidden_desktop)
	{
		hidden_desktop = CreateDesktopW(desktop_name, NULL, NULL, 0, GENERIC_ALL, &saD);
	}
	if (!hidden_desktop) {
		int err = GetLastError();
		SetProcessWindowStation(lastWindowStation);
		SetLastError(err);
		ErrorExit(L"setNewWindowStationAndDesktop - CreateDesktopW");
	}

	//revert to original desktop and window station
	if (!SetProcessWindowStation(lastWindowStation)) {
		ErrorExit(L"setNewWindowStationAndDesktop - SetProcessWindowStation 2");
	}

	CloseHandle(winsta);
	CloseHandle(hidden_desktop);

	return TRUE;
}
