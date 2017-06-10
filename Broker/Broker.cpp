// Broker.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <windows.h>
#include <atlstr.h>
#include <strsafe.h>
#include <Sddl.h>
#include <TlHelp32.h>
#include "Broker.h"
#include <thread>
#include <DbgHelp.h>
#define BUFFER_SIZE		4096 // 4K bytes





void createNamedPipe() {
	// Prepare the pipe name
	CString strPipeName;
	strPipeName.Format(_T("\\\\%s\\pipe\\%s"),
		_T("."),			// Server name
		_T("HelloWorld")	// Pipe name
	);

	//Security descriptor - set as low integerity level.
	SECURITY_ATTRIBUTES sa;
	sa.lpSecurityDescriptor = (PSECURITY_DESCRIPTOR)malloc(
		SECURITY_DESCRIPTOR_MIN_LENGTH);
	InitializeSecurityDescriptor(sa.lpSecurityDescriptor,
		SECURITY_DESCRIPTOR_REVISION);
	// ACL is set as NULL in order to allow all access to the object.
	SetSecurityDescriptorDacl(sa.lpSecurityDescriptor, TRUE, NULL, FALSE);
	sa.nLength = sizeof(sa);
	sa.bInheritHandle = TRUE;

	// Create the named pipe.
	HANDLE hPipe = CreateNamedPipe(
		strPipeName,				// The unique pipe name. This string must 
									// have the form of \\.\pipe\pipename
		PIPE_ACCESS_DUPLEX,			// The pipe is bi-directional; both  
									// server and client processes can read 
									// from and write to the pipe
		PIPE_TYPE_MESSAGE |			// Message type pipe 
		PIPE_READMODE_MESSAGE |		// Message-read mode 
		PIPE_WAIT,					// Blocking mode is enabled
		PIPE_UNLIMITED_INSTANCES,	// Max. instances
		BUFFER_SIZE,				// Output buffer size in bytes
		BUFFER_SIZE,				// Input buffer size in bytes

		NMPWAIT_USE_DEFAULT_WAIT,	// Time-out interval
		&sa							// Security attributes
	);

}


ULONG SetProcessUntrusted(HANDLE hProcess)
{
	TOKEN_MANDATORY_LABEL tml = { { (PSID)alloca(MAX_SID_SIZE), SE_GROUP_INTEGRITY } };

	ULONG cb = MAX_SID_SIZE;

	HANDLE hToken;

	if (!CreateWellKnownSid(WinUntrustedLabelSid, 0, tml.Label.Sid, &cb) ||
		!OpenProcessToken(hProcess, TOKEN_ADJUST_DEFAULT, &hToken))
	{
		return GetLastError();
	}

	ULONG dwError = NOERROR;
	if (!SetTokenInformation(hToken, TokenIntegrityLevel, &tml, sizeof(tml)))
	{
		dwError = GetLastError();
	}

	CloseHandle(hToken);

	return dwError;
}


HDESK CreateHiddenDesktop(CHAR *desktop_name)
{
	CHAR explorer_path[MAX_PATH];
	HDESK hidden_desktop = NULL, original_desktop;
	STARTUPINFOA startup_info = { 0 };
	PROCESS_INFORMATION process_info = { 0 };

	ExpandEnvironmentStringsA("%windir%\\explorer.exe", explorer_path, MAX_PATH - 1);

	hidden_desktop = OpenDesktopA(desktop_name, NULL, FALSE, GENERIC_ALL);
	if (!hidden_desktop)
	{
		hidden_desktop = CreateDesktopA(desktop_name, NULL, NULL, 0, GENERIC_ALL, NULL);
		if (hidden_desktop)
		{
			original_desktop = GetThreadDesktop(GetCurrentThreadId());
		
			if (SetThreadDesktop(hidden_desktop))
			{
				startup_info.cb = sizeof(startup_info);
				startup_info.lpDesktop = desktop_name;

				//We need to create an explorer.exe in the context of the new desktop for start menu, etc
				CreateProcessA(explorer_path, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &startup_info, &process_info);

				SetThreadDesktop(original_desktop);
		}
		}
	}
	return hidden_desktop;
}


BOOL CreateLowProcess(PWSTR pszCommandLine)
{
	HDESK original_desktop, hidden_desktop;
	hidden_desktop = CreateDesktop(TEXT("itai_sandbox"), NULL, NULL, 0, GENERIC_ALL, NULL);


	DWORD dwError = ERROR_SUCCESS;
	HANDLE hToken = NULL;
	HANDLE hNewToken = NULL;
	SID_IDENTIFIER_AUTHORITY MLAuthority = SECURITY_MANDATORY_LABEL_AUTHORITY;
	PSID pIntegritySid = NULL;
	TOKEN_MANDATORY_LABEL tml = { 0 };
	STARTUPINFO si = { sizeof(si) };
	PROCESS_INFORMATION pi = { 0 };

	
	// Open the primary access token of the process.
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY |
		TOKEN_ADJUST_DEFAULT | TOKEN_ASSIGN_PRIMARY , &hToken))
	{
		dwError = GetLastError();
		goto Cleanup;
	}

	// Duplicate the primary token of the current process.
	if (!DuplicateTokenEx(hToken, 0, NULL, SecurityImpersonation,
		TokenPrimary, &hNewToken))
	{
		dwError = GetLastError();
		goto Cleanup;
	}

	// Create the low integrity SID.
	if (!AllocateAndInitializeSid(&MLAuthority, 1, SECURITY_MANDATORY_LOW_RID,
		0, 0, 0, 0, 0, 0, 0, &pIntegritySid))
	{
		dwError = GetLastError();
		goto Cleanup;
	}

	tml.Label.Attributes = SE_GROUP_INTEGRITY;
	tml.Label.Sid = pIntegritySid;

	// Set the integrity level in the access token to low.
	if (!SetTokenInformation(hNewToken, TokenIntegrityLevel, &tml,
		(sizeof(tml) + GetLengthSid(pIntegritySid))))
	{
		dwError = GetLastError();
		goto Cleanup;
	}
	si.lpDesktop = TEXT("itai_sandbox");
	// Create the new process at the Low integrity level.
	if (!CreateProcessAsUserW(hNewToken, NULL, pszCommandLine, NULL, NULL,
		FALSE, NULL, NULL, NULL, &si, &pi))
	//if (!CreateProcessWithTokenW(hNewToken, LOGON_NETCREDENTIALS_ONLY, pszCommandLine, NULL, NULL,
	//		NULL, NULL, &si, &pi))
	{
		dwError = GetLastError();
		goto Cleanup;
	}
	Sleep(100);
	SetProcessUntrusted(pi.hProcess);

	//HANDLE sandboxedProcessMainThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, pi.dwThreadId);

	//ResumeThread(sandboxedProcessMainThread);



Cleanup:
	// Centralized cleanup for all allocated resources.
	if (hToken)
	{
		CloseHandle(hToken);
		hToken = NULL;
	}
	if (hNewToken)
	{
		CloseHandle(hNewToken);
		hNewToken = NULL;
	}
	if (pIntegritySid)
	{
		FreeSid(pIntegritySid);
		pIntegritySid = NULL;
	}
	if (pi.hProcess)
	{
		CloseHandle(pi.hProcess);
		pi.hProcess = NULL;
	}
	if (pi.hThread)
	{
		CloseHandle(pi.hThread);
		pi.hThread = NULL;
	}

	if (ERROR_SUCCESS != dwError)
	{
		// Make sure that the error code is set for failure.
		SetLastError(dwError);
		return FALSE;
	}
	else
	{
		return TRUE;
	}
}



int main()
{
	char * str = "C:\\Users\\itai marts\\Desktop\\Cyber2\\hw2\\Sandbox\\programUsingSandbox\\Debug\\programUsingSandbox.exe";
	//char * str = "calc";

	//convert path file to PWSTR
	int count = 0;
	PWSTR MyWS = NULL;
	count = MultiByteToWideChar(CP_ACP, 0, str, strlen(str), NULL, 0);
	if (count > 0)
	{
		MyWS = SysAllocStringLen(0, count);
		MultiByteToWideChar(CP_ACP, 0, str, strlen(str), MyWS, count);
	}
	
	//create and run the low process
	CreateLowProcess(MyWS);
	Sleep(50000);
	
	 

	return 0;
}


