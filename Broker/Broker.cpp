// Broker.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <windows.h>
#include <atlstr.h>
#include <strsafe.h>
#include <Sddl.h>
#include "Broker.h"

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



BOOL CreateLowProcess(PWSTR pszCommandLine)
{
	
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
		TOKEN_ADJUST_DEFAULT | TOKEN_ASSIGN_PRIMARY, &hToken))
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

	// Create the new process at the Low integrity level.
	if (!CreateProcessAsUser(hNewToken, NULL, pszCommandLine, NULL, NULL,
		FALSE, 0, NULL, NULL, &si, &pi))
	{
		dwError = GetLastError();
		goto Cleanup;
	}

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
	//char * str = "C:\\Users\\itai marts\\Desktop\\Cyber2\\hw2\\programUsingSandbox\\Debug\\programUsingSandbox.exe";
	char * str = "calc";

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

	/* need to create another desktop and run the low integrity process there
	*  need to give the new process pipe in order to make conversation with the broker
	*  implement the protocol as defined in assignment
	*/ 

	return 0;
}