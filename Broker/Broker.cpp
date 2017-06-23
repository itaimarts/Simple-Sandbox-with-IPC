// Broker.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <stdlib.h>
#include "TokenUtils.h"
#include "Utils.h"
#include "ProcessCreation.h"
#include "IPC.h"

#define sandboxedTargetPath  L"C:\\Users\\itai marts\\Desktop\\Cyber2\\hw2\\Sandbox\\target_program\\\Debug\\target_program.exe"
LPCWSTR filePath = L"C:\\itai.txt";

BOOL runProcessAsUntrusted(WCHAR * pathToFile, WCHAR * cmdLine) {
	
	//create tokens primary and initialization tokens
	HANDLE primaryToken = createRestrictedToken(GetCurrentProcess(), FALSE);
	HANDLE initializationToken = createRestrictedToken(GetCurrentProcess(), FALSE);
	HANDLE impersonation_token;
	PROCESS_INFORMATION pi = { 0 };

	//set new window station and desktop to this process in order the son process will inherit it
	setNewWindowStationAndDesktop();

	//create the process with the fully restricted token 
	//replace the name with method which return it
	CreateProcessWithExplicitTokenSuspended(pathToFile, cmdLine, primaryToken, L"Service-0x0-8a112$\\SandBoxHiddenDesktop", &pi);

	//initialize the process with impersonation token
	DuplicateToken(initializationToken, SecurityImpersonation, &impersonation_token);
	initializeProcessWithImpersonationToken(pi, impersonation_token);

	//assign the new process to restricted job
	HANDLE job = CreateRestrictedJobObject();
	if (!AssignProcessToJobObject(job, pi.hProcess)) {
		ErrorExit(L"Could not assign process to a job");
	}

	//load our dll into process memory


	//set the process as untrusted before the program start to working
	SetProcessUntrusted(pi.hProcess);

	//resumeprocess
	ResumeThread(pi.hThread);
	
	return TRUE;
}


//int main()
int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, PWSTR pCmdLine, int nCmdShow)
{
		
	SECURITY_ATTRIBUTES sa;
	ZeroMemory(&sa, sizeof(SECURITY_ATTRIBUTES));
	sa.bInheritHandle = TRUE;
	sa.nLength = sizeof(sa);
	WCHAR CmdLineBuf[1024];
	WCHAR AppPath[1024];

	IPC * ipc = new IPC(hInstance, pCmdLine, nCmdShow);
	HANDLE fHandle = CreateFile(filePath, GENERIC_ALL, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	//TODO: get the path file to run from cmd
	if (_snwprintf_s(CmdLineBuf, 1023, L"\"%s\" %p %p %p 0 %s 0", sandboxedTargetPath, ipc->targetToBrokerWrite, ipc->brokerToTargetRead, fHandle, filePath) < 0) {
		ErrorExit(L"main - initialization errors");
	}

	CmdLineBuf[1023] = '\0';
	wcscpy_s(AppPath, sandboxedTargetPath);

	//create and run the low process
	runProcessAsUntrusted(AppPath, CmdLineBuf);

	ipc->loop();
	Sleep(50000);
	
	 

	return 0;
}


