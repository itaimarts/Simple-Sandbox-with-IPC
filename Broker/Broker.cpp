// Broker.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "TokenUtils.h"
#include "Utils.h"
#include "ProcessCreation.h"


BOOL runProcessAsUntrusted(char * pathToFile) {
	
	//create tokens primary and initialization tokens
	HANDLE primaryToken = createRestrictedToken(GetCurrentProcess(), TRUE);
	HANDLE initializationToken = createRestrictedToken(GetCurrentProcess(), FALSE);
	HANDLE impersonation_token;

	//set new window station and desktop to this process in order the son process will inherit it
	setNewWindowStationAndDesktop();

	//create the process with the fully restricted token 
	PWSTR pathTofilePW;
	PROCESS_INFORMATION pi = { 0 };
	convertcharArrToPWSTR(pathToFile, &pathTofilePW);
	//replace the name with method wich return it
	CreateProcessWithExplicitTokenSuspended(pathTofilePW, primaryToken, L"Service-0x0-8a112$\\SandBoxHiddenDesktop", &pi);

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


int main()
{
	//char * str = "C:\\Users\\itai marts\\Desktop\\Cyber2\\hw2\\Sandbox\\programUsingSandbox\\Debug\\programUsingSandbox.exe";
	char * str = "C:\\Users\\itai marts\\Desktop\\Cyber2\\hw2\\Sandbox\\target_program\\\Debug\\target_program.exe";
	//TODO: get the path file to run from cmd

	//create and run the low process
	runProcessAsUntrusted(str);
	Sleep(50000);
	
	 

	return 0;
}


