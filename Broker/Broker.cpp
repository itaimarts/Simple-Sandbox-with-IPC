// Broker.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

#include "TokenUtils.h"
#include "Utils.h"
#include "pe_image.h"
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










BOOL CreateProcessWithExplicitTokenSuspended(
	__in PWSTR pszCommandLine, 
	__in HANDLE restrictedToken,
	__out PROCESS_INFORMATION * pi)
{
	
	DWORD dwError = ERROR_SUCCESS;
	STARTUPINFO si = { sizeof(si) };
	si.lpDesktop = L"Service-0x0-8a112$\\SandBoxHiddenDesktop";

	if (!CreateProcessAsUserW(restrictedToken, 
		NULL, 
		pszCommandLine, 
		NULL, 
		NULL,
		TRUE,
		CREATE_SUSPENDED | CREATE_BREAKAWAY_FROM_JOB /*| DETACHED_PROCESS*/,
		NULL, 
		NULL, 
		&si, pi))
	
	{
		dwError = GetLastError();
		goto Cleanup;
	}
	


	return TRUE;

Cleanup:
	// Centralized cleanup for all allocated resources.
	if ((*pi).hProcess)
	{
		CloseHandle((*pi).hProcess);
		(*pi).hProcess = NULL;
	}
	if ((*pi).hThread)
	{
		CloseHandle((*pi).hThread);
		(*pi).hThread = NULL;
	}
	return FALSE;
}


HANDLE CreateRestrictedJobObject() {
	/// Local variables, initilization is near use.
	int err = 0;
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
		//SetError(L"Could not create job object", GetLastError());
		return INVALID_HANDLE_VALUE;
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
		err = GetLastError();
		//SetError(L"Could not restrict ui for the job object", err);
		TerminateJobObject(job, EXIT_FAILURE);
		CloseHandle(job);
		SetLastError(err);
		return INVALID_HANDLE_VALUE;
	}

	/// Restrict information
	ZeroMemory(&basicLimits, sizeof(JOBOBJECT_BASIC_LIMIT_INFORMATION));
	basicLimits.LimitFlags = JOB_OBJECT_LIMIT_ACTIVE_PROCESS | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
	/// Limit to single process.
	basicLimits.ActiveProcessLimit = 1;

	ZeroMemory(&extLimit, sizeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
	extLimit.BasicLimitInformation = basicLimits;
	if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &extLimit, sizeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION))) {
		err = GetLastError();
		//SetError(L"Could not restrict information for the job object", err);
		TerminateJobObject(job, EXIT_FAILURE);
		CloseHandle(job);
		SetLastError(err);
		return INVALID_HANDLE_VALUE;
	}
	return job;
}




DWORD GetSidsToDisable(
	__in	PSID_AND_ATTRIBUTES SidsToDisable,
	__in	DWORD Bufsize,
	__in	PTOKEN_GROUPS pTokenGroups,
	__in	BOOL FullRestriction)
{
	DWORD i;
	DWORD DisableSidCount = 0;
	SID EveryoneSid = { 1, 1, SECURITY_WORLD_SID_AUTHORITY, SECURITY_WORLD_RID };

	/// Firstly check the arguments
	if (SidsToDisable == NULL || pTokenGroups == NULL ||
		Bufsize < pTokenGroups->GroupCount * sizeof(SID_AND_ATTRIBUTES))
	{
		SetLastError(ERROR_INVALID_PARAMETER);
		printf("INVALID_PARAMETER %s", ERROR_INVALID_PARAMETER);
		return ~0;
	}
	/// Full restriction want to only keep the SID LOGON.
	/// Not full restriction will keep LOGON, EVERYONE and BUILTIN/USERS SIDs.
	for (i = 0; i < pTokenGroups->GroupCount; i++)
	{
		SID* pSid = (SID*)pTokenGroups->Groups[i].Sid;
		if (!FullRestriction) {
			// this could be a large OR statement, but this way is easier to read
			if (EqualSid((PSID)&EveryoneSid, pTokenGroups->Groups[i].Sid)) {
				continue;
			}
			if (pSid->SubAuthority[0] == SECURITY_BUILTIN_DOMAIN_RID &&
				pSid->SubAuthority[1] == DOMAIN_ALIAS_RID_USERS)
			{
				continue;
			}
		}
		if (pSid->SubAuthorityCount == SECURITY_LOGON_IDS_RID_COUNT &&
			pSid->SubAuthority[0] == SECURITY_LOGON_IDS_RID)
		{
			continue;
		}
		SidsToDisable[DisableSidCount].Sid = pTokenGroups->Groups[i].Sid;
		DisableSidCount++;
	}
	return DisableSidCount;
}




BOOL SetIntegrityLevel(HANDLE RestrictedToken, BOOL FullRestriction) {

	DWORD dwError = ERROR_SUCCESS;	
	SID_IDENTIFIER_AUTHORITY MLAuthority = SECURITY_MANDATORY_LABEL_AUTHORITY;
	PSID pIntegritySid = NULL;
	TOKEN_MANDATORY_LABEL tml = { 0 };

	if (FullRestriction){
		if (!AllocateAndInitializeSid(&MLAuthority, 1, SECURITY_MANDATORY_UNTRUSTED_RID,
		0, 0, 0, 0, 0, 0, 0, &pIntegritySid))
		{
			dwError = GetLastError();
			return FALSE;
		}
	}
	else {
		if (!AllocateAndInitializeSid(&MLAuthority, 1, SECURITY_MANDATORY_MEDIUM_RID,
			0, 0, 0, 0, 0, 0, 0, &pIntegritySid))
		{
			dwError = GetLastError();
			return FALSE;
		}
	}

	tml.Label.Attributes = SE_GROUP_INTEGRITY;
	tml.Label.Sid = pIntegritySid;

	// Set the integrity level in the access token to low.
	if (!SetTokenInformation(RestrictedToken, TokenIntegrityLevel, &tml,
		(sizeof(tml) + GetLengthSid(pIntegritySid))))
	{
		dwError = GetLastError();
		return FALSE;
	}
}




BOOL TweakToken(HANDLE hToken)
{
	/// Local variables
	TOKEN_DEFAULT_DACL TokenDacl;
	PSID UserSid;
	PSID OwnerSid;
	DWORD needed;
	DWORD sidlen;
	ACCESS_ALLOWED_ACE* pAce;
	SID EveryoneSid = { 1, 1, SECURITY_WORLD_SID_AUTHORITY, SECURITY_WORLD_RID };
	SID SystemSid = { 1, 1, SECURITY_NT_AUTHORITY, SECURITY_LOCAL_SYSTEM_RID };
	const DWORD MaxSidSize = sizeof(SID) + (SID_MAX_SUB_AUTHORITIES - 1) * sizeof(DWORD);
	BYTE TokenUserBuf[MaxSidSize];
	BYTE TokenOwnerBuf[MaxSidSize];

	const DWORD DaclBufsize = sizeof(ACL) + (sizeof(ACCESS_ALLOWED_ACE) + MaxSidSize - sizeof(DWORD)) * 2;
	BYTE DaclBuf[DaclBufsize];

	BYTE AceBuf[sizeof(ACCESS_ALLOWED_ACE) + MaxSidSize - sizeof(DWORD)];
	ACL* pAcl = (ACL*)DaclBuf;

	/// Get relevant data
	if (!GetTokenInformation(hToken, TokenUser, TokenUserBuf, MaxSidSize, &needed)) {
		return FALSE;
	}
	if (!GetTokenInformation(hToken, TokenOwner, TokenOwnerBuf, MaxSidSize, &needed)) {
		return FALSE;
	}
	UserSid = ((TOKEN_USER*)TokenUserBuf)->User.Sid;
	OwnerSid = ((TOKEN_OWNER*)TokenOwnerBuf)->Owner;


	/// If the owner isn't the current user then set the owner as the current user.
	/// Otherwise the process will not be able to access itself.
	if (!EqualSid(UserSid, OwnerSid))
	{
		if (!SetTokenInformation(hToken, TokenOwner, UserSid, MaxSidSize))
		{
			ErrorExit(L"Cannot set token owner");
			return FALSE;
		}
	}
	/// Now let's set the token DACL
	if (!InitializeAcl(pAcl, DaclBufsize, ACL_REVISION))
	{
		ErrorExit(L"Cannot initialize ACL");
		return FALSE;
	}


	sidlen = GetLengthSid(UserSid);
	/// Create the first ACE for the UserSid
	pAce = (ACCESS_ALLOWED_ACE*)AceBuf;
	pAce->Header.AceFlags = 0;
	pAce->Header.AceType = 0;
	pAce->Header.AceSize = sizeof(ACCESS_ALLOWED_ACE) - sizeof(DWORD) + sidlen;
	pAce->Mask = GENERIC_ALL;
	CopySid(sidlen, (PSID)&(pAce->SidStart), UserSid);

	/// Append the pAce to the end
	if (!AddAce(pAcl, ACL_REVISION, ~0, pAce, pAce->Header.AceSize))
	{
		ErrorExit(L"Cannot add User ACE to ACL");
		return FALSE;
	}

	/// Now create the next one - everything is set, so we just change the SID and the size
	pAce->Header.AceSize = sizeof(ACCESS_ALLOWED_ACE) - sizeof(DWORD) + GetLengthSid((PSID)&SystemSid);
	CopySid(GetLengthSid(&SystemSid), (PSID)&(pAce->SidStart), (PSID)&SystemSid);
	if (!AddAce(pAcl, ACL_REVISION, ~0, pAce, pAce->Header.AceSize))
	{
		ErrorExit(L"Cannot add System ACE to ACL");
		return FALSE;
	}

	/// We finish with the creation of the DACL
	TokenDacl.DefaultDacl = pAcl;
	if (!SetTokenInformation(hToken, TokenDefaultDacl, &TokenDacl, pAcl->AclSize))
	{
		ErrorExit(L"Cannot set token DACL");
		return FALSE;
	}
	return TRUE;
}






HANDLE createRestrictedToken(HANDLE process, BOOL FullRestriction) {
	/// Local variables
	HANDLE RestrictedToken;
	int err = 0;
	int success = 0;
	HANDLE hProcToken;
	TOKEN_GROUPS* pTokenGroups;
	PSID logon;
	DWORD RestrictedCount = 0;
	DWORD bufsize = 512;
	DWORD DisableSidCount;
	SID_AND_ATTRIBUTES* SidsToDisable;
	SID_AND_ATTRIBUTES* restrictedSids;
	SID EveryoneSid = { 1, 1, SECURITY_WORLD_SID_AUTHORITY, SECURITY_WORLD_RID };

	/// Get process token to be used as a base.
	if (!OpenProcessToken(process, TOKEN_ALL_ACCESS | TOKEN_IMPERSONATE, &hProcToken))
	{
		printf("Could not open process token, %s", GetLastError());
		return INVALID_HANDLE_VALUE;
	}

	/// Extract the token's groups
	if (!GetTokenGroups(hProcToken, &pTokenGroups))
	{
		CloseHandle(hProcToken);
		return INVALID_HANDLE_VALUE;
	}

	/// Alocate dynamic buffer for the SIDS pretend to disable
	bufsize = pTokenGroups->GroupCount * sizeof(SID_AND_ATTRIBUTES);
	SidsToDisable = (SID_AND_ATTRIBUTES*)GlobalAlloc(GPTR, bufsize);
	if (SidsToDisable == NULL)
	{
		err = GetLastError();
		printf("Could not allocate memory for disabled sids %s", err);
		GlobalFree(pTokenGroups);
		CloseHandle(hProcToken);
		SetLastError(err);
		return INVALID_HANDLE_VALUE;
	}

	DisableSidCount = GetSidsToDisable(SidsToDisable, bufsize, pTokenGroups, FullRestriction);
	if (DisableSidCount == ~0)
	{
		err = GetLastError();
		GlobalFree(SidsToDisable);
		GlobalFree(pTokenGroups);
		CloseHandle(hProcToken);
		SetLastError(err);
		return INVALID_HANDLE_VALUE;
	}

	/// Create Restricted SID
	/// If FullRestriction is n then leave only LOGON & RESTRICTED SIDs, 
	/// otherwise leave LOGON, RESTRICTED, EVERYONE, BUILTIN\USERS SIDs.
	RestrictedCount = FullRestriction ? 2 : 4;
	restrictedSids = (SID_AND_ATTRIBUTES*)GlobalAlloc(GPTR, RestrictedCount * sizeof(SID_AND_ATTRIBUTES));
	if (restrictedSids == NULL) {
		err = GetLastError();
		//SetError(L"Could not allocate memory for restricted sids", err);
		GlobalFree(SidsToDisable);
		GlobalFree(pTokenGroups);
		CloseHandle(hProcToken);
		SetLastError(err);
		return INVALID_HANDLE_VALUE;
	}

	//either way need to define logon sid and  restricted sid in restricted arr
	ZeroMemory(restrictedSids, RestrictedCount * sizeof(SID_AND_ATTRIBUTES));
	ConvertStringSidToSid(RESTRICTED_SID, &(restrictedSids[0].Sid));
	GetLogonSID(hProcToken, &logon);
	restrictedSids[1].Sid = logon;
	//in case dont need the full restriction, insert the EVERYONE and builtin users sids to restricted arr
	if (!FullRestriction) {
		restrictedSids[2].Sid = &EveryoneSid;
		ConvertStringSidToSid(USERS_SID, &(restrictedSids[3].Sid));
	}

	success = CreateRestrictedToken(hProcToken,  /// existing token
		DISABLE_MAX_PRIVILEGE,				/// flags
		DisableSidCount,					/// number of SIDs to disable
		SidsToDisable,						/// array of SID and attributes
		0,									/// number of privileges to drop
		NULL,								/// array of privileges
		RestrictedCount,					/// no restricted SIDs
		restrictedSids,						/// array of restricted SIDs 
		&RestrictedToken);


	err = GetLastError();
	GlobalFree(logon);
	GlobalFree(restrictedSids);
	GlobalFree(SidsToDisable);
	GlobalFree(pTokenGroups);
	if (!success)
	{
		//SetError(L"Could not create restricted token", err);
		SetLastError(err);
		return INVALID_HANDLE_VALUE;
	}

	/// Set integrity level to untrusted
	SetIntegrityLevel(RestrictedToken, FALSE);
	
	/// If the current user is an admin, the owner will be 
	/// administrators - this might not be a good thing
	//if (!TweakToken(RestrictedToken)) {
	//	return INVALID_HANDLE_VALUE;
	//}
	return RestrictedToken;
}


/*
void* GetBaseAddress(const wchar_t* exe_name, void* entry_point) {
	HMODULE exe = ::LoadLibrary(exe_name);
	if (NULL == exe)
		return exe;

	base::win::PEImage pe(exe);
	if (!pe.VerifyMagic()) {
		::FreeLibrary(exe);
		return exe;
	}
	PIMAGE_NT_HEADERS nt_header = pe.GetNTHeaders();
	char* base = reinterpret_cast<char*>(entry_point) -
		nt_header->OptionalHeader.AddressOfEntryPoint;

	::FreeLibrary(exe);
	return base;
}

*/

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
	//DWORD message = GetLastError();
	
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
	
	//set the process as untrusted
	SetProcessUntrusted(pi.hProcess);

	return TRUE;
}





BOOL setNewWindowStationAndDesktop(__out HDESK * lastDesktop,
							__out HWINSTA * lastWindowStation) {

	/// Define the local veriables.

	SECURITY_ATTRIBUTES sa = { 0 };
	SECURITY_ATTRIBUTES attributes = { 0 };
	
	/// Copy the current desktop security attributes and updtae the last
	*lastDesktop = GetThreadDesktop(GetCurrentThreadId());
	if (*lastDesktop == NULL) {
		//SetError(L"Could not get the current thread desktop.", GetLastError());
		return FALSE;
	}
	if (!GetSecurityAttributes(GetThreadDesktop(GetCurrentThreadId()),
		&attributes)) {
		return FALSE;
	}
	
	/// Copy security attributes and update last
	*lastWindowStation = GetProcessWindowStation();
	if (!GetSecurityAttributes(*lastWindowStation, &sa)) {
		//SetError(L"Could not get the desktop security attributes.", GetLastError());
		CloseHandle(*lastDesktop);
		return FALSE;
	}
	
	//create new window station
	HWINSTA winsta = CreateWindowStation(NULL, NULL, WINSTA_ALL_ACCESS, &sa);
	DWORD message = GetLastError();
	if (!winsta) {
		DWORD message = GetLastError();
		winsta = OpenWindowStation(NULL, NULL, GENERIC_ALL);
	}
	if (!winsta) {
		//SetError(L"Could not create a new windows station.", GetLastError());
		//CloseHandle(original_desktop);
		return FALSE;
	}
	GetWindowObjectName(winsta);
	//set the new winstation to current process
	if (!SetProcessWindowStation(winsta)) {
		//SetError(L"Could not change new windows stations.", GetLastError());
		//CloseHandle(original_desktop);
		return FALSE;
	}

	//Open a new Desktop in the new station and it to the current thread
	wchar_t* desktop_name = L"SandBoxHiddenDesktop";
	HDESK hidden_desktop = OpenDesktopW(desktop_name, NULL, TRUE, GENERIC_ALL);
	if (!hidden_desktop)
	{
		hidden_desktop = CreateDesktopW(desktop_name, NULL, NULL, 0, GENERIC_ALL, &attributes);
	}
	if (!hidden_desktop) {
		//SetError(L"Could not create new desktop.", GetLastError());
		CloseHandle(winsta);
		SetProcessWindowStation(*lastWindowStation);
		//CloseHandle(original_desktop);
		return FALSE;
	}
	/*
	if (hidden_desktop) {
		// Replace the DACL on the new Desktop with a reduced privilege version.
		// We can soft fail on this for now, as it's just an extra mitigation.
		static const ACCESS_MASK kDesktopDenyMask = WRITE_DAC | WRITE_OWNER |
			DELETE |
			DESKTOP_CREATEMENU |
			DESKTOP_CREATEWINDOW |
			DESKTOP_HOOKCONTROL |
			DESKTOP_JOURNALPLAYBACK |
			DESKTOP_JOURNALRECORD |
			DESKTOP_SWITCHDESKTOP;
		AddKnownSidToObject(hidden_desktop, SE_WINDOW_OBJECT, Sid(WinRestrictedCodeSid),
			DENY_ACCESS, kDesktopDenyMask);
		return SBOX_ALL_OK;
	}
	*/
	//revert to original desktop and window station
	//SetThreadDesktop(*lastDesktop);
	SetProcessWindowStation(*lastWindowStation);

	CloseHandle(winsta);
	CloseHandle(hidden_desktop);
	

}




BOOL runProcessAsUntrusted(char * pathToFile) {
	
	HANDLE primaryToken = createRestrictedToken(GetCurrentProcess(), TRUE);
	HANDLE impersonateToken = createRestrictedToken(GetCurrentProcess(), FALSE);
	HANDLE impersonation_token;

	//set new window station and desktop to this process in order the son process will inherit it
	HDESK original_desktop;
	HWINSTA original_winsta;
	BOOL res = setNewWindowStationAndDesktop(&original_desktop, &original_winsta);

	//create the process with the fully restricted token 
	PWSTR pathTofilePW;
	PROCESS_INFORMATION pi = { 0 };
	convertcharArrToPWSTR(pathToFile, &pathTofilePW);
	CreateProcessWithExplicitTokenSuspended(pathTofilePW, primaryToken, &pi);

	//initialize the process with impersonation token
	DuplicateToken(impersonateToken,
		SecurityImpersonation,
		&impersonation_token);
	initializeProcessWithImpersonationToken(pi, impersonation_token);

	//assign the new process to this job
	HANDLE job = CreateRestrictedJobObject();
	if (job == INVALID_HANDLE_VALUE) {
		return FALSE;
	}

	if (!AssignProcessToJobObject(job, pi.hProcess)) {
		ErrorExit(L"Could not assign process to a job");
	}

	

	//load our dll into process memory

	//resumeprocess
	ResumeThread(pi.hThread);
 
	
	

	//wrap with job, put in another desktop, set IPC and so on..
	
	return TRUE;
}


int main()
{
	//char * str = "C:\\Users\\itai marts\\Desktop\\Cyber2\\hw2\\Sandbox\\programUsingSandbox\\Debug\\programUsingSandbox.exe";
	char * str = "C:\\Users\\itai marts\\Desktop\\Cyber2\\hw2\\Sandbox\\target_program\\\Debug\\target_program.exe";
	//create and run the low process
	runProcessAsUntrusted(str);
	Sleep(50000);
	
	 

	return 0;
}


