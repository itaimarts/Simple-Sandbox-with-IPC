#include "stdafx.h"
#include "TokenUtils.h"
#include "Utils.h"




BOOL GetTokenGroups(
	__in	HANDLE hProcToken,
	__out	PTOKEN_GROUPS* ppTokenGroups)
{
	DWORD bufsize = 0;
	DWORD bufsize2 = 0;

	/// Never trust anything from the user
	if (ppTokenGroups == NULL)
	{
		SetLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	/// We need to allocate a buffer for the groups, 
	if (GetTokenInformation(hProcToken, TokenGroups, NULL, 0, &bufsize) || GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
		return FALSE;
	}

	*ppTokenGroups = (TOKEN_GROUPS*)GlobalAlloc(GPTR, bufsize);
	if ((*ppTokenGroups) == NULL)
	{
		return FALSE;
	}
	return GetTokenInformation(hProcToken, TokenGroups, *ppTokenGroups, bufsize, &bufsize2);
}





BOOL GetLogonSID(
	__in	HANDLE hToken,
	__out	PSID* ppSid)
{
	BOOL bSuccess = FALSE;
	DWORD dwIndex = 0;
	DWORD dwLength = 0;
	PTOKEN_GROUPS ptgrp = NULL;
	LPTSTR pSid = L"";

	/// Get the required buffer size and allocate the TOKEN_GROUPS buffer.
	if (!GetTokenInformation(
		hToken,					/// handle to the access token
		TokenGroups,			/// get information about the token's groups
		(LPVOID)ptgrp,			/// pointer to TOKEN_GROUPS buffer
		0,                      /// size of buffer
		&dwLength				/// receives required buffer size
	))
	{
		if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
		{
			/// allocate buffer, re-allocate...
			ptgrp = (PTOKEN_GROUPS)GlobalAlloc(GPTR, dwLength);
		}
		if (ptgrp == NULL)
		{
			//SetError(L"Failed to allocate heap for process's groups", GetLastError());
			return FALSE;
		}
	}

	ZeroMemory(ptgrp, dwLength);
	/// Get the token group information from the access token.
	if (!GetTokenInformation(
		hToken,				/// handle to the access token
		TokenGroups,		/// get information about the token's groups
		(LPVOID)ptgrp,		/// pointer to TOKEN_GROUPS buffer
		dwLength,			/// size of buffer
		&dwLength			/// receives required buffer size
	))
	{
		//SetError(L"Could not load process groups", GetLastError());
		return FALSE;
	}

	/// Loop through the groups to find the logon SID.
	for (dwIndex = 0; dwIndex < ptgrp->GroupCount; dwIndex++) {
		if ((ptgrp->Groups[dwIndex].Attributes & SE_GROUP_LOGON_ID) == SE_GROUP_LOGON_ID)
		{
			dwLength = GetLengthSid(ptgrp->Groups[dwIndex].Sid);
			(*ppSid) = (PSID)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwLength);
			if ((*ppSid) == 0) {
				//SetError(L"Failed to allocate memory for the SID", GetLastError());
				return FALSE;
			}
			if (!CopySid(dwLength, (*ppSid), ptgrp->Groups[dwIndex].Sid))  // Source
			{
				//SetError(L"Failed to copy the SID", GetLastError());
				return FALSE;
			}
			break;
		}
	}
	return TRUE;
}








BOOL GetSecurityAttributes(HANDLE handle, SECURITY_ATTRIBUTES* attributes) {
	attributes->bInheritHandle = FALSE;
	attributes->nLength = sizeof(SECURITY_ATTRIBUTES);

	PACL dacl = NULL;
	DWORD result = GetSecurityInfo(handle, SE_WINDOW_OBJECT,
		DACL_SECURITY_INFORMATION, NULL, NULL, &dacl,
		NULL, &attributes->lpSecurityDescriptor);
	if (ERROR_SUCCESS == result)
		return TRUE;

	return FALSE;
}



BOOL SetProcessUntrusted(HANDLE hProcess)
{
	TOKEN_MANDATORY_LABEL tml = { { (PSID)alloca(MAX_SID_SIZE), SE_GROUP_INTEGRITY } };

	ULONG cb = MAX_SID_SIZE;

	HANDLE hToken = 0;

	if (!CreateWellKnownSid(WinUntrustedLabelSid, 0, tml.Label.Sid, &cb) ||
		!OpenProcessToken(hProcess, TOKEN_ADJUST_DEFAULT, &hToken))
	{
		ErrorExit(L"SetProcessUntrusted");
	}

	if (!SetTokenInformation(hToken, TokenIntegrityLevel, &tml, sizeof(tml)))
	{
		ErrorExit(L"SetProcessUntrusted");
	}
	
	if (hToken) {
		CloseHandle(hToken);
	}
	
	return TRUE;
}


DWORD GetSidsToDisable(
	__out	PSID_AND_ATTRIBUTES SidsToDisable,
	__in	DWORD Bufsize,
	__in	PTOKEN_GROUPS pTokenGroups,
	__in	BOOL fullRestriction)
{
	DWORD i;
	DWORD DisableSidCount = 0;
	SID EveryoneSid = { 1, 1, SECURITY_WORLD_SID_AUTHORITY, SECURITY_WORLD_RID };

	/// Firstly check the arguments
	if (SidsToDisable == NULL || pTokenGroups == NULL || Bufsize < pTokenGroups->GroupCount * sizeof(SID_AND_ATTRIBUTES))
	{
		SetLastError(ERROR_INVALID_PARAMETER);
		ErrorExit(L"GetSidsToDisable");
	}

	/// If full restriction we want to disable all the suds without SID LOGON.
	/// else will keep LOGON, EVERYONE and BUILTIN/USERS SIDs and disable all the others
	for (i = 0; i < pTokenGroups->GroupCount; i++)
	{
		SID* pSid = (SID*)pTokenGroups->Groups[i].Sid;

		if (!fullRestriction) {
			// Everyone SID -- continue
			if (EqualSid((PSID)&EveryoneSid, pTokenGroups->Groups[i].Sid)) {
				continue;
			}
			// BUILTIN/USERS SID continue
			if (pSid->SubAuthority[0] == SECURITY_BUILTIN_DOMAIN_RID &&
				pSid->SubAuthority[1] == DOMAIN_ALIAS_RID_USERS)
			{
				continue;
			}
		}
		//  SID LOGON -- continue
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



BOOL SetIntegrityLevel(HANDLE token, BOOL FullRestriction) {

	SID_IDENTIFIER_AUTHORITY MLAuthority = SECURITY_MANDATORY_LABEL_AUTHORITY;
	PSID pIntegritySid = NULL;
	TOKEN_MANDATORY_LABEL tml = { 0 };

	if (FullRestriction) {
		if (!AllocateAndInitializeSid(&MLAuthority, 1, SECURITY_MANDATORY_UNTRUSTED_RID,
			0, 0, 0, 0, 0, 0, 0, &pIntegritySid))
		{
			ErrorExit(L"SetIntegrityLevel");
		}
	}
	else {
		if (!AllocateAndInitializeSid(&MLAuthority, 1, SECURITY_MANDATORY_MEDIUM_RID,
			0, 0, 0, 0, 0, 0, 0, &pIntegritySid))
		{
			ErrorExit(L"SetIntegrityLevel");
		}
	}

	tml.Label.Attributes = SE_GROUP_INTEGRITY;
	tml.Label.Sid = pIntegritySid;

	if (!SetTokenInformation(token, TokenIntegrityLevel, &tml,
		(sizeof(tml) + GetLengthSid(pIntegritySid))))
	{
		ErrorExit(L"SetIntegrityLevel");
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
		ErrorExit(L"createRestrictedToken");
	}

	/// Extract the token's groups
	if (!GetTokenGroups(hProcToken, &pTokenGroups))
	{
		err = GetLastError();
		CloseHandle(hProcToken);
		SetLastError(err);
		ErrorExit(L"createRestrictedToken");
	}

	/// Alocate buffer for the SIDS pretend to disable
	bufsize = pTokenGroups->GroupCount * sizeof(SID_AND_ATTRIBUTES);
	SidsToDisable = (SID_AND_ATTRIBUTES*)GlobalAlloc(GPTR, bufsize);
	if (SidsToDisable == NULL)
	{
		err = GetLastError();
		GlobalFree(pTokenGroups);
		CloseHandle(hProcToken);
		SetLastError(err);
		ErrorExit(L"createRestrictedToken");
	}

	// Get the Sids to disable
	DisableSidCount = GetSidsToDisable(SidsToDisable, bufsize, pTokenGroups, FullRestriction);

	/// Create Restricted SID
	/// If FullRestriction is true then leave only LOGON & RESTRICTED SIDs, 
	/// otherwise leave LOGON, RESTRICTED, EVERYONE, BUILTIN\USERS SIDs.
	RestrictedCount = FullRestriction ? 2 : 4;
	restrictedSids = (SID_AND_ATTRIBUTES*)GlobalAlloc(GPTR, RestrictedCount * sizeof(SID_AND_ATTRIBUTES));
	if (restrictedSids == NULL) {
		err = GetLastError();
		GlobalFree(SidsToDisable);
		GlobalFree(pTokenGroups);
		CloseHandle(hProcToken);
		SetLastError(err);
		ErrorExit(L"createRestrictedToken");
	}

	//add logon sid and  restricted sid to restricted arr
	ZeroMemory(restrictedSids, RestrictedCount * sizeof(SID_AND_ATTRIBUTES));
	ConvertStringSidToSid(RESTRICTED_SID, &(restrictedSids[0].Sid));
	GetLogonSID(hProcToken, &logon);
	restrictedSids[1].Sid = logon;
	
	//in case dont need the full restriction, insert the EVERYONE and builtin users sids to restricted arr
	if (!FullRestriction) {
		restrictedSids[2].Sid = &EveryoneSid;
		ConvertStringSidToSid(USERS_SID, &(restrictedSids[3].Sid));
	}

	if (!CreateRestrictedToken(hProcToken,  /// existing token
		DISABLE_MAX_PRIVILEGE,				/// flags
		DisableSidCount,					/// number of SIDs to disable
		SidsToDisable,						/// array of SID and attributes
		0,									/// number of privileges to drop
		NULL,								/// array of privileges
		RestrictedCount,					/// no restricted SIDs
		restrictedSids,						/// array of restricted SIDs 
		&RestrictedToken)) 
	{
		err = GetLastError();
		GlobalFree(logon);
		GlobalFree(restrictedSids);
		GlobalFree(SidsToDisable);
		GlobalFree(pTokenGroups);
		SetLastError(err);
		ErrorExit(L"createRestrictedToken");
	}

	/// Set integrity level ,untrusted = true, medium = false
	SetIntegrityLevel(RestrictedToken, FALSE);

	return RestrictedToken;
}
