#include "stdafx.h"
#include "TokenUtils.h"




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