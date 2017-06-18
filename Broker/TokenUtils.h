#pragma once

#include <aclapi.h>

#define RESTRICTED_SID					L"S-1-5-12"
#define USERS_SID						L"S-1-5-32-545"
#define LOW_INTEGRITY_LEVEL_SID			L"S-1-16-4096"

BOOL GetTokenGroups(__in	HANDLE hProcToken, __out	PTOKEN_GROUPS* ppTokenGroups);
BOOL GetLogonSID(__in	HANDLE hToken, __out	PSID* ppSid);
BOOL GetSecurityAttributes(HANDLE handle, SECURITY_ATTRIBUTES* attributes);
BOOL SetProcessUntrusted(HANDLE hProcess);

DWORD GetSidsToDisable(
	__out	PSID_AND_ATTRIBUTES SidsToDisable,
	__in	DWORD Bufsize,
	__in	PTOKEN_GROUPS pTokenGroups,
	__in	BOOL fullRestriction);

BOOL SetIntegrityLevel(HANDLE token, BOOL FullRestriction);

HANDLE createRestrictedToken(HANDLE process, BOOL FullRestriction);










