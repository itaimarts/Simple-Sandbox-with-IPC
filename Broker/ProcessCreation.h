#pragma once

BOOL CreateProcessWithExplicitTokenSuspended(
	__in PWSTR pszCommandLine,
	__in HANDLE token,
	__in LPWSTR fullDesktop_name,
	__out PROCESS_INFORMATION * pi);

HANDLE CreateRestrictedJobObject();

BOOL initializeProcessWithImpersonationToken(PROCESS_INFORMATION pi, HANDLE impersonationToken);

BOOL setNewWindowStationAndDesktop();


