#include "stdafx.h"

void convertcharArrToPWSTR(char * src, PWSTR * tar) {
	int count = 0;
	count = MultiByteToWideChar(CP_ACP, 0, src, strlen(src), NULL, 0);
	if (count > 0)
	{
		*tar = SysAllocStringLen(0, count);
		MultiByteToWideChar(CP_ACP, 0, src, strlen(src), *tar, count);
	}
}



void ErrorExit(LPTSTR lpszFunction)
{
	// Retrieve the system error message for the last-error code

	LPVOID lpMsgBuf;
	LPVOID lpDisplayBuf;
	DWORD dw = GetLastError();

	FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		dw,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR)&lpMsgBuf,
		0, NULL);

	// Display the error message and exit the process

	lpDisplayBuf = (LPVOID)LocalAlloc(LMEM_ZEROINIT,
		(lstrlen((LPCTSTR)lpMsgBuf) + lstrlen((LPCTSTR)lpszFunction) + 40) * sizeof(TCHAR));
	StringCchPrintf((LPTSTR)lpDisplayBuf,
		LocalSize(lpDisplayBuf) / sizeof(TCHAR),
		TEXT("%s failed with error %d: %s"),
		lpszFunction, dw, lpMsgBuf);
	MessageBox(NULL, (LPCTSTR)lpDisplayBuf, TEXT("Error"), MB_OK);

	LocalFree(lpMsgBuf);
	LocalFree(lpDisplayBuf);
	ExitProcess(dw);
}

char * GetWindowObjectName(HANDLE handle) {
	// Get the size of the name.
	DWORD size = 0;
	::GetUserObjectInformation(handle, UOI_NAME, NULL, 0, &size);

	if (!size) {
		//NOTREACHED();
		return new char();
	}

	// Create the buffer that will hold the name.
	char *name_buffer = new char[size];
	TCHAR szName[100];
	DWORD dwLen;

	// Query the name of the object.
	if (!::GetUserObjectInformation(handle, UOI_NAME, szName, sizeof(szName), &dwLen)){
		//NOTREACHED();
		return new char();
	}

	return (char *)szName;
}