#include "stdafx.h"
#include "IPC.h"
#include "Utils.h"


IPC::IPC()
{
	initIPC();
}


bool IPC::initIPC()
{
	SECURITY_ATTRIBUTES sa;
	ZeroMemory(&sa, sizeof(SECURITY_ATTRIBUTES));
	sa.nLength = sizeof(sa);
	sa.bInheritHandle = TRUE;

	if (!CreatePipe(&brokerToTargetRead, &brokerToTargetWrite, &sa, BUFFER_SIZE)) {
		ErrorExit(L"initIPC");
	}

	if (!CreatePipe(&targetToBrokerRead, &targetToBrokerWrite, &sa, BUFFER_SIZE)) {
		ErrorExit(L"initIPC");
	}

	return true;
}




bool IPC::writeToTarget(char* msg, size_t msgLen)
{
	DWORD sended;

	if (!WriteFile(brokerToTargetWrite, msg, msgLen, &sended, NULL) || sended != msgLen) {
		ErrorExit(L"writeToTarget");
	}

	return true;
}


bool IPC::handleCreateWindowExMsg(struct createWindowExMsg * rawMsg)
{

	HWND hwnd = { 0 };

	HWND hwnd_1 = CreateWindowEx(WS_EX_CLIENTEDGE, L"edit", L"Line one",
		WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_BORDER | ES_LEFT,
		CW_USEDEFAULT, CW_USEDEFAULT, 200, 24,	// x, y, w, h
		hwnd, (HMENU)(123),
		(HINSTANCE)GetWindowLong(hwnd, GWL_HINSTANCE), NULL);

	//wchar_t * msg;
	//MessageBoxW(NULL, msg, L"MsgFromTextBox", MB_OK);

	struct createWindowExMsg response;
	response.type = createWindowEx;
	//response.text = 
	//write the message to target
	
	return true;
}


bool IPC::handleMsgFromTarget(void* rawMsg)
{
	struct createWindowExMsg * msg = (struct createWindowExMsg *) rawMsg;

	switch (msg->type)
	{
	case createWindowEx:
		handleCreateWindowExMsg(msg);
		break;
	}
	return true;
}



bool IPC::loop()
{
	while (1)
	{
		TCHAR  chBuf[BUFFER_SIZE];
		DWORD cbRead;
		bool fSuccess;
		do
		{
			// Read from pipe 
			fSuccess = ReadFile(
				targetToBrokerRead,    // pipe handle 
				chBuf,    // buffer to receive reply 
				BUFFER_SIZE * sizeof(char),  // size of buffer 
				&cbRead,  // number of bytes read 
				NULL);    // not overlapped 

			if (!fSuccess && GetLastError() != ERROR_MORE_DATA)
				break;

			handleMsgFromTarget((void*)chBuf);

		} while (!fSuccess);  // repeat loop if ERROR_MORE_DATA 
	}
}

/*
bool handlers_string(wchar_t* buffer_to_fill)
{

	size_t len_path = wcslen(buffer_to_fill);

	size_t new_size = wsprintf(buffer_to_fill, L"%ls --handlers %lu %lu %lu %lu", buffer_to_fill, brokerToTargetRead, brokerToTargetWrite, targetToBrokerRead, targetToBrokerWrite);

	return ((new_size - len_path) > 0);
}

*/