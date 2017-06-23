#include "stdafx.h"
#include "IPC.h"
#include "Utils.h"



HWND textboxIPC;
static TCHAR buffIPC[1024];//find reslt for this !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!


IPC::IPC(HINSTANCE hInstance, PWSTR pCmdLine, int nCmdShow)
{
	this->hInstance = hInstance;
	this->pCmdLine = pCmdLine;
	this->nCmdShow = nCmdShow;
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
	//create the window which user asked for
	createWindow(hInstance, rawMsg->text, nCmdShow);
	
	//create the response from user
	struct createWindowExMsg response;
	response.type = createWindowEx;
	_snwprintf_s(response.text, 1023, L"%s", buffIPC);
	
	//write the response for user
	//writeToTarget((char*)&response, sizeof(struct createWindowExMsg));
	DWORD sended;
	if (!WriteFile(brokerToTargetWrite, &response, sizeof(struct createWindowExMsg), &sended, NULL) || sended != sizeof(struct createWindowExMsg)) {
		ErrorExit(L"writeToTarget");
	}

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


LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg)
	{
		case WM_DESTROY:
		{
			PostQuitMessage(0);
			return 0;
		}
		case WM_PAINT:
		{
			PAINTSTRUCT ps;
			HDC hdc = BeginPaint(hwnd, &ps);

			FillRect(hdc, &ps.rcPaint, (HBRUSH)(COLOR_WINDOW + 1));

			EndPaint(hwnd, &ps);
			break;
		}

		case WM_COMMAND:
		{
			if (wParam == OK_BUTTON)
			{
				GetWindowText(textboxIPC, buffIPC, 1024);
				PostQuitMessage(0);
				return 1;
			}
			break;

			return 0;
		}

	}
	return DefWindowProc(hwnd, uMsg, wParam, lParam);
}


int IPC::createWindow(HINSTANCE hInstance, PWSTR message, int nCmdShow) {
	// Register the window class.
	const LPCWSTR CLASS_NAME = L"WINDOW";

	WNDCLASS wc = {};

	wc.lpfnWndProc = WindowProc;
	wc.hInstance = hInstance;
	wc.lpszClassName = CLASS_NAME;

	RegisterClass(&wc);

	// Create the window.
	HWND hwnd = CreateWindowEx(
		0,                              // Optional window styles.
		CLASS_NAME,                     // Window class
		L"Sandboxed program asked you to answer",    // Window text
		WS_OVERLAPPEDWINDOW,            // Window style

										// Size and position
		CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,

		NULL,       // Parent window    
		NULL,       // Menu
		hInstance,  // Instance handle
		NULL        // Additional application data
	);

	if (hwnd == NULL)
	{
		return 0;
	}
	textboxIPC = CreateWindow(L"Edit", message, WS_BORDER | WS_CHILD | WS_VISIBLE | ES_READONLY, 56, 10, 300, 18, hwnd, 0, 0, 0);
	textboxIPC = CreateWindow(L"EDIT", 0, WS_BORDER | WS_CHILD | WS_VISIBLE, 56, 40, 300, 50, hwnd, 0, 0, 0);
	CreateWindow(L"BUTTON", L"Send", WS_CHILD | WS_VISIBLE, 70, 90, 80, 25, hwnd, (HMENU)OK_BUTTON, 0, 0);

	ShowWindow(hwnd, nCmdShow);

	// Run the message loop.

	MSG msg = {};
	while (GetMessage(&msg, NULL, 0, 0))
	{
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}

	return 0;
}
