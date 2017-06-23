#pragma once


#define BUFFER_SIZE		4096 // 4K bytes
#define OK_BUTTON (100)



enum TypeMsg { createWindowEx, createFile };

struct createWindowExMsg {
	TypeMsg type;
	TCHAR	text[BUFFER_SIZE];
};

struct createFileMsg {
	TypeMsg  type;
	char	data[256];
};



class IPC {

	private:
		HINSTANCE hInstance;
		PWSTR pCmdLine;
		int nCmdShow;


	public:
		//fields
		HANDLE brokerToTargetRead;
		HANDLE brokerToTargetWrite;
		HANDLE targetToBrokerRead;
		HANDLE targetToBrokerWrite;

	

		//methods
		IPC(HINSTANCE hInstance, PWSTR pCmdLine, int nCmdShow);
		bool handleMsgFromTarget(void* rawMsg);
		bool writeToTarget(char* msg, size_t msgLen);
		bool handleCreateWindowExMsg(struct createWindowExMsg * rawMsg);
		bool initIPC();
		bool loop();
		int createWindow(HINSTANCE hInstance, PWSTR message, int nCmdShow);
		//LRESULT CALLBACK IPC::WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
};

