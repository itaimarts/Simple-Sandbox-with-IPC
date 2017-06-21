#pragma once


#define BUFFER_SIZE		4096 // 4K bytes


enum TypeMsg { createWindowEx, createFile };

struct createWindowExMsg {
	TypeMsg type;
	char	text[BUFFER_SIZE];
};

struct createFileMsg {
	TypeMsg  type;
	char	data[256];
};



class IPC {

	private:
		
	public:
		//fields
		HANDLE brokerToTargetRead;
		HANDLE brokerToTargetWrite;
		HANDLE targetToBrokerRead;
		HANDLE targetToBrokerWrite;

		//methods
		IPC();
		bool handleMsgFromTarget(void* rawMsg);
		bool writeToTarget(char* msg, size_t msgLen);
		bool handleCreateWindowExMsg(struct createWindowExMsg * rawMsg);
		bool initIPC();
		bool loop();
};

