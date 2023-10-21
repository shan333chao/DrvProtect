#include "CommR3.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "../../SSS_Drivers/ERROR_CODE.h"
#include "../log.h"
 


 


 
//hook通讯
DWORD HookComm(ULONG type, PVOID inData, ULONG inSize)
{
 
	//srand(time(NULL));
	//int seed = rand() % 4;
	COMM_DATA commData = { 0 };
	commData.Type = type;
	commData.InData = (ULONG64)inData;
	commData.InDataLen = inSize;
	commData.ID = COMM_ID;

	LPARAM res= SetMessageExtraInfo(&commData);
 
	Logp("通讯结果 %08x \n", res);
	return res ? commData.status : STATUS_OP_UNSUCCESS;
}