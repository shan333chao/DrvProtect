#pragma once
#include <ntifs.h>
#include "CommStructs.h"


typedef VOID (FASTCALL* MyCompleteRequest)( 	_In_ PIRP Irp, 	_In_ CCHAR PriorityBoost);
typedef NTSTATUS(NTAPI* CommCallBack)(PCOMM_DATA pCommData);
void FASTCALL MyIofCompleteRequest(PIRP Irp, CCHAR PriorityBoost);

BOOLEAN UnComm();

NTSTATUS RegisterComm(CommCallBack callBack);