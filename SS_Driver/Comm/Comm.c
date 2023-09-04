#include "Comm.h"
#include "../Tools/Log.h"


PDRIVER_OBJECT			pDriverObject = 0;
PULONG64				pImp = 0;
PULONG64				pOriginIRP_MJ_DEVICE_CONTROL = 0;
extern POBJECT_TYPE* IoDriverObjectType;
CommCallBack gCommCallback = NULL;

#define DEVICE_NAME  L"\\Device\\Null"
BOOLEAN UnComm() {
	//判断通讯状态
	if (!pImp)
	{
		Log( "[SSS]IofCompleteRequest not Found \r\n");
		return;
	}
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = pOriginIRP_MJ_DEVICE_CONTROL;
	UNICODE_STRING uIofCompleteRequest = { 0 };
	RtlInitUnicodeString(&uIofCompleteRequest, L"IofCompleteRequest");
	ULONG64 originFunc = (ULONG64)MmGetSystemRoutineAddress(&uIofCompleteRequest);
	//替换导入地址
	PHYSICAL_ADDRESS pICRAddr = MmGetPhysicalAddress(pImp);
	if (!pICRAddr.QuadPart)
	{
		Log( "[SSS]MmGetPhysicalAddress failed %p \r\n", pImp);
		return FALSE;
	}
	PULONG64 pImpPhy = MmMapIoSpace(pICRAddr, 0x8, MmCached);
	if (!pImpPhy)
	{
		Log( "[SSS]MmMapIoSpace failed %p \r\n", pImp);
		return FALSE;
	}

	*pImpPhy = originFunc;
	MmUnmapIoSpace(pImpPhy, 0x8);
	gCommCallback = NULL;
	return TRUE;
}

void FASTCALL MyIofCompleteRequest(PIRP pIrp, CCHAR PriorityBoost) {
	Log( "[SSS]MyIofCompleteRequest");

	PCOMM_DATA  commData = (PCOMM_DATA)pIrp->AssociatedIrp.SystemBuffer;

	if (MmIsAddressValid(commData) && MmIsAddressValid(commData + 7) && gCommCallback)
	{
		if (commData->ID == COMM_ID)
		{
			NTSTATUS status = gCommCallback(commData);
			commData->status = status;
			pIrp->IoStatus.Information = 0;
			pIrp->IoStatus.Status = status;
		}
	}
	IoCompleteRequest(pIrp, PriorityBoost);
}


NTSTATUS RegisterComm(CommCallBack callBack) {
	UNICODE_STRING			serviceName = { 0 };  //驱动的服务名
	PHYSICAL_ADDRESS		pICRAddr = { 0 };
	PUCHAR					pFunc = NULL;
	PULONG64				pImpPhy = NULL;
	NTSTATUS				status = NULL;
	PFILE_OBJECT			pFileObjcet = NULL;
	PDEVICE_OBJECT			pDeviceObject = NULL;
	RtlInitUnicodeString(&serviceName, DEVICE_NAME);
	status = IoGetDeviceObjectPointer(&serviceName, FILE_ALL_ACCESS, &pFileObjcet, &pDeviceObject);
	if (!NT_SUCCESS(status))
	{
		Log( "[SSS]IoGetDeviceObjectPointer not Found \r\n");
		return STATUS_UNSUCCESSFUL;
	}
	pDriverObject = pDeviceObject->DriverObject;
	pOriginIRP_MJ_DEVICE_CONTROL = pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL];
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = pDriverObject->MajorFunction[IRP_MJ_CLOSE];
	pFunc = (PUCHAR)pDriverObject->MajorFunction[IRP_MJ_CLOSE];
	for (size_t i = 0; i < 0x100; i++)
	{
		if (pFunc[i] == 0xff && pFunc[i + 1] == 0x15)
		{
			LONG64 lOffset = *(PLONG32)(pFunc + i + 2);
			ULONG64 uNextLine = (ULONG64)(pFunc + i + 6); 
			pImp = (PULONG64)(lOffset + uNextLine); 
			break;
		}
	}
	if (!pImp)
	{
		Log( "[SSS]IofCompleteRequest not Found \r\n");
		return STATUS_UNSUCCESSFUL;
	}
	//替换导入地址
	pICRAddr = MmGetPhysicalAddress(pImp);
	if (!pICRAddr.QuadPart)
	{
		Log( "[SSS]MmGetPhysicalAddress failed %p \r\n", pImp);
		return STATUS_UNSUCCESSFUL;
	}
	pImpPhy = MmMapIoSpace(pICRAddr, 0x8, MmCached);
	if (!pImpPhy)
	{
		Log( "[SSS]MmMapIoSpace failed %p \r\n", pImp);
		return STATUS_UNSUCCESSFUL;
	}
	*pImpPhy = MyIofCompleteRequest;
	MmUnmapIoSpace(pImpPhy, 0x8);
	gCommCallback = callBack;
	Log( "[SSS]Communicate build %p \r\n", pImp);
	return  STATUS_SUCCESS;

}

 