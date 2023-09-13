#include "Comm.h"




namespace communicate {


	PDRIVER_OBJECT			pDriverObject = 0;
	PULONG64				pImp = 0;
	PDRIVER_DISPATCH				pOriginIRP_MJ_DEVICE_CONTROL = 0;
	extern POBJECT_TYPE* IoDriverObjectType = NULL;
	CommCallBack gCommCallback = NULL;





	BOOLEAN UnComm() {
		//判断通讯状态
		if (!pImp)
		{
			Log("[SSS]IofCompleteRequest not Found \r\n");
			return FALSE;
		}
		pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = pOriginIRP_MJ_DEVICE_CONTROL;

		ULONG64 originFunc = imports::imported.iof_complete_request;
		//替换导入地址
		PHYSICAL_ADDRESS pICRAddr = imports::mm_get_physical_address(pImp);
		if (!pICRAddr.QuadPart)
		{
			Log("[SSS]imports::mm_get_physical_address failed %p \r\n", pImp);
			return FALSE;
		}
		PULONG64 pImpPhy = (PULONG64)imports::mm_map_io_space(pICRAddr, 0x8, MmCached);
		if (!pImpPhy)
		{
			Log("[SSS]MmMapIoSpace failed %p \r\n", pImp);
			return FALSE;
		}

		*pImpPhy = originFunc;
		imports::mm_unmap_io_space(pImpPhy, 0x8);
		gCommCallback = NULL;
		return TRUE;
	}

	void FASTCALL MyIofCompleteRequest(PIRP pIrp, CCHAR PriorityBoost) {
		Log("[SSS]MyIofCompleteRequest");

		PCOMM_DATA  commData = (PCOMM_DATA)pIrp->AssociatedIrp.SystemBuffer;

		if (imports::mm_is_address_valid(commData) && imports::mm_is_address_valid(commData + 7) && gCommCallback)
		{
			if (commData->ID == COMM_ID)
			{
				NTSTATUS status = gCommCallback(commData);
				commData->status = status;
				pIrp->IoStatus.Information = 0;
				pIrp->IoStatus.Status = status;
			}
		}
		imports::iof_complete_request(pIrp, PriorityBoost);
	}


	NTSTATUS RegisterComm(CommCallBack callBack) {
		UNICODE_STRING			serviceName = { 0 };  //驱动的服务名
		PHYSICAL_ADDRESS		pICRAddr = { 0 };
		PUCHAR					pFunc = NULL;
		PULONG64				pImpPhy = NULL;
		NTSTATUS				status = NULL;
		PFILE_OBJECT			pFileObjcet = NULL;
		PDEVICE_OBJECT			pDeviceObject = NULL;

		imports::rtl_init_unicode_string(&serviceName, skCrypt(L"\\Device\\Null"));
		status = imports::io_get_device_object_pointer(&serviceName, FILE_ALL_ACCESS, &pFileObjcet, &pDeviceObject);
		if (!NT_SUCCESS(status))
		{
			Log("[SSS]IoGetDeviceObjectPointer not Found \r\n");
			return STATUS_UNSUCCESSFUL;
		}
		pDriverObject = pDeviceObject->DriverObject;
		pOriginIRP_MJ_DEVICE_CONTROL = pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL];
		pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = pDriverObject->MajorFunction[IRP_MJ_CLOSE];
		pFunc = (PUCHAR)pDriverObject->MajorFunction[IRP_MJ_CLOSE];
		DbgBreakPoint();
		UCHAR sig1 = 0xffu;
		UCHAR sig2 = 0x15u;
		if (Utils::InitOsVersion().dwBuildNumber >= 22000)
		{
			sig1 = 0xe8u;
			sig2 = 0x02u;
		}
		for (size_t i = 0; i < 0x100; i++)
		{
			if (pFunc[i] == sig1 && pFunc[i + 1] == sig2)
			{

				LONG64 lOffset = 0;
				ULONG64 uNextLine = 0;
				if (sig1 == 0xe8u)
				{
					lOffset = *(PLONG32)(pFunc + i + 1);
					uNextLine = (ULONG64)(pFunc + i + 5);
				}
				else {
					lOffset = *(PLONG32)(pFunc + i + 2);
					uNextLine = (ULONG64)(pFunc + i + 6);
				}

			
				pImp = (PULONG64)(lOffset + uNextLine);
				break;
			}
		}
		if (!pImp)
		{
			Log("[SSS]IofCompleteRequest not Found \r\n");
			return STATUS_UNSUCCESSFUL;
		}
		//替换导入地址
		pICRAddr = imports::mm_get_physical_address(pImp);
		if (!pICRAddr.QuadPart)
		{
			Log("[SSS]imports::mm_get_physical_address failed %p \r\n", pImp);
			return STATUS_UNSUCCESSFUL;
		}
		if (Utils::InitOsVersion().dwBuildNumber >= 22000)
		{
			pImpPhy = (PULONG64)imports::mm_map_io_space(pICRAddr, 0x8, MmCached);
		}
		else {
			pImpPhy = (PULONG64)imports::mm_map_io_space_ex(pICRAddr, 0x8, PAGE_READWRITE);;
		
		} 
		if (!pImpPhy)
		{
			Log("[SSS]MmMapIoSpace failed %p \r\n", pImp);
			return STATUS_UNSUCCESSFUL;
		}
		*pImpPhy = (ULONG64)MyIofCompleteRequest;
		imports::mm_unmap_io_space(pImpPhy, 0x8);
		gCommCallback = callBack;
		Log("[SSS]Communicate build %p \r\n", pImp);
		return  STATUS_SUCCESS;

	}



}
