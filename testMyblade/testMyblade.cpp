#include <Windows.h>
#include <stdio.h>
#include "FuncDef.h"


#ifdef _X86
HMODULE dllModule = LoadLibraryA("SSS_dll_x86.dll");
#else
HMODULE dllModule = LoadLibraryA("SSS_dll_x64.dll");
#endif // WIN32



WriteMemory write_memory = NULL;
ReadMemory read_memory = NULL;
InitReg reg = NULL;
GetProcessIdByName getProcessIdByName = NULL;
FakeProcess fuckProcess = NULL;
ProtectWindow protectWindow = NULL;
AntiSnapShotWindow antiSnapshot = NULL;
AddProtectProcessR3  r3ProcessAccess = NULL;
CreateMyThread createThread = NULL;
AllocateMemmory allocMem = NULL;
GetModuleExportAddr2 getModuleExport2 = NULL;
QueryModule  queryModule = NULL;
GetModuleExportAddr getModuleExport = NULL;
InjectX64DLL inject = NULL;
QueryVADModule queryVad = NULL;
SearchPattern search = NULL;
void InitFuncs() {
	write_memory = (WriteMemory)GetProcAddress(dllModule, "_PhyWriteMemory");
	read_memory = (ReadMemory)GetProcAddress(dllModule, "_PhyReadMemory");
	reg = (InitReg)GetProcAddress(dllModule, "_InitReg");
	getProcessIdByName = (GetProcessIdByName)GetProcAddress(dllModule, "_GetProcessIdByName");
	fuckProcess = (FakeProcess)GetProcAddress(dllModule, "_ProtectProcess");
	protectWindow = (ProtectWindow)GetProcAddress(dllModule, "_ProtectWindow");
	antiSnapshot = (AntiSnapShotWindow)GetProcAddress(dllModule, "_AntiSnapShotWindow");
	r3ProcessAccess = (AddProtectProcessR3)GetProcAddress(dllModule, "_ProtectProcessR3_Add");
	createThread = (CreateMyThread)GetProcAddress(dllModule, "_CreateMyThread");
	allocMem = (AllocateMemmory)GetProcAddress(dllModule, "_AllocateMem");
	getModuleExport2 = (GetModuleExportAddr2)GetProcAddress(dllModule, "_GetModuleExportAddr2");
	queryModule = (QueryModule)GetProcAddress(dllModule, "_QueryModule");
	getModuleExport = (GetModuleExportAddr)GetProcAddress(dllModule, "_GetModuleExportAddr");
	inject = (InjectX64DLL)GetProcAddress(dllModule, "_InjectX64DLL");
	queryVad = (QueryVADModule)GetProcAddress(dllModule, "_QueryVADModule");
	search = (SearchPattern)GetProcAddress(dllModule, "_SearchPattern");

}



VOID ReadMemExample(ULONG pid) {



	PVOID address = (PVOID)0x400000;
	ULONG length = sizeof(ULONG);
	ULONG buffer = 0;
	ULONG ret = read_memory(pid, address, (PVOID)&buffer, length);
	if (!ret)
	{
		printf("读到的数据 %08x \n", buffer);

	}
	else {
		printf("读取出错 错误码%08x \n", ret);
		return;
	}
}



VOID WriteMemExample(ULONG pid) {

	ULONG length = sizeof(ULONG);
	ULONG buffer = 0xccccccc;

	ULONG ret = write_memory(pid, (PVOID)0x400000, (PVOID)&buffer, length);
	if (!ret)
	{
		printf("写入成功 \n");
	}
	else
	{
		printf("写入失败  %08x \n", ret);
	}
}


void RegExample() {


	char code[] = "e120c826168d9828624d13355aa5b9ce8959ed0698ff16efc56ef05388356c1fe6cb16a48afe3a01ba021bb1bd9465b48f96";
	//该方法仅需调用一次
	ULONG ret = reg(code);
 
	if (ret == 0x10000000)
	{
		printf("初始化成功");
	}
	else
	{
		printf("初始化失败 %08x \n", ret);
		return;
	}
}




ULONG GetProcessId(PCHAR name) {

	ULONG pid = 0;
	ULONG ret = getProcessIdByName(name, &pid);
	if (ret)
	{
		printf("getProcessIdByName error %08x \n", ret);
	}
	return pid;
}






void FakeProcessExample() {

	char name[] = "Wub_x64.exe";
	ULONG  protectPid = GetProcessId(name);

	char fakename[] = "die.exe";
	ULONG fakePid = GetProcessId(fakename);

	if (!protectPid || !fakePid)
	{
		printf("进程未找到");
		return;
	}


	ULONG ret = fuckProcess(protectPid, fakePid);
	if (!ret)
	{
		printf("伪装成功");

	}
	else
	{
		printf("伪装失败  错误码 %08x \n", ret);
	}
}


void ProtectWindowExample() {


	HWND hwnd = FindWindowA(NULL, "Windows Update Blocker v1.8");
	if (!hwnd)
	{
		return;
	}
	ULONG ret = protectWindow(HandleToULong(hwnd));
	if (!ret)
	{
		printf("窗口保护成功 \n");
	}
	else
	{
		printf("保护失败 错误码 %08x \n", ret);
	}
}

VOID SetAntiSnapShot() {

	HWND hwnd = FindWindowA(NULL, "Detect It Easy v3.07 [Windows 10 Version 1909](x86_64)");
	if (!hwnd)
	{
		return;
	}
	ULONG ret = antiSnapshot(HandleToULong(hwnd));
	if (!ret)
	{
		printf("窗口保护成功 \n");
	}
	else
	{
		printf("保护失败 错误码 %08x \n", ret);
	}

}




void SetProcessR3Access() {


	ULONG pid = 7240;
	ULONG ret = r3ProcessAccess(pid);
	if (!ret)
	{
		printf("设置进程保护成功 \n");

	}
	else
	{
		printf("保护失败 错误码 %08x \n", ret);
	}
}


void QueryModuleExample() {

	ULONG pid = 8252;
	char moduleName[] = "die.exe";
	ULONG64 moduleBase = 0;
	ULONG moduleSize = 0;
	ULONG type = 1;
	ULONG ret = queryModule(pid, moduleName, &moduleBase, &moduleSize, type);
	if (!ret)
	{
		printf("\t 查询方式%d %s moduleBase 0x%llx moduleSize 0x%08x\n", type, moduleName, moduleBase, moduleSize);
	}
	else
	{
		printf("\t 查询方式%d 模块失败 错误码 %08x \n", type, ret);
	}

	/// <summary>
	/// 查询方式2  无附加进程
	/// </summary>
	type = 2;
	ret = queryModule(pid, moduleName, &moduleBase, &moduleSize, type);
	if (!ret)
	{
		printf("\t 查询方式%d %s moduleBase 0x%llx moduleSize 0x%08x \n", type, moduleName, moduleBase, moduleSize);
	}
	else
	{
		printf("\t 查询方式%d 模块失败 错误码 %08x \n", type, ret);
	}
}


VOID QueryVADModuleExample() {


	ULONG pid = 8252;
	char moduleName[] = "die.exe";
	ULONG64 moduleBase = 0;
	ULONG moduleSize = 0;

	ULONG ret = queryVad(pid, moduleName, &moduleBase, &moduleSize);
	if (!ret)
	{
		printf("\tqueryVad  %s moduleBase 0x%llx moduleSize 0x%08x\n", moduleName, moduleBase, moduleSize);
	}
	else
	{
		printf("\t queryVad模块失败 错误码 %08x \n", ret);
	}
}



ULONG64 AllocMemmoryExample(ULONG pid, ULONG memSize) {


	ULONG64 addr = 0;
	ULONG ret = allocMem(pid, memSize, &addr);
	if (!ret)
	{
		printf("\t申请到的内存地址 %llx \n", addr);
	}
	else
	{
		printf("\t    错误码 %08x \n", ret);
	}
	return addr;
}




void CreateThreadExample() {


	char moduleName[] = "die.exe";

	ULONG pid = GetProcessId(moduleName);
	if (!pid)
	{
		printf("\t进程未找到 \n");
		return;
	}
	ULONG_PTR messageBox = (ULONG64)MessageBoxA;
	//定义shellcode
	UCHAR msgBoxShellcode[] = {
		0x48, 0x83, 0xEC, 0x28,										//sub rsp,0x28
		0x49, 0xC7, 0xC1, 0x01, 0x00, 0x00, 0x00,					//mov r9,0x1
		0x49, 0xC7, 0xC0, 0x02, 0x00, 0x00, 0x00,					//mov r8,0x2
		0x48, 0xC7, 0xC2, 0x03, 0x00, 0x00, 0x00,					//mov rcx,0x4
		0x48, 0xC7, 0xC1, 0x04, 0x00, 0x00, 0x00,					//mov rcx,0x4
		0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	//mov rax,0x12345678123
		0xFF, 0xD0,													//call rax
		0x48, 0x83, 0xC4, 0x28										//add rsp,0x28 
	};
	*(PULONG)(msgBoxShellcode + 34) = messageBox;


	ULONG memSize = 0x1000;
	//申请内存
	ULONG64 addr = 0;
	allocMem(pid, memSize,&addr);
	if (addr==0)
	{
		printf("\t申请内存失败 \n");
		return;
	}



	ULONG length = sizeof(msgBoxShellcode);
	ULONG ret = write_memory(pid, (PVOID)addr, (PVOID)msgBoxShellcode, length);




	ret = createThread(pid, &addr, NULL);
	if (!ret)
	{
		printf("\t创建线程 成功 \n");
	}
	else
	{
		printf("\t 错误码 %08x \n", ret);
	}
}


VOID SearchPatternExample() {


	ULONG pid = 9828;
	char moduleName[] = "die.exe";
	char pattern[] = "\x48\x00\x00\x00\x33\xC9\xFF\x00\x00\x00\x00\x00\x48\x85\xC0\x74\x00\xB9\x00\x00\x00\x00\x66\x39\x08\x75\x00";
	char mask[] = "x???xxx?????xxxx?x????xxxx?";
	ULONG64 addr = 0;
	ULONG ret = search(pid, moduleName, pattern, mask, &addr);
	if (!ret)
	{
		printf("\t搜索特征成功 0x%llx \n", addr);
	}
	else
	{
		printf("\t特征搜索失败  %08x \n", ret);
	}
}



VOID InjectX64DllExample() {


	ULONG pid = 0;
	char moduleName[] = "x64dbg.exe";
	pid = GetProcessId(moduleName);
	if (!pid)
	{
		printf("\t进程未找到 0x%llx \n", pid);
		return;
	}
	char dllPath[] = "c:\\MyInject.dll";
	ULONG ret = inject(pid, dllPath, 3);
	if (!ret)
	{
		printf("\t 注入成功！ \n");
	}
	else
	{
		printf("注入失败 %08x \n", ret);
	}
}



VOID GetModuleExportExample() {


	ULONG pid = 0;
	char processName[] = "ida64.exe";
	pid = GetProcessId(processName);
	if (!pid)
	{
		printf("\t进程未找到 0x%llx \n", pid);
		return;
	}
	char moduleName[] = "ida64.dll";
	char exportName[] = "MD5Final";
	ULONG64 funcAddr = 0;
	ULONG ret = getModuleExport(pid, moduleName, exportName, &funcAddr);
	if (!ret)
	{
		printf("\t 查询成功！ 0x%llx \n", funcAddr);
	}
	else
	{
		printf("注入失败 %08x \n", ret);
	}
}



void GetModuleExportExample2() {


	ULONG pid = 0;
	char processName[] = "ida64.exe";

	pid = GetProcessId(processName);
	if (!pid)
	{
		printf("\t进程未找到 0x%llx \n", pid);
		return;
	}


	char moduleName[] = "ida64.dll";
	ULONG64 moduleBase = 0;
	ULONG moduleSize = 0;
	ULONG ret = queryModule(pid, moduleName, &moduleBase, &moduleSize, 2);
	if (ret)
	{
		printf("查询模块失败 %08x \n", ret);
		return;
	}
	char exportName[] = "MD5Final";
	ULONG64 funcAddr = 0;

	ret = getModuleExport2(pid, moduleBase, exportName, &funcAddr);
	if (!ret)
	{
		printf("\t 查询成功！ 0x%llx \n", funcAddr);
	}
	else
	{
		printf("注入失败 %08x \n", ret);
	}

}

int main()
{
	InitFuncs();
	RegExample();

	//char name[] = "InstDrv.exe";
	//ULONG pid = GetProcessId(name);
	//if (!pid)
	//{
	//	return 1;
	//}
	//printf("进程id %d \n", pid);
	//WriteMemExample(pid);
	//ReadMemExample(pid); 
	//FakeProcessExample();
	//ProtectWindowExample();
	//SetAntiSnapShot();
	//SetProcessR3Access();
	//QueryModuleExample();
	//QueryVADModuleExample();
	//AllocMemmoryExample();
	//SearchPatternExample();
	//InjectX64DllExample();
	//GetModuleExportExample();
	//GetModuleExportExample2();
	//CreateThreadExample();
	getchar();


}


