#include "Comm/CommR3.h"
#include <stdio.h>
#include "Example.h"
 
#define _CRT_SECURE_NO_WARNINGS
void ShowFunc() {
	
	printf("----------------------------------------\n");
	printf("\t0->  测试通讯\n");
	printf("\t1->  进程伪装\n");
	printf("\t2->  保护窗口\n");
	printf("\t3->  反截图\n");
	printf("\t4->  读取内存\n");
	printf("\t6->  写入内存\n");
	printf("\t7->  查询进程模块\n");
	printf("\t14-> 查询进程模块(不附加进程)\n");
	printf("\t8->  创建只读但可执行内存\n");
	printf("\t9->  创建线程\n");
	printf("\t10-> 查询进程VAD模块(不附加进程)\n");
	printf("\t11-> 添加进程保护\n");
	printf("\t12-> 移除进程保护\n");
	printf("\t13-> 特征码搜索 \n");
	printf("\t15-> 注入x64DLL \n");
	printf("\t16-> 主线程call(不附加进程无线程) \n");
	printf("\t17-> 内核拉伸DLL \n");
	printf("\t18-> 获取模块导出函数地址（无附加） \n");
	printf("\t88-> 退出\n");
	printf("----------------------------------------\n");

}
int StringToBuff(char* str, unsigned char* OutputBuff)
{
	char* p = NULL;
	char High = 0;
	char Low = 0;
	int i = 0;
	int Len = 0;
	int count = 0;

	p = str;
	Len = strlen(p);

	while (count < (Len / 2))
	{
		High = ((*p > '9') && ((*p <= 'F') || (*p <= 'f'))) ? *p - 48 - 7 : *p - 48;
		Low = (*(++p) > '9' && ((*p <= 'F') || (*p <= 'f'))) ? *p - 48 - 7 : *p - 48;
		OutputBuff[count] = ((High & 0x0f) << 4 | (Low & 0x0f));
		p++;
		count++;
	}
	//判断字符串长度是否为奇数
	if (0 != Len % 2)
	{
		OutputBuff[count++] = ((*p > '9') && (*p <= 'F') || (*p <= 'f')) ? *p - 48 - 7 : *p - 48;
	}

	return Len / 2 + Len % 2;
}
int main() {
	SetConsoleTitleA("驱动保护功能展示");
	ULONG pid = 0;
	ULONG fakeId = 0;
	ULONG fakeMemoryPid = 0;
	PVOID	Address = 0;
	ULONG		uDataSize = 0;
	ULONG32  hwnd = 0;
	HWND deskHwnd = GetDesktopWindow();
	GetWindowThreadProcessId(deskHwnd, &fakeMemoryPid);

	PUCHAR buffer = VirtualAlloc(NULL, USN_PAGE_SIZE, MEM_COMMIT, PAGE_READWRITE);

LOOP:
	memset(buffer, 0, USN_PAGE_SIZE);
	ShowFunc();
	printf("请输入要执行的操作\n");
	char code = 0;
	scanf_s("%d", &code);
	switch (code)
	{
	case 0: {
		printf("请输入卡密：\n");
		printf("5096324d4c57130ba8a8688bbfa63c2deb2173f0723031c5c2b54096d40a1fa64ce81481b48f387bf2b671fbeed5e7620956\r\n");
		char cardcode[0x1000] = { 0 };
		scanf_s("%s", cardcode, 0x1000); 
		TestComm(cardcode, 0);
		break;
	}
	case 1: {
		printf("输入要保护的进程id：\n");
		scanf_s("%d", &pid);
		printf("输入要伪装的进程id：\n");
		scanf_s("%d", &fakeId);
		ProtectProcess(pid, fakeId);
		break;
	}

	case 2: {
		printf("输入要保护的主窗口句柄(HEX)：\n");
		scanf_s("%d", &hwnd);
		ProtectWindow(hwnd);
		break;
	}

	case 3:
	{
		printf("输入要反截图的主窗口句柄：\n");
		scanf_s("%d", &hwnd);
		AntiSnapShotWindow(hwnd);
		break;
 
	} 
	case 4: {
		printf("输入要读取的进程id：\n");
		scanf_s("%d", &pid);
		printf("请输入地址：\n");
		scanf_s("%llx", &Address);
		printf("请输入读取长度：\n");
		scanf_s("%d", &uDataSize);
		PhyReadMemory(pid, Address, uDataSize);
		break;
	}


	case 6: {
		memset(buffer, 0, USN_PAGE_SIZE);
		printf("输入要写入的进程id：\n");
		scanf_s("%d", &pid);
		printf("请输入地址：\n");
		scanf_s("%llx", &Address);
		printf("请输入写入数据(HEX)：\n");
		char shellcode[0x1000] = { 0 };
		scanf_s("%s", shellcode, 0x1000);
		ULONG len = StringToBuff(shellcode, buffer);
		PhyWriteMemory(pid, Address, buffer, len);
		memset(buffer, 0, USN_PAGE_SIZE);
		break;
	}
	case 7: {
		printf("输入查询的进程id：\n");
		scanf_s("%d", &pid);
		PCHAR ModuleName = VirtualAlloc(NULL, USN_PAGE_SIZE, MEM_COMMIT, PAGE_READWRITE);
		memset(ModuleName, 0, USN_PAGE_SIZE);
		printf("输入模块名(不区分大小写):");
		scanf_s("%s", ModuleName, 0x1000);
		QueryModule(pid, ModuleName, 1);
		memset(ModuleName, 0, sizeof(ModuleName));
		VirtualFree(ModuleName, USN_PAGE_SIZE, MEM_RELEASE);
		break;
	}

	case 8: {
		printf("输入进程id：\n");
		scanf_s("%d", &pid);
		printf("输入申请的内存大小(DEC)：\n");
		scanf_s("%d", &uDataSize);
		AllocateMem(pid,  uDataSize);
		break;
	}
	case 9: {
		printf("输入进程id：\n");
		scanf_s("%d", &pid);
		printf("请粘贴一段shellcode(HEX)：\n");
		char shellcode[0x1000] = { 0 };
		scanf_s("%s", shellcode, 0x1000);
		ULONG len = StringToBuff(shellcode, buffer);
		CreateMyThread(pid, fakeId, buffer, len);
		break;
	}
	case 10: {
		printf("输入查询的进程id：\n");
		scanf_s("%d", &pid);
		PCHAR ModuleName = VirtualAlloc(NULL, USN_PAGE_SIZE, MEM_COMMIT, PAGE_READWRITE);
		memset(ModuleName, 0, USN_PAGE_SIZE);
		printf("输入模块名(不区分大小写):");
		scanf_s("%s", ModuleName, 0x1000);
		QueryVADModule(pid, ModuleName);
		memset(ModuleName, 0, sizeof(ModuleName));
		VirtualFree(ModuleName, USN_PAGE_SIZE, MEM_RELEASE);
		break;
	}
	case 11: {
		printf("输入进程id：\n");
		scanf_s("%d", &pid);
		ProtectProcessR3(pid, TRUE);
		break;
	}
	case 12: {
		printf("输入进程id：\n");
		scanf_s("%d", &pid);
		ProtectProcessR3(pid, FALSE);
		break;
	}
	case 13: {
		printf("输入查询的进程id：\n");
		scanf_s("%d", &pid);
		PCHAR ModuleName = VirtualAlloc(NULL, USN_PAGE_SIZE, MEM_COMMIT, PAGE_READWRITE);
		memset(ModuleName, 0, USN_PAGE_SIZE);
		printf("输入模块名(区分大小写):");
		scanf_s("%s", ModuleName, 0x1000);

		PCHAR pattern = VirtualAlloc(NULL, USN_PAGE_SIZE, MEM_COMMIT, PAGE_READWRITE);
		memset(pattern, 0, USN_PAGE_SIZE);
		printf("输入特征码(格式:\\x64\\x00\\x00\\x00):");
		scanf_s("%s", pattern, 0x1000);

		PCHAR mask = VirtualAlloc(NULL, USN_PAGE_SIZE, MEM_COMMIT, PAGE_READWRITE);
		memset(mask, 0, USN_PAGE_SIZE);
		printf("输入匹配模板(格式:x??????x??xx??):");
		scanf_s("%s", mask, 0x1000);
		SearchPattern(pid, ModuleName, pattern, mask);

		VirtualFree(mask, USN_PAGE_SIZE, MEM_RELEASE);
		VirtualFree(pattern, USN_PAGE_SIZE, MEM_RELEASE);
		VirtualFree(ModuleName, USN_PAGE_SIZE, MEM_RELEASE);
		break;
	}
	case 14: {
		printf("输入查询的进程id：\n");
		scanf_s("%d", &pid);
		PCHAR ModuleName = VirtualAlloc(NULL, USN_PAGE_SIZE, MEM_COMMIT, PAGE_READWRITE);
		memset(ModuleName, 0, USN_PAGE_SIZE);
		printf("输入模块名(严格区分大小写):");
		scanf_s("%s", ModuleName, 0x1000);
		QueryModule(pid, ModuleName, 2);
		memset(ModuleName, 0, sizeof(ModuleName));
		VirtualFree(ModuleName, USN_PAGE_SIZE, MEM_RELEASE);
		break;
	}
	case 15: {
		printf("输入要注入的进程id：\n");
		scanf_s("%d", &pid);
		PCHAR dllFilePath = VirtualAlloc(NULL, USN_PAGE_SIZE, MEM_COMMIT, PAGE_READWRITE);
		memset(dllFilePath, 0, USN_PAGE_SIZE);
		printf("输入dll文件路径(严格区分大小写):");
		scanf_s("%s", dllFilePath, 0x1000);
		UCHAR type = 0;
		printf("输入启动方式 1 createthread  2 hijack rip  3 insert apc ：\n");
		scanf_s("%d", &type);
		InjectX64DLL(pid, dllFilePath, type);
		VirtualFree(dllFilePath, USN_PAGE_SIZE, MEM_RELEASE);
		break;
	}
	case 16: {
		printf("输入进程id：\n");
		scanf_s("%d", &pid);
		printf("shellcode地址：\n");
		scanf_s("%llx", &Address);
		printf("shellcode长度：\n");
		scanf_s("%d", &uDataSize);
		void CALL_MAIN_THREAD(pid, Address, uDataSize);
		break;
	}
	case 17: {
		printf("输入要注入的进程id：\n");
		scanf_s("%d", &pid);
		PCHAR dllFilePath = VirtualAlloc(NULL, USN_PAGE_SIZE, MEM_COMMIT, PAGE_READWRITE);
		memset(dllFilePath, 0, USN_PAGE_SIZE);
		printf("输入dll文件路径(严格区分大小写):");
		scanf_s("%s", dllFilePath, 0x1000);
		WriteX64DLL(pid, dllFilePath);
		VirtualFree(dllFilePath, USN_PAGE_SIZE, MEM_RELEASE);
		break;
	}
	case 18: {
		printf("输入查询的进程id：\n");
		scanf_s("%d", &pid);
		PCHAR ModuleName = VirtualAlloc(NULL, USN_PAGE_SIZE, MEM_COMMIT, PAGE_READWRITE);
		memset(ModuleName, 0, USN_PAGE_SIZE);
		printf("输入模块名(区分大小写):");
		scanf_s("%s", ModuleName, 0x1000);
		PCHAR exportName = VirtualAlloc(NULL, USN_PAGE_SIZE, MEM_COMMIT, PAGE_READWRITE);
		memset(exportName, 0, USN_PAGE_SIZE);
		printf("输入导出方法名(区分大小写):");
		scanf_s("%s", exportName, 0x1000);
		GetModuleExportAddr(pid, ModuleName, exportName);

		VirtualFree(exportName, USN_PAGE_SIZE, MEM_RELEASE);
		VirtualFree(ModuleName, USN_PAGE_SIZE, MEM_RELEASE);

		break;
	}
 
	case 88:
		goto EXITSYS;
		break;
	default:
		printf("输入错误\n");
		break;
	}
	system("pause");
	system("cls");
	goto LOOP;
EXITSYS:

	return 0;

}