#include "Comm/CommR3.h"
#include <stdio.h>
#include "Example.h"
#define _CRT_SECURE_NO_WARNINGS
void ShowFunc() {
	printf("----------------------------------------\n");
	printf("\t0->  ����ͨѶ\n");
	printf("\t1->  ����αװ\n");
	printf("\t2->  ���ش��ڲ�����ͼ\n");
	printf("\t3->  �ڴ��ȡ\n");
	printf("\t4->  �ڴ�д��\n");
	printf("\t5->  �����ڴ��ȡ\n");
	printf("\t6->  �����ڴ�д��\n");
	printf("\t7->  ��ѯ����ģ��\n");
	printf("\t14->  ��ѯ����ģ��(�����ӽ���)\n");
	printf("\t8->  ���������ڴ�\n");
	printf("\t9->  �����߳�\n");
	printf("\t10-> ��ѯ����VADģ��(�����ӽ���)\n");
	printf("\t11-> ��ӽ��̱���\n");
	printf("\t12-> �Ƴ����̱���\n");
	printf("\t13-> ���������� \n");
	printf("\t15-> ��ģ�����߳�ע��DLL \n");
	printf("\t16-> ���߳�call(�����ӽ������߳�) \n");
	printf("\t17-> �ں�����DLL \n");
	printf("\t88-> �˳�\n");
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
	//�ж��ַ��������Ƿ�Ϊ����
	if (0 != Len % 2)
	{
		OutputBuff[count++] = ((*p > '9') && (*p <= 'F') || (*p <= 'f')) ? *p - 48 - 7 : *p - 48;
	}

	return Len / 2 + Len % 2;
}
int main() {
	SetConsoleTitleA("������������չʾ");
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
	printf("������Ҫִ�еĲ���\n");
	char code = 0;
	scanf_s("%d", &code);
	switch (code)
	{
	case 0: {
		printf("�����뿨�ܣ�\n");
		char cardcode[0x1000] = { 0 };
		scanf_s("%s", cardcode, 0x1000);
		ULONG len = StringToBuff(cardcode, buffer);
		TestComm(buffer, len);
		break;
	}
	case 1: {
		printf("����Ҫ�����Ľ���id��\n");
		scanf_s("%d", &pid);
		printf("����Ҫαװ�Ľ���id��\n");
		scanf_s("%d", &fakeId);
		ProtectProcess(pid, fakeId);
		break;
	}

	case 2: {
		printf("����Ҫ�����Ĵ��ھ��(HEX)��\n");
		scanf_s("%08x", &hwnd);
		ProtectWindow(hwnd);
		break;
	}

	case 3:
	{
		printf("����Ҫ��ȡ�Ľ���id��\n");
		scanf_s("%d", &pid);
		printf("�������ȡ��ַ��\n");
		scanf_s("%llx", &Address);
		printf("�������ȡ���ȣ�\n");
		scanf_s("%d", &uDataSize);
		FakeReadMemory(pid, fakeMemoryPid, Address, uDataSize);
		break;
	}

	case 4: {
		memset(buffer, 0, USN_PAGE_SIZE);
		printf("����Ҫд��Ľ���id��\n");
		scanf_s("%d", &pid);
		printf("�������ַ��\n");
		scanf_s("%llx", &Address);
		printf("������Ҫд�������(HEX)��\n");
		char shellcode[0x1000] = { 0 };
		scanf_s("%s", shellcode, 0x1000);
		ULONG len = StringToBuff(shellcode, buffer);
		FakeWriteMemory(pid, fakeMemoryPid, Address, buffer, len);
		memset(buffer, 0, USN_PAGE_SIZE);
		break;
	}
	case 5: {
		printf("����Ҫ��ȡ�Ľ���id��\n");
		scanf_s("%d", &pid);
		printf("�������ַ��\n");
		scanf_s("%llx", &Address);
		printf("�������ȡ���ȣ�\n");
		scanf_s("%d", &uDataSize);
		PhyReadMemory(pid, Address, uDataSize);
		break;
	}


	case 6: {
		memset(buffer, 0, USN_PAGE_SIZE);
		printf("����Ҫд��Ľ���id��\n");
		scanf_s("%d", &pid);
		printf("�������ַ��\n");
		scanf_s("%llx", &Address);
		printf("������д������(HEX)��\n");
		char shellcode[0x1000] = { 0 };
		scanf_s("%s", shellcode, 0x1000);
		ULONG len = StringToBuff(shellcode, buffer);
		PhyWriteMemory(pid, Address, buffer, len);
		memset(buffer, 0, USN_PAGE_SIZE);
		break;
	}
	case 7: {
		printf("�����ѯ�Ľ���id��\n");
		scanf_s("%d", &pid);
		PCHAR ModuleName = VirtualAlloc(NULL, USN_PAGE_SIZE, MEM_COMMIT, PAGE_READWRITE);
		memset(ModuleName, 0, USN_PAGE_SIZE);
		printf("����ģ����(�����ִ�Сд):");
		scanf_s("%s", ModuleName, 0x1000);
		QueryModule(pid, ModuleName, 1);
		memset(ModuleName, 0, sizeof(ModuleName));
		VirtualFree(ModuleName, USN_PAGE_SIZE, MEM_RELEASE);
		break;
	}

	case 8: {
		printf("�������id��\n");
		scanf_s("%d", &pid);
		printf("����������ڴ��С(DEC)��\n");
		scanf_s("%d", &uDataSize);
		AllocateMem(pid, fakeMemoryPid, uDataSize);
		break;
	}
	case 9: {
		printf("�������id��\n");
		scanf_s("%d", &pid);
		printf("��ճ��һ��shellcode(HEX)��\n");
		char shellcode[0x1000] = { 0 };
		scanf_s("%s", shellcode, 0x1000);
		ULONG len = StringToBuff(shellcode, buffer);
		CreateMyThread(pid, fakeId, buffer, len);
		break;
	}
	case 10: {
		printf("�����ѯ�Ľ���id��\n");
		scanf_s("%d", &pid);
		PCHAR ModuleName = VirtualAlloc(NULL, USN_PAGE_SIZE, MEM_COMMIT, PAGE_READWRITE);
		memset(ModuleName, 0, USN_PAGE_SIZE);
		printf("����ģ����(���ִ�Сд):");
		scanf_s("%s", ModuleName, 0x1000);
		QueryVADModule(pid, ModuleName);
		memset(ModuleName, 0, sizeof(ModuleName));
		VirtualFree(ModuleName, USN_PAGE_SIZE, MEM_RELEASE);
		break;
	}
	case 11: {
		printf("�������id��\n");
		scanf_s("%d", &pid);
		ProtectProcessR3(pid, TRUE);
		break;
	}
	case 12: {
		printf("�������id��\n");
		scanf_s("%d", &pid);
		ProtectProcessR3(pid, FALSE);
		break;
	}
	case 13: {
		printf("�����ѯ�Ľ���id��\n");
		scanf_s("%d", &pid);
		PCHAR ModuleName = VirtualAlloc(NULL, USN_PAGE_SIZE, MEM_COMMIT, PAGE_READWRITE);
		memset(ModuleName, 0, USN_PAGE_SIZE);
		printf("����ģ����(���ִ�Сд):");
		scanf_s("%s", ModuleName, 0x1000);

		PCHAR pattern = VirtualAlloc(NULL, USN_PAGE_SIZE, MEM_COMMIT, PAGE_READWRITE);
		memset(pattern, 0, USN_PAGE_SIZE);
		printf("����������(��ʽ:\\x64\\x00\\x00\\x00):");
		scanf_s("%s", pattern, 0x1000);

		PCHAR mask = VirtualAlloc(NULL, USN_PAGE_SIZE, MEM_COMMIT, PAGE_READWRITE);
		memset(mask, 0, USN_PAGE_SIZE);
		printf("����ƥ��ģ��(��ʽ:x??????x??xx??):");
		scanf_s("%s", mask, 0x1000);
		SearchPattern(pid, ModuleName, pattern, mask);
		break;
	}
	case 14: {
		printf("�����ѯ�Ľ���id��\n");
		scanf_s("%d", &pid);
		PCHAR ModuleName = VirtualAlloc(NULL, USN_PAGE_SIZE, MEM_COMMIT, PAGE_READWRITE);
		memset(ModuleName, 0, USN_PAGE_SIZE);
		printf("����ģ����(�ϸ����ִ�Сд):");
		scanf_s("%s", ModuleName, 0x1000);
		QueryModule(pid, ModuleName, 2);
		memset(ModuleName, 0, sizeof(ModuleName));
		VirtualFree(ModuleName, USN_PAGE_SIZE, MEM_RELEASE);
		break;
	}
	case 15: {
		printf("����Ҫע��Ľ���id��\n");
		scanf_s("%d", &pid);
		PCHAR dllFilePath = VirtualAlloc(NULL, USN_PAGE_SIZE, MEM_COMMIT, PAGE_READWRITE);
		memset(dllFilePath, 0, USN_PAGE_SIZE);
		printf("����dll�ļ�·��(�ϸ����ִ�Сд):");
		scanf_s("%s", dllFilePath, 0x1000);
		InjectX64DLL(pid, dllFilePath);
		VirtualFree(dllFilePath, USN_PAGE_SIZE, MEM_RELEASE);
		break;
	}
	case 16: {
		printf("�������id��\n");
		scanf_s("%d", &pid);
		printf("�������ַ��\n");
		scanf_s("%llx", &Address);
		printf("�������ȡ���ȣ�\n");
		scanf_s("%d", &uDataSize);
		void CALL_MAIN_THREAD(pid, Address, uDataSize);
		break;
	}
	case 17: {
		printf("����Ҫע��Ľ���id��\n");
		scanf_s("%d", &pid);
		PCHAR dllFilePath = VirtualAlloc(NULL, USN_PAGE_SIZE, MEM_COMMIT, PAGE_READWRITE);
		memset(dllFilePath, 0, USN_PAGE_SIZE);
		printf("����dll�ļ�·��(�ϸ����ִ�Сд):");
		scanf_s("%s", dllFilePath, 0x1000);
		WriteX64DLL(pid, dllFilePath);
		VirtualFree(dllFilePath, USN_PAGE_SIZE, MEM_RELEASE); 
		break;
	}

	case 88:
		goto EXITSYS;
		break;
	default:
		printf("�������\n");
		break;
	}
	system("pause");
	system("cls");
	goto LOOP;
EXITSYS:

	return 0;

}