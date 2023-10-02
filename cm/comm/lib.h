#include "CommR3.h"
#include <stdio.h>
#include <windows.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

BOOL InitDriver();
ULONG init(char* regCode);

BOOL FakeReadMemory(ULONG PID, ULONG fakePid, PVOID Address, PVOID buffer, ULONG uDataSize);
BOOL FakeWriteMemory(ULONG		PID, ULONG fakePid, PVOID	Address, PUCHAR pValBuffer,ULONG length);
BOOL PhyReadMemory(ULONG PID, PVOID Address, PVOID buffer, ULONG uDataSize);
BOOL PhyWriteMemory(ULONG		PID, PVOID	Address, PUCHAR		pValBuffer, ULONG length);

//����αװ 
//protectPid �������id
//fakePid Ҫαװ�Ľ���id
BOOL ProtectProcess(ULONG protectPid, ULONG fakePid);

//���ڱ���
//hwnd ���������ھ��
BOOL ProtectWindow(ULONG32 hwnd);


//��PEB �в�ѯģ�� ��ַ��С
//pid ������
//szModuleName ģ����  �������ִ�Сд��
BOOL QueryModule(ULONG pid, PCHAR szModuleName, PULONGLONG pModuleBase, PULONG pModuleSize);


//��VAD �в�ѯģ�� ��ַ��С
//pid ������
//szModuleName ģ����  ���ϸ����ִ�Сд��
BOOL QueryVADModule(ULONG pid, PCHAR szModuleName, PULONGLONG pModuleBase, PULONG pModuleSize);


//���������ڴ�
//pid ������
//uDataSize �����ڴ��С
PUCHAR AllocateMem(ULONG PID, ULONG uDataSize);


//�����߳�
//pid ������
//shellcode ��shellcode �����ݣ�
//len ��shellcode �ֽڳ��ȣ�
//Argument (�߳����� ���� ��ΪNULL)
BOOL CreateMyThread(ULONG PID, PVOID address, PVOID Argument);


//��������
//pid ������
//isProcect  �����Ƿ񱣻�
BOOL ProtectProcessR3(ULONG pid, BOOLEAN isProcect);
#ifdef __cplusplus
}
#endif
