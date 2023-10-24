#pragma once
#include <Windows.h>
/// <summary>
/// ��ʼ��
/// </summary>
/// <param name="regCode">ע����</param>
/// <returns></returns>
typedef ULONG(*InitReg)(PCHAR regCode);


/// <summary>
/// ��ȡ�����ڴ�
/// </summary>
/// <param name="PID">����id</param>
/// <param name="Address">��ȡ�ĵ�ַ</param>
/// <param name="buffer">Ҫ�����ĵ�ַ</param>
/// <param name="uDataSize">��ȡ����</param>
/// <returns>״̬��</returns>
typedef ULONG(*ReadMemory)(ULONG PID, PVOID Address, PVOID buffer, ULONG length);


/// <summary>
/// д�������ڴ�
/// </summary>
/// <param name="PID">����id</param>
/// <param name="Address">д��ĵ�ַ</param>
/// <param name="pValBuffer">Ҫд������ݵĵ�ַ</param>
/// <param name="length">д�����ݵ��ֽڳ���</param>
/// <returns>״̬��</returns>
typedef ULONG(*WriteMemory)(ULONG PID, PVOID Address, PVOID pValBuffer, ULONG length);


/// <summary>
/// ����αװ
/// protectPid  �Լ��Ľ���id
/// fakePid  Ҫαװ�Ľ���id
/// </summary>
typedef ULONG(*FakeProcess)(ULONG protectPid, ULONG fakePid);


/// <summary>
/// ��������
/// hwnd ���ھ��
/// </summary>
typedef ULONG(*ProtectWindow) (ULONG32 hwnd);



/// <summary>
/// ����ͼ
/// hwnd ���ھ��
/// </summary>
typedef ULONG(*AntiSnapShotWindow) (ULONG32 hwnd);



/// <summary>
/// ��ѯ����ģ�� ���ḽ�ӽ��̣�
/// </summary>
/// <param name="pid">����ID</param>
/// <param name="szModuleName">ģ����</param>
/// <param name="pModuleBase">ģ���ַ</param>
/// <param name="pModuleSize">ģ���С</param>
/// <param name="type">��ѯ���� 1 PEB(�и���)  2 NO_ATTACH(�޸���) </param>
/// <returns>״̬��</returns>
typedef ULONG(*QueryModule)(ULONG pid, PCHAR szModuleName, PULONG64 pModuleBase, PULONG pModuleSize, USHORT type);



/// <summary>
/// ��ѯ����ģ�� ���ḽ�ӽ��̣�
/// </summary>
/// <param name="pid">����ID</param>
/// <param name="szModuleName">ģ����</param>
/// <param name="pModuleBase">ģ���ַ</param>
/// <param name="pModuleSize">ģ���С</param>
/// <returns>״̬��</returns>
typedef ULONG(*QueryVADModule)(ULONG pid, PCHAR szModuleName, PULONGLONG pModuleBase, PULONG pModuleSize);



/// <summary>
/// �����ڴ� ������Ϊ��д������ִ�У�
/// </summary>
/// <param name="PID">����ID</param>
/// <param name="uDataSize">�����ڴ�Ĵ�С</param>
/// <param name="retAddr">���뵽���ڴ��ַ</param>
/// <returns>״̬��</returns>
typedef ULONG(*AllocateMemmory)(ULONG PID, ULONG uDataSize, PULONG64 pAddr);


/// <summary>
/// �����߳� 
/// </summary>
/// <param name="PID">����id</param>
/// <param name="address">������ַ</param>
/// <param name="Argument">����</param>
/// <returns>״̬��</returns>
typedef ULONG(*CreateMyThread) (ULONG PID, PVOID address, PVOID Argument);



/// <summary>
/// r3��������
/// hwnd ����id
/// </summary>
typedef ULONG(*AddProtectProcessR3)(ULONG pid);



/// <summary>
/// ����������
/// </summary>
/// <param name="pid">����ID</param>
/// <param name="szModuleName">ģ����</param>
/// <param name="pattern">������</param>
/// <param name="mask">������ģ��</param>
/// <param name="retAddr">���������ڴ��ַ</param>
/// <returns>״̬��</returns>
typedef  ULONG(*SearchPattern)(ULONG pid, PCHAR szModuleName, PCHAR pattern, PCHAR mask, PULONG64 retAddr);



/// <summary>
/// ע��dll
/// </summary>
/// <param name="pid">����ID</param>
/// <param name="dllFilePath">dll�ļ�����·��</param>
///  <param name="type">������ʽ 1 �߳����� 2 �ٳ�rip���� 3 apc ����</param>
/// <returns>״̬��</returns>
typedef ULONG(*InjectX64DLL)(ULONG pid, PCHAR dllFilePath, UCHAR type);



/// <summary>
/// ��ѯģ�鵼����ַ
/// </summary>
/// <param name="pid">����id</param>
/// <param name="ModuleName">ģ���� </param>
/// <param name="ExportFuncName">������������</param>
/// <param name="funcAddr">����������ַ</param>
/// <returns>״̬��</returns> 
typedef ULONG(*GetModuleExportAddr)(ULONG pid, PCHAR ModuleName, PCHAR ExportFuncName, PULONG64 funcAddr);


/// <summary>
/// ��ѯģ�鵼����ַ2
/// </summary>
/// <param name="pid">����id</param>
/// <param name="ModuleBase">ģ���ַ </param>
/// <param name="ExportFuncName">�����������ƣ��ִ�Сд��</param>
/// <param name="funcAddr">����������ַ</param>
/// <returns>״̬��</returns>
typedef  ULONG(*GetModuleExportAddr2)(ULONG pid, ULONG64 ModuleBase, PCHAR ExportFuncName, PULONG64 FuncAddr);



/// <summary>
/// ͨ��ģ������ȡ����id
/// </summary>
/// <param name="szModuleName">ģ����</param>
/// <returns>����id</returns>
typedef ULONG(*GetProcessIdByName)(PCHAR szModuleName, PULONG pid);