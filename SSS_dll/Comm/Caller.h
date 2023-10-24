

 
#include "../../SSS_Drivers/Comm/CommStructs.h"
#ifdef __cplusplus
extern "C" {  // only need to export C interface if
              // used by C++ source code
#endif
ULONG InstallDriver();
/// <summary>
/// ��ʼ��
/// </summary>
/// <param name="regCode">ע����</param>
/// <returns></returns>
__declspec(dllimport) ULONG   _InitReg(_In_ PCHAR regCode);

/// <summary>
/// ��ȡ�����ڴ�
/// </summary>
/// <param name="PID">����id</param>
/// <param name="Address">��ȡ�ĵ�ַ</param>
/// <param name="buffer">Ҫ�����ĵ�ַ</param>
/// <param name="uDataSize">��ȡ����</param>
/// <returns>״̬��</returns>
__declspec(dllimport) ULONG _PhyReadMemory(_In_ ULONG PID, _In_ PVOID Address, _Out_ PVOID buffer, _In_ ULONG uDataSize);
/// <summary>
/// д�������ڴ�
/// </summary>
/// <param name="PID">����id</param>
/// <param name="Address">д��ĵ�ַ</param>
/// <param name="pValBuffer">Ҫд������ݵĵ�ַ</param>
/// <param name="length">д�����ݵ��ֽڳ���</param>
/// <returns>״̬��</returns>
__declspec(dllimport) ULONG _PhyWriteMemory(_In_ ULONG		PID, _In_ PVOID	Address, _In_ PVOID		pValBuffer, _In_ ULONG length);

/// <summary>
/// ����αװ
/// </summary>
/// <param name="protectPid">�Լ��Ľ���PID</param>
/// <param name="fakePid">��Ҫαװ�Ľ���PID</param>
/// <returns>������</returns>
__declspec(dllimport) ULONG _ProtectProcess(_In_ ULONG protectPid, _In_ ULONG fakePid);
/// <summary>
/// ��������
/// </summary>
/// <param name="hwnd">�����ھ��</param>
/// <returns>״̬��</returns>
__declspec(dllimport) ULONG _ProtectWindow(_In_ ULONG32 hwnd);

/// <summary>
/// ����ͼ
/// </summary>
/// <param name="hwnd">�����ھ��</param>
/// <returns>״̬��</returns>
__declspec(dllimport) ULONG _AntiSnapShotWindow(ULONG32 hwnd);

/// <summary>
/// ��ѯ����ģ�� ���ḽ�ӽ��̣�
/// </summary>
/// <param name="pid">����ID</param>
/// <param name="szModuleName">ģ����</param>
/// <param name="pModuleBase">ģ���ַ</param>
/// <param name="pModuleSize">ģ���С</param>
/// <param name="type">��ѯ���� 1 PEB(�и���)  2 NO_ATTACH(�޸���) </param>
/// <returns>״̬��</returns>
__declspec(dllimport) ULONG _QueryModule(_In_ ULONG pid, _In_ PCHAR szModuleName, _Out_ PULONGLONG pModuleBase, _Out_ PULONG pModuleSize,_In_ USHORT type);


/// <summary>
/// ͨ��ģ������ȡ����id
/// </summary>
/// <param name="szModuleName">ģ����</param>
/// <returns>����id</returns>
__declspec(dllimport) ULONG _GetProcessIdByName(_In_ PCHAR szModuleName, PULONG pid);

/// <summary>
/// ��VAD�в�ѯ����ģ��(�޸���)
/// </summary>
/// <param name="pid">����ID</param>
/// <param name="szModuleName">ģ������</param>
/// <param name="pModuleBase">ģ���ַ</param>
/// <param name="pModuleSize">ģ���С</param>
/// <returns>״̬��</returns>
__declspec(dllimport) ULONG _QueryVADModule(_In_ ULONG pid, _In_ PCHAR szModuleName, _Out_ PULONGLONG pModuleBase, _Out_ PULONG pModuleSize);



/// <summary>
/// �����ڴ� ������Ϊ��д������ִ�У�
/// </summary>
/// <param name="PID">����ID</param>
/// <param name="uDataSize">�����ڴ�Ĵ�С</param>
/// <param name="retAddr">���뵽���ڴ��ַ</param>
/// <returns>״̬��</returns>
__declspec(dllimport) ULONG _AllocateMem(_In_ ULONG PID, _In_ ULONG uDataSize, _Out_ PULONG64 retAddr);


/// <summary>
/// �����߳� 
/// </summary>
/// <param name="PID">����id</param>
/// <param name="address">������ַ</param>
/// <param name="Argument">����</param>
/// <returns>״̬��</returns>
__declspec(dllimport) ULONG _CreateMyThread(_In_ ULONG PID, _In_ PVOID address, _In_ PVOID Argument);


/// <summary>
/// ���ý��̱�����Ӧ�ò�ܾ����ʣ�
/// </summary>
/// <param name="pid">����id</param>
/// <returns>״̬��</returns>
__declspec(dllimport) ULONG _ProtectProcessR3_Add(_In_ ULONG pid);

/// <summary>
/// �Ƴ����̱��� ��Ӧ�ò�ܾ����ʣ�
/// </summary>
/// <param name="pid">����ID</param>
/// <returns>״̬��</returns>
__declspec(dllimport) ULONG _ProtectProcessR3_Remove(_In_ ULONG pid);

/// <summary>
/// ����������
/// </summary>
/// <param name="pid">����ID</param>
/// <param name="szModuleName">ģ����</param>
/// <param name="pattern">������</param>
/// <param name="mask">������ģ��</param>
/// <param name="retAddr">���������ڴ��ַ</param>
/// <returns>״̬��</returns>

__declspec(dllimport) ULONG _SearchPattern(_In_ ULONG pid, _In_ PCHAR szModuleName, _In_ PCHAR pattern, _In_ PCHAR mask, _Out_ PULONG64 retAddr);


/// <summary>
/// ע��dll
/// </summary>
/// <param name="pid">����ID</param>
/// <param name="dllFilePath">dll�ļ�����·��</param>
///  <param name="type">������ʽ 1 �߳����� 2 �ٳ�rip���� 3 apc ����</param>
/// <returns>״̬��</returns>
__declspec(dllimport)  ULONG _InjectX64DLL(_In_ ULONG pid, _In_ PCHAR dllFilePath, UCHAR type);

/// <summary>
/// ��ѯģ�鵼����ַ
/// </summary>
/// <param name="pid">����id</param>
/// <param name="ModuleName">ģ�������ִ�Сд��</param>
/// <param name="ExportFuncName">������������</param>
/// <returns>״̬��</returns>
__declspec(dllimport) ULONG _GetModuleExportAddr(ULONG pid, PCHAR ModuleName, PCHAR ExportFuncName);

/// <summary>
/// ��ѯģ�鵼����ַ2
/// </summary>
/// <param name="pid">����id</param>
/// <param name="ModuleBase">ģ���ַ </param>
/// <param name="ExportFuncName">�����������ƣ��ִ�Сд��</param>
/// <param name="funcAddr">����������ַ</param>
/// <returns>״̬��</returns>
__declspec(dllimport) ULONG _GetModuleExportAddr2(ULONG pid, ULONG64 ModuleBase, PCHAR ExportFuncName,PULONG64 FuncAddr);

/// <summary>
/// ��ѯģ�鵼����ַ
/// </summary>
/// <param name="pid">����id</param>
/// <param name="ModuleName">ģ���� </param>
/// <param name="ExportFuncName">������������</param>
/// <param name="funcAddr">����������ַ</param>
/// <returns>״̬��</returns> 
__declspec(dllimport) ULONG _GetModuleExportAddr(ULONG pid, PCHAR ModuleName, PCHAR ExportFuncName, PULONG64 funcAddr);


/// <summary>
/// д��һ��DLL ������������Ҫ�ֶ�����DLL ������
/// </summary>
/// <param name="PID">����dll</param>
/// <param name="dllFilePath">dll�ļ�·��</param>
/// <param name="entryPoint">д�����뺯����ַ</param>
/// <param name="R3_ImageBase">д������ʼ�ڴ��ַ</param>
/// <param name="R0_ImageBase">ӳ����ں˵�ַ�������û�ʹ�ã�</param>
/// <returns></returns>
__declspec(dllimport) ULONG _WriteDLL(ULONG PID, PCHAR dllFilePath, PULONG64 entryPoint, PULONG64 R3_ImageBase, PULONG64 R0_ImageBase);

/// <summary>
///  �ַ���������ת�ֽ�
/// </summary>
/// <param name="pattern">�ַ���</param>
/// <param name="mask">������ģ��</param>
/// <param name="outPattern">ת�����������</param>
__declspec(dllimport) VOID ConvertString2Pattern(_In_ PCHAR pattern, _In_ PCHAR mask, _Out_  PCHAR outPattern);


/// <summary>
///  ת��CE xdbg  ������ȡ�������� ��ʽΪ("1B ?? 2C ?? ED ?? ?? ??" �� ȥ���ո�"1B??2C??ED??????" )
/// </summary>
/// <param name="pattern">�������ַ���</param>
/// <param name="mask">ת�����������ģ��</param>
/// <param name="outPattern">ת�����������</param>
__declspec(dllimport) VOID ConvertCEPattern(_In_ PCHAR CE_XDBG_pattern, _Out_ PCHAR mask, _Out_  PCHAR outPattern);


/// <summary>
/// �޸Ľ����ڴ�����
/// </summary>
/// <param name="PID">����ID</param>
/// <param name="address">�ڴ��ַ</param>
/// <param name="length">�޸ĳ���</param>
/// <returns></returns>
__declspec(dllimport) ULONG _CHANGE_MEMORY_ATTR(_In_ ULONG PID, _In_  ULONG64 address, _In_  ULONG length);


/// <summary>
/// ���߳�call
/// </summary>
/// <param name="PID">����id</param>
/// <param name="shellcodeAddr">shellcode ��ַ</param>
/// <param name="shellcodeLen">shellcode ����</param>
/// <returns></returns>
__declspec(dllimport) ULONG _CALL_MAIN_THREAD(_In_ ULONG PID, _In_ ULONG64 shellcodeAddr, _In_ ULONG shellcodeLen);
#ifdef __cplusplus
}
#endif