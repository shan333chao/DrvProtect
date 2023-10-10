

#include <windows.h>
 
namespace caller {
	ULONG InstallDriver();
	/// <summary>
	/// ��ʼ��
	/// </summary>
	/// <param name="regCode">ע����</param>
	/// <returns></returns>
	ULONG init(_In_ char* regCode);
	/// <summary>
	/// αװ��ȡ�ڴ�
	/// </summary>
	/// <param name="PID">����ID</param>
	/// <param name="fakePid">αװ����ID</param>
	/// <param name="Address">�ڴ��ַ</param>
	/// <param name="buffer">Ҫ�����ĵ�ַ</param>
	/// <param name="uDataSize">��ȡ���ֽڳ���</param>
	/// <returns>״̬��</returns>
	ULONG FakeReadMemory(_In_ ULONG PID, _In_ ULONG fakePid, _In_ PVOID Address, _Out_ PVOID buffer, _In_ ULONG uDataSize);
	/// <summary>
	/// αװд���ڴ�
	/// </summary>
	/// <param name="PID">����id</param>
	/// <param name="fakePid">αװ����id</param>
	/// <param name="Address">д��ĵ�ַ</param>
	/// <param name="pValBuffer">Ҫд������ݵĵ�ַ</param>
	/// <param name="length">�����ֽڳ���</param>
	/// <returns>״̬��</returns>
	ULONG FakeWriteMemory(_In_ ULONG		PID, _In_ ULONG fakePid, _In_ ULONG64	Address, _In_ PVOID pValBuffer, _In_ ULONG length);
	/// <summary>
	/// ��ȡ�����ڴ�
	/// </summary>
	/// <param name="PID">����id</param>
	/// <param name="Address">��ȡ�ĵ�ַ</param>
	/// <param name="buffer">Ҫ�����ĵ�ַ</param>
	/// <param name="uDataSize">��ȡ����</param>
	/// <returns>״̬��</returns>
	ULONG PhyReadMemory(_In_ ULONG PID, _In_ PVOID Address, _Out_ PVOID buffer, _In_ ULONG uDataSize);
	/// <summary>
	/// д�������ڴ�
	/// </summary>
	/// <param name="PID">����id</param>
	/// <param name="Address">д��ĵ�ַ</param>
	/// <param name="pValBuffer">Ҫд������ݵĵ�ַ</param>
	/// <param name="length">д�����ݵ��ֽڳ���</param>
	/// <returns>״̬��</returns>
	ULONG PhyWriteMemory(_In_ ULONG		PID, _In_ PVOID	Address, _In_ PVOID		pValBuffer, _In_ ULONG length);

	/// <summary>
	/// ����αװ
	/// </summary>
	/// <param name="protectPid">�Լ��Ľ���PID</param>
	/// <param name="fakePid">��Ҫαװ�Ľ���PID</param>
	/// <returns>������</returns>
	ULONG ProtectProcess(_In_ ULONG protectPid, _In_ ULONG fakePid);
	/// <summary>
	/// �������ڲ�����ͼ
	/// </summary>
	/// <param name="hwnd">�����ھ��</param>
	/// <returns>״̬��</returns>
	ULONG ProtectWindow(_In_ ULONG32 hwnd);


	/// <summary>
	/// ��ѯ����ģ�� ���ḽ�ӽ��̣�
	/// </summary>
	/// <param name="pid">����ID</param>
	/// <param name="szModuleName">ģ����</param>
	/// <param name="pModuleBase">ģ���ַ</param>
	/// <param name="pModuleSize">ģ���С</param>
	/// <returns>״̬��</returns>
	ULONG QueryModule(_In_ ULONG pid, _In_ PCHAR szModuleName, _Out_ PULONGLONG pModuleBase, _Out_ PULONG pModuleSize);


	/// <summary>
	/// ��VAD�в�ѯ����ģ��(�޸���)
	/// </summary>
	/// <param name="pid">����ID</param>
	/// <param name="szModuleName">ģ������</param>
	/// <param name="pModuleBase">ģ���ַ</param>
	/// <param name="pModuleSize">ģ���С</param>
	/// <returns>״̬��</returns>
	ULONG QueryVADModule(_In_ ULONG pid, _In_ PCHAR szModuleName, _Out_ PULONGLONG pModuleBase, _Out_ PULONG pModuleSize);


	
	/// <summary>
	/// �����ڴ� ������Ϊ��д������ִ�У�
	/// </summary>
	/// <param name="PID">����ID</param>
	/// <param name="uDataSize">�����ڴ�Ĵ�С</param>
	/// <param name="retAddr">���뵽���ڴ��ַ</param>
	/// <returns>״̬��</returns>
	ULONG AllocateMem(_In_ ULONG PID, _In_ ULONG uDataSize,_Out_ PULONG64 retAddr);


	/// <summary>
	/// �����߳� 
	/// </summary>
	/// <param name="PID">����id</param>
	/// <param name="address">������ַ</param>
	/// <param name="Argument">����</param>
	/// <returns>״̬��</returns>
	ULONG CreateMyThread(_In_ ULONG PID, _In_ PVOID address, _In_ PVOID Argument);


	/// <summary>
	/// ���ý��̱�����Ӧ�ò�ܾ����ʣ�
	/// </summary>
	/// <param name="pid">����id</param>
	/// <returns>״̬��</returns>
	ULONG ProtectProcessR3_Add(_In_ ULONG pid);

	/// <summary>
	/// �Ƴ����̱��� ��Ӧ�ò�ܾ����ʣ�
	/// </summary>
	/// <param name="pid">����ID</param>
	/// <returns>״̬��</returns>
	ULONG ProtectProcessR3_Remove(_In_ ULONG pid);

	/// <summary>
	/// ����������
	/// </summary>
	/// <param name="pid">����ID</param>
	/// <param name="szModuleName">ģ����</param>
	/// <param name="pattern">������</param>
	/// <param name="mask">������ģ��</param>
	/// <param name="retAddr">���������ڴ��ַ</param>
	/// <returns>״̬��</returns>
	
	ULONG SearchPattern(_In_ ULONG pid, _In_ PCHAR szModuleName, _In_ PCHAR pattern, _In_ PCHAR mask,_Out_ PULONG64 retAddr);


	/// <summary>
	/// ע��dll
	/// </summary>
	/// <param name="pid">����ID</param>
	/// <param name="dllFilePath">dll�ļ�����·��</param>
	/// <returns>״̬��</returns>
	ULONG InjectX64DLL(_In_ ULONG pid, _In_ PCHAR dllFilePath);
}

