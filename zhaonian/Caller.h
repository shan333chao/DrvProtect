

#include <windows.h>
 
namespace caller {
	ULONG InstallDriver();
	/// <summary>
	/// 初始化
	/// </summary>
	/// <param name="regCode">注册码</param>
	/// <returns></returns>
	ULONG init(_In_ char* regCode);
	/// <summary>
	/// 伪装读取内存
	/// </summary>
	/// <param name="PID">进程ID</param>
	/// <param name="fakePid">伪装进程ID</param>
	/// <param name="Address">内存地址</param>
	/// <param name="buffer">要读到的地址</param>
	/// <param name="uDataSize">读取的字节长度</param>
	/// <returns>状态码</returns>
	ULONG FakeReadMemory(_In_ ULONG PID, _In_ ULONG fakePid, _In_ PVOID Address, _Out_ PVOID buffer, _In_ ULONG uDataSize);
	/// <summary>
	/// 伪装写入内存
	/// </summary>
	/// <param name="PID">进程id</param>
	/// <param name="fakePid">伪装进程id</param>
	/// <param name="Address">写入的地址</param>
	/// <param name="pValBuffer">要写入的数据的地址</param>
	/// <param name="length">数据字节长度</param>
	/// <returns>状态码</returns>
	ULONG FakeWriteMemory(_In_ ULONG		PID, _In_ ULONG fakePid, _In_ ULONG64	Address, _In_ PVOID pValBuffer, _In_ ULONG length);
	/// <summary>
	/// 读取物理内存
	/// </summary>
	/// <param name="PID">进程id</param>
	/// <param name="Address">读取的地址</param>
	/// <param name="buffer">要读到的地址</param>
	/// <param name="uDataSize">读取长度</param>
	/// <returns>状态码</returns>
	ULONG PhyReadMemory(_In_ ULONG PID, _In_ PVOID Address, _Out_ PVOID buffer, _In_ ULONG uDataSize);
	/// <summary>
	/// 写入物理内存
	/// </summary>
	/// <param name="PID">进程id</param>
	/// <param name="Address">写入的地址</param>
	/// <param name="pValBuffer">要写入的数据的地址</param>
	/// <param name="length">写入数据的字节长度</param>
	/// <returns>状态码</returns>
	ULONG PhyWriteMemory(_In_ ULONG		PID, _In_ PVOID	Address, _In_ PVOID		pValBuffer, _In_ ULONG length);

	/// <summary>
	/// 进程伪装
	/// </summary>
	/// <param name="protectPid">自己的进程PID</param>
	/// <param name="fakePid">需要伪装的进程PID</param>
	/// <returns>错误码</returns>
	ULONG ProtectProcess(_In_ ULONG protectPid, _In_ ULONG fakePid);
	/// <summary>
	/// 保护窗口并反截图
	/// </summary>
	/// <param name="hwnd">主窗口句柄</param>
	/// <returns>状态码</returns>
	ULONG ProtectWindow(_In_ ULONG32 hwnd);


	/// <summary>
	/// 查询进程模块 （会附加进程）
	/// </summary>
	/// <param name="pid">进程ID</param>
	/// <param name="szModuleName">模块名</param>
	/// <param name="pModuleBase">模块基址</param>
	/// <param name="pModuleSize">模块大小</param>
	/// <returns>状态码</returns>
	ULONG QueryModule(_In_ ULONG pid, _In_ PCHAR szModuleName, _Out_ PULONGLONG pModuleBase, _Out_ PULONG pModuleSize);


	/// <summary>
	/// 在VAD中查询进程模块(无附加)
	/// </summary>
	/// <param name="pid">进程ID</param>
	/// <param name="szModuleName">模块名称</param>
	/// <param name="pModuleBase">模块基址</param>
	/// <param name="pModuleSize">模块大小</param>
	/// <returns>状态码</returns>
	ULONG QueryVADModule(_In_ ULONG pid, _In_ PCHAR szModuleName, _Out_ PULONGLONG pModuleBase, _Out_ PULONG pModuleSize);


	
	/// <summary>
	/// 申请内存 （属性为读写，但可执行）
	/// </summary>
	/// <param name="PID">进程ID</param>
	/// <param name="uDataSize">申请内存的大小</param>
	/// <param name="retAddr">申请到的内存地址</param>
	/// <returns>状态码</returns>
	ULONG AllocateMem(_In_ ULONG PID, _In_ ULONG uDataSize,_Out_ PULONG64 retAddr);


	/// <summary>
	/// 创建线程 
	/// </summary>
	/// <param name="PID">进程id</param>
	/// <param name="address">启动地址</param>
	/// <param name="Argument">参数</param>
	/// <returns>状态码</returns>
	ULONG CreateMyThread(_In_ ULONG PID, _In_ PVOID address, _In_ PVOID Argument);


	/// <summary>
	/// 设置进程保护（应用层拒绝访问）
	/// </summary>
	/// <param name="pid">进程id</param>
	/// <returns>状态码</returns>
	ULONG ProtectProcessR3_Add(_In_ ULONG pid);

	/// <summary>
	/// 移除进程保护 （应用层拒绝访问）
	/// </summary>
	/// <param name="pid">进程ID</param>
	/// <returns>状态码</returns>
	ULONG ProtectProcessR3_Remove(_In_ ULONG pid);

	/// <summary>
	/// 搜索特征码
	/// </summary>
	/// <param name="pid">进程ID</param>
	/// <param name="szModuleName">模块名</param>
	/// <param name="pattern">特征码</param>
	/// <param name="mask">特征码模板</param>
	/// <param name="retAddr">搜索到的内存地址</param>
	/// <returns>状态码</returns>
	
	ULONG SearchPattern(_In_ ULONG pid, _In_ PCHAR szModuleName, _In_ PCHAR pattern, _In_ PCHAR mask,_Out_ PULONG64 retAddr);


	/// <summary>
	/// 注入dll
	/// </summary>
	/// <param name="pid">进程ID</param>
	/// <param name="dllFilePath">dll文件完整路径</param>
	/// <returns>状态码</returns>
	ULONG InjectX64DLL(_In_ ULONG pid, _In_ PCHAR dllFilePath);
}

