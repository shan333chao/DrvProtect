

 
#include "../../SSS_Drivers/Comm/CommStructs.h"
#ifdef __cplusplus
extern "C" {  // only need to export C interface if
              // used by C++ source code
#endif
ULONG InstallDriver();
/// <summary>
/// 初始化
/// </summary>
/// <param name="regCode">注册码</param>
/// <returns></returns>
__declspec(dllimport) ULONG   _InitReg(_In_ PCHAR regCode);

/// <summary>
/// 读取物理内存
/// </summary>
/// <param name="PID">进程id</param>
/// <param name="Address">读取的地址</param>
/// <param name="buffer">要读到的地址</param>
/// <param name="uDataSize">读取长度</param>
/// <returns>状态码</returns>
__declspec(dllimport) ULONG _PhyReadMemory(_In_ ULONG PID, _In_ PVOID Address, _Out_ PVOID buffer, _In_ ULONG uDataSize);
/// <summary>
/// 写入物理内存
/// </summary>
/// <param name="PID">进程id</param>
/// <param name="Address">写入的地址</param>
/// <param name="pValBuffer">要写入的数据的地址</param>
/// <param name="length">写入数据的字节长度</param>
/// <returns>状态码</returns>
__declspec(dllimport) ULONG _PhyWriteMemory(_In_ ULONG		PID, _In_ PVOID	Address, _In_ PVOID		pValBuffer, _In_ ULONG length);

/// <summary>
/// 进程伪装
/// </summary>
/// <param name="protectPid">自己的进程PID</param>
/// <param name="fakePid">需要伪装的进程PID</param>
/// <returns>错误码</returns>
__declspec(dllimport) ULONG _ProtectProcess(_In_ ULONG protectPid, _In_ ULONG fakePid);
/// <summary>
/// 保护窗口
/// </summary>
/// <param name="hwnd">主窗口句柄</param>
/// <returns>状态码</returns>
__declspec(dllimport) ULONG _ProtectWindow(_In_ ULONG32 hwnd);

/// <summary>
/// 反截图
/// </summary>
/// <param name="hwnd">主窗口句柄</param>
/// <returns>状态码</returns>
__declspec(dllimport) ULONG _AntiSnapShotWindow(ULONG32 hwnd);

/// <summary>
/// 查询进程模块 （会附加进程）
/// </summary>
/// <param name="pid">进程ID</param>
/// <param name="szModuleName">模块名</param>
/// <param name="pModuleBase">模块基址</param>
/// <param name="pModuleSize">模块大小</param>
/// <param name="type">查询类型 1 PEB(有附加)  2 NO_ATTACH(无附加) </param>
/// <returns>状态码</returns>
__declspec(dllimport) ULONG _QueryModule(_In_ ULONG pid, _In_ PCHAR szModuleName, _Out_ PULONGLONG pModuleBase, _Out_ PULONG pModuleSize,_In_ USHORT type);


/// <summary>
/// 通过模块名获取进程id
/// </summary>
/// <param name="szModuleName">模块名</param>
/// <returns>进程id</returns>
__declspec(dllimport) ULONG _GetProcessIdByName(_In_ PCHAR szModuleName, PULONG pid);

/// <summary>
/// 在VAD中查询进程模块(无附加)
/// </summary>
/// <param name="pid">进程ID</param>
/// <param name="szModuleName">模块名称</param>
/// <param name="pModuleBase">模块基址</param>
/// <param name="pModuleSize">模块大小</param>
/// <returns>状态码</returns>
__declspec(dllimport) ULONG _QueryVADModule(_In_ ULONG pid, _In_ PCHAR szModuleName, _Out_ PULONGLONG pModuleBase, _Out_ PULONG pModuleSize);



/// <summary>
/// 申请内存 （属性为读写，但可执行）
/// </summary>
/// <param name="PID">进程ID</param>
/// <param name="uDataSize">申请内存的大小</param>
/// <param name="retAddr">申请到的内存地址</param>
/// <returns>状态码</returns>
__declspec(dllimport) ULONG _AllocateMem(_In_ ULONG PID, _In_ ULONG uDataSize, _Out_ PULONG64 retAddr);


/// <summary>
/// 创建线程 
/// </summary>
/// <param name="PID">进程id</param>
/// <param name="address">启动地址</param>
/// <param name="Argument">参数</param>
/// <returns>状态码</returns>
__declspec(dllimport) ULONG _CreateMyThread(_In_ ULONG PID, _In_ PVOID address, _In_ PVOID Argument);


/// <summary>
/// 设置进程保护（应用层拒绝访问）
/// </summary>
/// <param name="pid">进程id</param>
/// <returns>状态码</returns>
__declspec(dllimport) ULONG _ProtectProcessR3_Add(_In_ ULONG pid);

/// <summary>
/// 移除进程保护 （应用层拒绝访问）
/// </summary>
/// <param name="pid">进程ID</param>
/// <returns>状态码</returns>
__declspec(dllimport) ULONG _ProtectProcessR3_Remove(_In_ ULONG pid);

/// <summary>
/// 搜索特征码
/// </summary>
/// <param name="pid">进程ID</param>
/// <param name="szModuleName">模块名</param>
/// <param name="pattern">特征码</param>
/// <param name="mask">特征码模板</param>
/// <param name="retAddr">搜索到的内存地址</param>
/// <returns>状态码</returns>

__declspec(dllimport) ULONG _SearchPattern(_In_ ULONG pid, _In_ PCHAR szModuleName, _In_ PCHAR pattern, _In_ PCHAR mask, _Out_ PULONG64 retAddr);


/// <summary>
/// 注入dll
/// </summary>
/// <param name="pid">进程ID</param>
/// <param name="dllFilePath">dll文件完整路径</param>
///  <param name="type">启动方式 1 线程启动 2 劫持rip启动 3 apc 启动</param>
/// <returns>状态码</returns>
__declspec(dllimport)  ULONG _InjectX64DLL(_In_ ULONG pid, _In_ PCHAR dllFilePath, UCHAR type);

/// <summary>
/// 查询模块导出地址
/// </summary>
/// <param name="pid">进程id</param>
/// <param name="ModuleName">模块名（分大小写）</param>
/// <param name="ExportFuncName">导出方法名称</param>
/// <returns>状态码</returns>
__declspec(dllimport) ULONG _GetModuleExportAddr(ULONG pid, PCHAR ModuleName, PCHAR ExportFuncName);

/// <summary>
/// 查询模块导出地址2
/// </summary>
/// <param name="pid">进程id</param>
/// <param name="ModuleBase">模块基址 </param>
/// <param name="ExportFuncName">导出方法名称（分大小写）</param>
/// <param name="funcAddr">导出方法地址</param>
/// <returns>状态码</returns>
__declspec(dllimport) ULONG _GetModuleExportAddr2(ULONG pid, ULONG64 ModuleBase, PCHAR ExportFuncName,PULONG64 FuncAddr);

/// <summary>
/// 查询模块导出地址
/// </summary>
/// <param name="pid">进程id</param>
/// <param name="ModuleName">模块名 </param>
/// <param name="ExportFuncName">导出方法名称</param>
/// <param name="funcAddr">导出方法地址</param>
/// <returns>状态码</returns> 
__declspec(dllimport) ULONG _GetModuleExportAddr(ULONG pid, PCHAR ModuleName, PCHAR ExportFuncName, PULONG64 funcAddr);


/// <summary>
/// 写入一个DLL （不启动，需要手动构建DLL 启动）
/// </summary>
/// <param name="PID">进程dll</param>
/// <param name="dllFilePath">dll文件路径</param>
/// <param name="entryPoint">写入后的入函数地址</param>
/// <param name="R3_ImageBase">写入后的起始内存地址</param>
/// <param name="R0_ImageBase">映射的内核地址（高手用户使用）</param>
/// <returns></returns>
__declspec(dllimport) ULONG _WriteDLL(ULONG PID, PCHAR dllFilePath, PULONG64 entryPoint, PULONG64 R3_ImageBase, PULONG64 R0_ImageBase);

/// <summary>
///  字符串特征码转字节
/// </summary>
/// <param name="pattern">字符串</param>
/// <param name="mask">特征码模板</param>
/// <param name="outPattern">转换后的特征码</param>
__declspec(dllimport) VOID ConvertString2Pattern(_In_ PCHAR pattern, _In_ PCHAR mask, _Out_  PCHAR outPattern);


/// <summary>
///  转换CE xdbg  工具提取的特征码 格式为("1B ?? 2C ?? ED ?? ?? ??" 或 去掉空格"1B??2C??ED??????" )
/// </summary>
/// <param name="pattern">特征码字符串</param>
/// <param name="mask">转换后的特征码模板</param>
/// <param name="outPattern">转换后的特征码</param>
__declspec(dllimport) VOID ConvertCEPattern(_In_ PCHAR CE_XDBG_pattern, _Out_ PCHAR mask, _Out_  PCHAR outPattern);


/// <summary>
/// 修改进程内存属性
/// </summary>
/// <param name="PID">进程ID</param>
/// <param name="address">内存地址</param>
/// <param name="length">修改长度</param>
/// <returns></returns>
__declspec(dllimport) ULONG _CHANGE_MEMORY_ATTR(_In_ ULONG PID, _In_  ULONG64 address, _In_  ULONG length);


/// <summary>
/// 主线程call
/// </summary>
/// <param name="PID">进程id</param>
/// <param name="shellcodeAddr">shellcode 地址</param>
/// <param name="shellcodeLen">shellcode 长度</param>
/// <returns></returns>
__declspec(dllimport) ULONG _CALL_MAIN_THREAD(_In_ ULONG PID, _In_ ULONG64 shellcodeAddr, _In_ ULONG shellcodeLen);
#ifdef __cplusplus
}
#endif