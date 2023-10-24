#pragma once
#include <Windows.h>
/// <summary>
/// 初始化
/// </summary>
/// <param name="regCode">注册码</param>
/// <returns></returns>
typedef ULONG(*InitReg)(PCHAR regCode);


/// <summary>
/// 读取物理内存
/// </summary>
/// <param name="PID">进程id</param>
/// <param name="Address">读取的地址</param>
/// <param name="buffer">要读到的地址</param>
/// <param name="uDataSize">读取长度</param>
/// <returns>状态码</returns>
typedef ULONG(*ReadMemory)(ULONG PID, PVOID Address, PVOID buffer, ULONG length);


/// <summary>
/// 写入物理内存
/// </summary>
/// <param name="PID">进程id</param>
/// <param name="Address">写入的地址</param>
/// <param name="pValBuffer">要写入的数据的地址</param>
/// <param name="length">写入数据的字节长度</param>
/// <returns>状态码</returns>
typedef ULONG(*WriteMemory)(ULONG PID, PVOID Address, PVOID pValBuffer, ULONG length);


/// <summary>
/// 进程伪装
/// protectPid  自己的进程id
/// fakePid  要伪装的进程id
/// </summary>
typedef ULONG(*FakeProcess)(ULONG protectPid, ULONG fakePid);


/// <summary>
/// 保护窗口
/// hwnd 窗口句柄
/// </summary>
typedef ULONG(*ProtectWindow) (ULONG32 hwnd);



/// <summary>
/// 反截图
/// hwnd 窗口句柄
/// </summary>
typedef ULONG(*AntiSnapShotWindow) (ULONG32 hwnd);



/// <summary>
/// 查询进程模块 （会附加进程）
/// </summary>
/// <param name="pid">进程ID</param>
/// <param name="szModuleName">模块名</param>
/// <param name="pModuleBase">模块基址</param>
/// <param name="pModuleSize">模块大小</param>
/// <param name="type">查询类型 1 PEB(有附加)  2 NO_ATTACH(无附加) </param>
/// <returns>状态码</returns>
typedef ULONG(*QueryModule)(ULONG pid, PCHAR szModuleName, PULONG64 pModuleBase, PULONG pModuleSize, USHORT type);



/// <summary>
/// 查询进程模块 （会附加进程）
/// </summary>
/// <param name="pid">进程ID</param>
/// <param name="szModuleName">模块名</param>
/// <param name="pModuleBase">模块基址</param>
/// <param name="pModuleSize">模块大小</param>
/// <returns>状态码</returns>
typedef ULONG(*QueryVADModule)(ULONG pid, PCHAR szModuleName, PULONGLONG pModuleBase, PULONG pModuleSize);



/// <summary>
/// 申请内存 （属性为读写，但可执行）
/// </summary>
/// <param name="PID">进程ID</param>
/// <param name="uDataSize">申请内存的大小</param>
/// <param name="retAddr">申请到的内存地址</param>
/// <returns>状态码</returns>
typedef ULONG(*AllocateMemmory)(ULONG PID, ULONG uDataSize, PULONG64 pAddr);


/// <summary>
/// 创建线程 
/// </summary>
/// <param name="PID">进程id</param>
/// <param name="address">启动地址</param>
/// <param name="Argument">参数</param>
/// <returns>状态码</returns>
typedef ULONG(*CreateMyThread) (ULONG PID, PVOID address, PVOID Argument);



/// <summary>
/// r3保护进程
/// hwnd 进程id
/// </summary>
typedef ULONG(*AddProtectProcessR3)(ULONG pid);



/// <summary>
/// 搜索特征码
/// </summary>
/// <param name="pid">进程ID</param>
/// <param name="szModuleName">模块名</param>
/// <param name="pattern">特征码</param>
/// <param name="mask">特征码模板</param>
/// <param name="retAddr">搜索到的内存地址</param>
/// <returns>状态码</returns>
typedef  ULONG(*SearchPattern)(ULONG pid, PCHAR szModuleName, PCHAR pattern, PCHAR mask, PULONG64 retAddr);



/// <summary>
/// 注入dll
/// </summary>
/// <param name="pid">进程ID</param>
/// <param name="dllFilePath">dll文件完整路径</param>
///  <param name="type">启动方式 1 线程启动 2 劫持rip启动 3 apc 启动</param>
/// <returns>状态码</returns>
typedef ULONG(*InjectX64DLL)(ULONG pid, PCHAR dllFilePath, UCHAR type);



/// <summary>
/// 查询模块导出地址
/// </summary>
/// <param name="pid">进程id</param>
/// <param name="ModuleName">模块名 </param>
/// <param name="ExportFuncName">导出方法名称</param>
/// <param name="funcAddr">导出方法地址</param>
/// <returns>状态码</returns> 
typedef ULONG(*GetModuleExportAddr)(ULONG pid, PCHAR ModuleName, PCHAR ExportFuncName, PULONG64 funcAddr);


/// <summary>
/// 查询模块导出地址2
/// </summary>
/// <param name="pid">进程id</param>
/// <param name="ModuleBase">模块基址 </param>
/// <param name="ExportFuncName">导出方法名称（分大小写）</param>
/// <param name="funcAddr">导出方法地址</param>
/// <returns>状态码</returns>
typedef  ULONG(*GetModuleExportAddr2)(ULONG pid, ULONG64 ModuleBase, PCHAR ExportFuncName, PULONG64 FuncAddr);



/// <summary>
/// 通过模块名获取进程id
/// </summary>
/// <param name="szModuleName">模块名</param>
/// <returns>进程id</returns>
typedef ULONG(*GetProcessIdByName)(PCHAR szModuleName, PULONG pid);