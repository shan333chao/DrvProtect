#ifndef  _ERROR_CODE_H
#define _ERROR_CODE_H




//测试通讯
#define  STATUS_TEST_COMM_ERROR  0x10000001
//测试通讯测试成功
#define  STATUS_TEST_COMM_SUCCESS  0x10000000
//注册码过期
#define  STATUS_TEST_COMM_REG_EXPIRED  0x10000003

//无效注册码
#define  STATUS_TEST_COMM_REG_INVALID  0x10000004

//注册码过期或未注册
#define STATUS_TEST_COMM_UNREG_OR_EXPIRED  0x10000005
//测试通讯
#define  STATUS_TEST_COMM_WAY_ERROR  0x10000006 
//驱动启动
#ifdef  _X64
#define  STATUS_TEST_COMM_DRIVER_STARTED 0xC000003EL
#else
#define  STATUS_TEST_COMM_DRIVER_STARTED 0x00000017
#endif //  x64




//分配驱动文件内存失败
#define  STATUS_TEST_COMM_ALLOC_FAIL		0x10000008
//驱动文件未找到
#define  STATUS_TEST_COMM_MISS_DRIVE_FILE		0x10000009
//创建注册表失败
#define  STATUS_TEST_COMM_CREATE_SERVICE_KEY	0x10000010
//获取模块失败
#define  STATUS_TEST_COMM_GETMODULEHANDLEA		0x10000011
//加载驱动失败
#define  STATUS_TEST_COMM_SE_LOAD_DRIVER_PRIVILEGE				0x10000012
//创建驱动文件失败
#define  STATUS_TEST_COMM_CREATE_DRIVE				0x10000013
#define  STATUS_TEST_COMM_OPEN_SCMANAGER			0x10000014
#define  STATUS_TEST_COMM_CREATE_SERVICE			0x10000015


//进程伪装
#define  STATUS_PROTECT_PROCESS_ERROR  0x20000001
//进程自杀
#define  STATUS_KILL
//遍历进程
#define STATUS_ENUM_PROCESS 0x30000001
//伪装读取内存
#define STATUS_FAKE_READ_MEMORY 0x40000001
//伪装写入内存
#define STATUS_FAKE_WRITE_MEMORY 0x50000001
//伪装读取内存
#define STATUS_PHY_READ_MEMORY 0x60000001
//伪装写入内存
#define STATUS_PHY_WRITE_MEMORY 0x70000001
//保护窗口
#define STATUS_WND_PROTECT 0x80000001
//申请内存
#define STATUS_CREATE_MEMORY 0x90000001
//创建线程
#define STATUS_CREATE_THREAD 0xa0000001
//查询模块
#define STATUS_QUERY_MODULE 0xb0000001
//查询VAD模块
#define STATUS_QUERY_VAD_MODULE 0xC1000001
#define STATUS_QUERY_VAD_MODULE_MODULE_NAME 0xC1000002
//内核模块注入
#define STATUS_INJECT_DLL 0xE0000001
//注入分配内存错误
#define STATUS_INJECT_DLL_ALLOC_FAILED 0xE0000002

//进程保护
#define STATUS_PROTECT_PROCESS_ADD 0xF0000001
//移除应用层保护
#define STATUS_PROTECT_PROCESS_REMOVE 0x11000001
//特征搜索
#define STATUS_PATTERN_SEARCH 0x12000001
//特征码模板错误
#define STATUS_PATTERN_SEARCH_MASK 0x12000002
//内核拉伸dll
#define STATUS_WRITE_DLL 0x13000001
//主线程call
#define STATUS_CALL_MAIN 0x140000001
//获取远程模块导出函数地址
#define STATUS_MODULE_EXPORT 0x15000001

//模块基地址错误
#define STATUS_MODULE_EXPORT_MODULE_BASE_ERROR 0x15000002


#define STATUS_DIR_BASE_ERROR 0xDE000001
//调用成功
#define STATUS_OP_SUCCESS  0
//调用失败
#define STATUS_OP_UNSUCCESS 0xC0000001L
#define STATUS_COMMON_PARAM_1       0xC00000EFL
#define STATUS_COMMON_PARAM_2       0xC00000F0L
#define STATUS_COMMON_PARAM_3       0xC00000F1L
#define STATUS_COMMON_PARAM_4       0xC00000F2L
#define STATUS_COMMON_PARAM_5       0xC00000F3L
#define STATUS_COMMON_PARAM_6       0xC00000F4L
#define STATUS_COMMON_PARAM_7       0xC00000F5L
#define STATUS_COMMON_PARAM_8       0xC00000F6L
#define STATUS_COMMON_PARAM_9       0xC00000F7L
//分配内存错误
#define STATUS_COMMON_ALLOC_FAILED       0xC00000EFL
 
#endif // 