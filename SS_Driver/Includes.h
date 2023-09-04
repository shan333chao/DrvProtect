 

/* ��� ifdef ����C �� C++ ʹ��ͷ�ļ���*/
#ifdef __cplusplus
extern "C"
{
#endif

#include <ntifs.h>

#include "Tools/Log.h"
#include "Tools/Utils.h"
#include "Tools/PE.h"
#include "Tools/DefineCommon.h"
#include "Comm/Comm.h"
#include "Comm/CommStructs.h"
#include "Memmory/Memory.h"
#include "Memmory/PMemory.h"
#include "Process/FakeProcess.h"
#include "Process/Process.h"
#include "Thread/SThread.h"
#include "SSDT/Functions.h"
#include "SSDT/NTDLL.h"
#include "SSDT/ssdt.h"
#include "SSDT/Win32uDLL.h"
#include "SFile/FileUtil.h"
 
#ifdef __cplusplus
}
#endif
 