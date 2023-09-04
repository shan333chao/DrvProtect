#pragma once
#include <ntifs.h>
#include <ntimage.h>
#include "DelMySelf.h"

 

PUCHAR LoadDriver(PDRIVER_OBJECT pDriver, PUNICODE_STRING pReg);


//解密
VOID DecryptDriverData();
//拉伸pe
PUCHAR FileBufferToImageBuffer();
//修复重定位
void Relocation(PUCHAR imageBuffer);
//修复导入表
VOID RepairImportData(PUCHAR pImageBuffer);
//修复cookie
void Repaircookie(PUCHAR imagebuffer); //修复高版本驱动在低版本操作系统运行驱动的兼容性,所有系统都会检查cookie的安全标记进行对比，如果是系统本身加载的就会自己修，比如win10，但是我们自己加载进内存的得自己修
//启动驱动
void RunDriver(PUCHAR imageBuffer);
//清理pe无用信息
void ClearPeSection(PUCHAR imageBuffer);


