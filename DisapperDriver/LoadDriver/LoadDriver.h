#pragma once
#include <ntifs.h>
#include <ntimage.h>
#include "DelMySelf.h"

 

PUCHAR LoadDriver(PDRIVER_OBJECT pDriver, PUNICODE_STRING pReg);


//����
VOID DecryptDriverData();
//����pe
PUCHAR FileBufferToImageBuffer();
//�޸��ض�λ
void Relocation(PUCHAR imageBuffer);
//�޸������
VOID RepairImportData(PUCHAR pImageBuffer);
//�޸�cookie
void Repaircookie(PUCHAR imagebuffer); //�޸��߰汾�����ڵͰ汾����ϵͳ���������ļ�����,����ϵͳ������cookie�İ�ȫ��ǽ��жԱȣ������ϵͳ������صľͻ��Լ��ޣ�����win10�����������Լ����ؽ��ڴ�ĵ��Լ���
//��������
void RunDriver(PUCHAR imageBuffer);
//����pe������Ϣ
void ClearPeSection(PUCHAR imageBuffer);


