#include "VadModules.h"
namespace VadModules {
	USHORT EPROCESS_OFFSET_VADROOT = 0;
	VOID EnumVad(PMMVAD Root, PALL_VADS pBuffer, ULONG nCnt, wchar_t* szModuleName)
	{
		if (!Root || !pBuffer || !nCnt)
		{
			return;
		}

		__try
		{
			if (nCnt > pBuffer->nCnt)
			{


				// ��֤�ڵ�ɶ���
				if (MmIsAddressValid(Root->Subsection) && MmIsAddressValid(Root->Subsection->ControlArea))
				{

					if (MmIsAddressValid((PVOID)((Root->Subsection->ControlArea->FilePointer.Value >> 4) << 4)))
					{
						ULONG_PTR fileObj = ((Root->Subsection->ControlArea->FilePointer.Value >> 4) << 4);
						if (fileObj)
						{
							if (wcsstr(((PFILE_OBJECT)fileObj)->FileName.Buffer, szModuleName) != 0) {
								pBuffer->VadInfos[pBuffer->nCnt].pFileObject = fileObj;

								// �õ���ʼҳ�����ҳ
								ULONG64 endptr = (ULONG64)Root->Core.EndingVpnHigh;
								endptr = endptr << 32;

								ULONG64 startptr = (ULONG64)Root->Core.StartingVpnHigh;
								startptr = startptr << 32;

								// �õ����ڵ�
								pBuffer->VadInfos[pBuffer->nCnt].pVad = (ULONG_PTR)Root;

								// ��ʼҳ: startingVpn * 0x1000
								pBuffer->VadInfos[pBuffer->nCnt].startVpn = (startptr | Root->Core.StartingVpn) << PAGE_SHIFT;

								// ����ҳ: EndVpn * 0x1000 + 0xfff
								pBuffer->VadInfos[pBuffer->nCnt].endVpn = ((endptr | Root->Core.EndingVpn) << PAGE_SHIFT) + 0xfff;

								// VAD��־ 928 = Mapped    1049088 = Private   ....
								pBuffer->VadInfos[pBuffer->nCnt].flags = Root->Core.u1.Flags.flag;
								pBuffer->nCnt++;
								return;
							}
						}
					}
				}

			}

			if (MmIsAddressValid(Root->Core.VadNode.Left))
			{
				// �ݹ�ö��������
				EnumVad((PMMVAD)Root->Core.VadNode.Left, pBuffer, nCnt, szModuleName);
			}

			if (MmIsAddressValid(Root->Core.VadNode.Right))
			{
				// �ݹ�ö��������
				EnumVad((PMMVAD)Root->Core.VadNode.Right, pBuffer, nCnt, szModuleName);
			}
		}
		__except (1)
		{
		}
	}

	BOOLEAN EnumProcessVad(ULONG Pid, PALL_VADS pBuffer, ULONG nCnt, wchar_t* szModuleName)
	{
		PEPROCESS Peprocess = 0;
		PRTL_AVL_TREE Table = NULL;
		PMMVAD Root = NULL;

		// ͨ������PID�õ�����EProcess
		if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)Pid, &Peprocess)))
		{
			// ��ƫ����ӵõ�VADͷ�ڵ�
			Table = (PRTL_AVL_TREE)((UCHAR*)Peprocess + EPROCESS_OFFSET_VADROOT);
			if (!MmIsAddressValid(Table) || !EPROCESS_OFFSET_VADROOT)
			{
				return FALSE;
			}

			__try
			{
				// ȡ��ͷ�ڵ�
				Root = (PMMVAD)Table->Root;

				if (nCnt > pBuffer->nCnt)
				{
					if (MmIsAddressValid(Root->Subsection) && MmIsAddressValid(Root->Subsection->ControlArea))
					{
						if (MmIsAddressValid((PVOID)((Root->Subsection->ControlArea->FilePointer.Value >> 4) << 4)))
						{
							ULONG_PTR fileObj = ((Root->Subsection->ControlArea->FilePointer.Value >> 4) << 4);
							if (fileObj)
							{
								if (wcsstr(((PFILE_OBJECT)fileObj)->FileName.Buffer, szModuleName) != 0) {
									pBuffer->VadInfos[pBuffer->nCnt].pFileObject = fileObj;
									// �õ���ʼҳ�����ҳ
									ULONG64 endptr = (ULONG64)Root->Core.EndingVpnHigh;
									endptr = endptr << 32;

									ULONG64 startptr = (ULONG64)Root->Core.StartingVpnHigh;
									startptr = startptr << 32;

									pBuffer->VadInfos[pBuffer->nCnt].pVad = (ULONG_PTR)Root;

									// ��ʼҳ: startingVpn * 0x1000
									pBuffer->VadInfos[pBuffer->nCnt].startVpn = (startptr | Root->Core.StartingVpn) << PAGE_SHIFT;

									// ����ҳ: EndVpn * 0x1000 + 0xfff
									pBuffer->VadInfos[pBuffer->nCnt].endVpn = (endptr | Root->Core.EndingVpn) << PAGE_SHIFT;
									pBuffer->VadInfos[pBuffer->nCnt].flags = Root->Core.u1.Flags.flag;
									pBuffer->nCnt++;
									return FALSE;
								}
							}

						}
					}
				}

				// ö��������
				if (Table->Root->Left)
				{
					EnumVad((MMVAD*)Table->Root->Left, pBuffer, nCnt, szModuleName);
				}

				// ö��������
				if (Table->Root->Right)
				{
					EnumVad((MMVAD*)Table->Root->Right, pBuffer, nCnt, szModuleName);
				}
			}
			__finally
			{
				ObDereferenceObject(Peprocess);
			}
		}
		else
		{
			return FALSE;
		}

		return TRUE;
	}


	NTSTATUS GetModuleBaseInVAD(ULONG pid, PCHAR pcModuleName, PULONG_PTR pModuleBase) {
		static USHORT vad_root_address = 0;
		if (!vad_root_address)
		{
			USHORT vadOffset = *(PUSHORT)(imports::imported.ps_get_process_exit_status + 2);
			vadOffset += 4;
			vad_root_address = vadOffset;
			EPROCESS_OFFSET_VADROOT = vad_root_address;
		}
		NTSTATUS status = STATUS_UNSUCCESSFUL;
		__try
		{
			VADProcess vad = { 0 };

			vad.nPid = pid;

			// Ĭ����1000���߳�
			vad.nSize = sizeof(VAD_INFO) * 0x5000 + sizeof(ULONG);

			// ������ʱ�ռ�
			vad.pBuffer = (PALL_VADS)ExAllocatePool(PagedPool, vad.nSize);

			// ���ݴ��볤�ȵõ�ö������
			ULONG nCount = (vad.nSize - sizeof(ULONG)) / sizeof(VAD_INFO);

			ANSI_STRING aName = { 0 };

			imports::rtl_init_ansi_string(&aName, pcModuleName);

			UNICODE_STRING moduleNameMem = { 0 };
			imports::rtl_ansi_string_to_unicode_string(&moduleNameMem, &aName, TRUE);
			// ö��VAD
			if (!EnumProcessVad(vad.nPid, vad.pBuffer, nCount, moduleNameMem.Buffer))
			{
				return status;
			}  
			// ���VAD
			for (size_t i = 0; i < vad.pBuffer->nCnt; i++)
			{
				Log("StartVPN = %p | ", vad.pBuffer->VadInfos[i].startVpn);
				Log("EndVPN = %p | ", vad.pBuffer->VadInfos[i].endVpn);
				Log("PVAD = %p | ", vad.pBuffer->VadInfos[i].pVad);
				Log("Flags = %d | ", vad.pBuffer->VadInfos[i].flags);
				PFILE_OBJECT  file = (PFILE_OBJECT)vad.pBuffer->VadInfos[i].pFileObject;
				Log("Flags = %wZ \r\n", file->FileName);

				if (wcsstr(file->FileName.Buffer, moduleNameMem.Buffer) != 0)
				{
					*pModuleBase = vad.pBuffer->VadInfos[i].startVpn;
					status = STATUS_SUCCESS;
					break;
				}
			}
			imports::rtl_free_unicode_string(&moduleNameMem);
			imports::ex_free_pool_with_tag(vad.pBuffer, 0);
		}
		__except (1)
		{
			status = STATUS_UNSUCCESSFUL;
		}
		return status;
	}
}