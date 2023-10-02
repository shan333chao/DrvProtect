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


				// 验证节点可读性
				if (MmIsAddressValid(Root->Subsection) && MmIsAddressValid(Root->Subsection->ControlArea))
				{

					if (MmIsAddressValid((PVOID)((Root->Subsection->ControlArea->FilePointer.Value >> 4) << 4)))
					{
						ULONG_PTR fileObj = ((Root->Subsection->ControlArea->FilePointer.Value >> 4) << 4);
						if (fileObj)
						{
							if (wcsstr(((PFILE_OBJECT)fileObj)->FileName.Buffer, szModuleName) != 0) {
								pBuffer->VadInfos[pBuffer->nCnt].pFileObject = fileObj;

								// 得到起始页与结束页
								ULONG64 endptr = (ULONG64)Root->Core.EndingVpnHigh;
								endptr = endptr << 32;

								ULONG64 startptr = (ULONG64)Root->Core.StartingVpnHigh;
								startptr = startptr << 32;

								// 得到根节点
								pBuffer->VadInfos[pBuffer->nCnt].pVad = (ULONG_PTR)Root;

								// 起始页: startingVpn * 0x1000
								pBuffer->VadInfos[pBuffer->nCnt].startVpn = (startptr | Root->Core.StartingVpn) << PAGE_SHIFT;

								// 结束页: EndVpn * 0x1000 + 0xfff
								pBuffer->VadInfos[pBuffer->nCnt].endVpn = ((endptr | Root->Core.EndingVpn) << PAGE_SHIFT) + 0xfff;

								// VAD标志 928 = Mapped    1049088 = Private   ....
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
				// 递归枚举左子树
				EnumVad((PMMVAD)Root->Core.VadNode.Left, pBuffer, nCnt, szModuleName);
			}

			if (MmIsAddressValid(Root->Core.VadNode.Right))
			{
				// 递归枚举右子树
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

		// 通过进程PID得到进程EProcess
		if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)Pid, &Peprocess)))
		{
			// 与偏移相加得到VAD头节点
			Table = (PRTL_AVL_TREE)((UCHAR*)Peprocess + EPROCESS_OFFSET_VADROOT);
			if (!MmIsAddressValid(Table) || !EPROCESS_OFFSET_VADROOT)
			{
				return FALSE;
			}

			__try
			{
				// 取出头节点
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
									// 得到起始页与结束页
									ULONG64 endptr = (ULONG64)Root->Core.EndingVpnHigh;
									endptr = endptr << 32;

									ULONG64 startptr = (ULONG64)Root->Core.StartingVpnHigh;
									startptr = startptr << 32;

									pBuffer->VadInfos[pBuffer->nCnt].pVad = (ULONG_PTR)Root;

									// 起始页: startingVpn * 0x1000
									pBuffer->VadInfos[pBuffer->nCnt].startVpn = (startptr | Root->Core.StartingVpn) << PAGE_SHIFT;

									// 结束页: EndVpn * 0x1000 + 0xfff
									pBuffer->VadInfos[pBuffer->nCnt].endVpn = (endptr | Root->Core.EndingVpn) << PAGE_SHIFT;
									pBuffer->VadInfos[pBuffer->nCnt].flags = Root->Core.u1.Flags.flag;
									pBuffer->nCnt++;
									return FALSE;
								}
							}

						}
					}
				}

				// 枚举左子树
				if (Table->Root->Left)
				{
					EnumVad((MMVAD*)Table->Root->Left, pBuffer, nCnt, szModuleName);
				}

				// 枚举右子树
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

			// 默认有1000个线程
			vad.nSize = sizeof(VAD_INFO) * 0x5000 + sizeof(ULONG);

			// 分配临时空间
			vad.pBuffer = (PALL_VADS)ExAllocatePool(PagedPool, vad.nSize);

			// 根据传入长度得到枚举数量
			ULONG nCount = (vad.nSize - sizeof(ULONG)) / sizeof(VAD_INFO);

			ANSI_STRING aName = { 0 };

			imports::rtl_init_ansi_string(&aName, pcModuleName);

			UNICODE_STRING moduleNameMem = { 0 };
			imports::rtl_ansi_string_to_unicode_string(&moduleNameMem, &aName, TRUE);
			// 枚举VAD
			if (!EnumProcessVad(vad.nPid, vad.pBuffer, nCount, moduleNameMem.Buffer))
			{
				return status;
			}  
			// 输出VAD
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