#pragma once
#ifndef IMPORTS_H
#define IMPORTS_H 
#include <ntifs.h>
#define VentroAPI  



struct _m_imported
{

	uintptr_t mm_get_system_routine_address;
	uintptr_t mm_map_io_space;
	uintptr_t io_get_device_object_pointer;
	uintptr_t mm_get_physical_address;
	uintptr_t mm_is_address_valid;
	uintptr_t ke_delay_execution_thread;
	uintptr_t ex_allocate_pool_with_tag;
	uintptr_t ex_get_previous_mode;
	uintptr_t ps_create_system_thread;
	uintptr_t zw_close;
	uintptr_t nt_trace_control;
	uintptr_t mm_build_mdl_for_non_paged_pool;
	uintptr_t ps_get_process_exit_status;
	uintptr_t ps_reference_primary_token;
	uintptr_t ps_get_process_wow64_process;
	uintptr_t ps_get_process_image_file_name;
	uintptr_t ps_reference_process_file_pointer;
	uintptr_t ke_initialize_guarded_mutex;
	uintptr_t ke_acquire_guarded_mutex;
	uintptr_t ke_release_guarded_mutex;
	uintptr_t ps_get_process_id;
	uintptr_t ps_get_current_process_id;
	uintptr_t ps_get_current_thread_id;
	uintptr_t ps_get_process_session_id;
	uintptr_t zw_create_file;
	uintptr_t zw_query_information_file;
	uintptr_t zw_read_file;
	uintptr_t rtl_compare_memory;
	uintptr_t rtl_image_nt_header;
	uintptr_t ex_allocate_pool;
	uintptr_t zw_query_system_information;
	uintptr_t ex_free_pool_with_tag;
	uintptr_t rtl_init_ansi_string;
	uintptr_t rtl_ansi_string_to_unicode_string;
	uintptr_t mm_copy_virtual_memory;
	uintptr_t io_get_current_process;

	uintptr_t ps_get_process_peb;
	uintptr_t ob_reference_object_safe;
	uintptr_t zw_allocate_virtual_memory;
	uintptr_t rtl_compare_unicode_string;
	uintptr_t rtl_free_unicode_string;
	uintptr_t obf_dereference_object;
	uintptr_t mm_copy_memory;
	uintptr_t ps_get_process_section_base_address;
	uintptr_t zw_query_virtual_memory;
	uintptr_t zw_free_virtual_memory;
	uintptr_t io_create_driver;
	uintptr_t io_allocate_mdl;
	uintptr_t mm_probe_and_lock_pages;
	uintptr_t mm_map_locked_pages_specify_cache;
	uintptr_t mm_protect_mdl_system_address;
	uintptr_t mm_unmap_locked_pages;
	uintptr_t mm_unlock_pages;
	uintptr_t io_free_mdl;
	uintptr_t iof_complete_request;
	uintptr_t rtl_init_unicode_string;
	uintptr_t ex_raise_hard_error;

	uintptr_t io_delete_device;
	uintptr_t io_create_device;
	uintptr_t rtl_get_version;
	uintptr_t mm_map_io_space_ex;
	uintptr_t mm_unmap_io_space;
	uintptr_t mm_get_physical_memory_ranges;

	uintptr_t mm_get_virtual_for_physical;

	uintptr_t ke_stack_attach_process;
	uintptr_t ke_unstack_detach_process;
	uintptr_t io_query_file_dos_device_name;
	uintptr_t ps_get_thread_process;
	uintptr_t ke_get_current_thread;
	uintptr_t mm_user_probe_address;
	uintptr_t rtl_find_exported_routine_by_name;
	uintptr_t ex_release_resource_lite;
	uintptr_t ex_acquire_resource_exclusive_lite;
	uintptr_t rtl_random_ex;
	uintptr_t rtl_avl_remove_node;
	uintptr_t ke_query_time_increment;
	uintptr_t ps_initial_system_process;
	uintptr_t ps_get_process_exit_process_called;

};
namespace imports {




	extern struct _m_imported imported;

	VentroAPI ULONG	ke_query_time_increment(VOID);



	VentroAPI PEPROCESS ps_initial_system_process();

	VentroAPI BOOLEAN ps_get_process_exit_process_called(PEPROCESS eprocess);

	VentroAPI ULONG rtl_random_ex(PULONG Seed);
	VOID FASTCALL ex_release_resource_lite(PERESOURCE Resource);
	BOOLEAN		ex_acquire_resource_exclusive_lite(
		_Inout_ _Requires_lock_not_held_(*_Curr_)
		_When_(return != 0, _Acquires_exclusive_lock_(*_Curr_))
		PERESOURCE Resource,
		_In_ _Literal_ BOOLEAN Wait
	);
	VentroAPI PVOID rtl_find_exported_routine_by_name(_In_ PVOID ImageBase, _In_ PCCH RoutineName);

	VentroAPI PKTHREAD ke_get_current_thread(VOID);

	VentroAPI PEPROCESS ps_get_thread_process(PETHREAD Thread);

	VentroAPI NTSTATUS io_query_file_dos_device_name(_In_  PFILE_OBJECT FileObject, _Out_ POBJECT_NAME_INFORMATION* ObjectNameInformation);
	VentroAPI NTSTATUS zw_protect_virtual_memory(__in HANDLE ProcessHandle, __inout PVOID* BaseAddress, __inout PSIZE_T RegionSize, __in ULONG NewProtectWin32, __out PULONG OldProtect);
	VentroAPI PVOID ke_stack_attach_process(PRKPROCESS PROCESS, PRKAPC_STATE ApcState);

	VentroAPI PVOID ke_unstack_detach_process(PRKAPC_STATE ApcState);

	VentroAPI PVOID mm_get_system_routine_address(PUNICODE_STRING SystemRoutineName);
	VentroAPI PVOID mm_map_io_space(_In_ PHYSICAL_ADDRESS PhysicalAddress, _In_ SIZE_T NumberOfBytes, _In_ MEMORY_CACHING_TYPE CacheType);


	VentroAPI NTSTATUS io_get_device_object_pointer(_In_  PUNICODE_STRING ObjectName, _In_  ACCESS_MASK DesiredAccess, _Out_ PFILE_OBJECT* FileObject, _Out_ PDEVICE_OBJECT* DeviceObject);


	VentroAPI PHYSICAL_ADDRESS mm_get_physical_address(PVOID BaseAddress);


	VentroAPI BOOLEAN mm_is_address_valid(PVOID VirtualAddress);

	VentroAPI NTSTATUS ke_delay_execution_thread(_In_ KPROCESSOR_MODE WaitMode, _In_ BOOLEAN Alertable, _In_ PLARGE_INTEGER Interval);


	VentroAPI PVOID ex_allocate_pool_with_tag(POOL_TYPE PoolType, _In_ SIZE_T NumberOfBytes, _In_ ULONG Tag);


	VentroAPI KPROCESSOR_MODE ex_get_previous_mode(VOID);


	VentroAPI NTSTATUS ps_create_system_thread(_Out_ PHANDLE ThreadHandle, _In_ ULONG DesiredAccess, _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes, _In_opt_  HANDLE ProcessHandle, PCLIENT_ID ClientId, PKSTART_ROUTINE StartRoutine, PVOID StartContext);

	VentroAPI NTSTATUS zw_close(HANDLE Handle);

	VentroAPI NTSTATUS nt_trace_control(ULONG FunctionCode, PVOID InBuffer, ULONG InBufferLen, PVOID OutBuffer, ULONG OutBufferLen, PULONG ReturnLength);


	VentroAPI VOID mm_build_mdl_for_non_paged_pool(PMDL MemoryDescriptorList);

	VentroAPI NTSTATUS ps_get_process_exit_status(PEPROCESS Process);


	VentroAPI PACCESS_TOKEN ps_reference_primary_token(PEPROCESS Process);

	VentroAPI PVOID ps_get_process_wow64_process(PEPROCESS Process);


	VentroAPI PCHAR ps_get_process_image_file_name(PEPROCESS Process);
	VentroAPI NTSTATUS ps_reference_process_file_pointer(IN PEPROCESS Process, OUT PVOID* OutFileObject);
	VentroAPI VOID ke_initialize_guarded_mutex(PKGUARDED_MUTEX Mutex);

	VentroAPI VOID ke_acquire_guarded_mutex(PKGUARDED_MUTEX Mutex);
	VentroAPI VOID ke_release_guarded_mutex(PKGUARDED_MUTEX Mutex);

	VentroAPI HANDLE ps_get_process_id(PEPROCESS Process);
	VentroAPI HANDLE ps_get_current_process_id(VOID);

	VentroAPI HANDLE ps_get_current_thread_id(VOID);


	VentroAPI ULONG ps_get_process_session_id(PEPROCESS Process);

	VentroAPI NTSTATUS zw_create_file(_Out_ PHANDLE FileHandle, _In_ ACCESS_MASK DesiredAccess, _In_ POBJECT_ATTRIBUTES ObjectAttributes, _Out_ PIO_STATUS_BLOCK IoStatusBlock, _In_opt_ PLARGE_INTEGER AllocationSize, _In_ ULONG FileAttributes, _In_ ULONG ShareAccess, _In_ ULONG CreateDisposition, _In_ ULONG CreateOptions, _In_reads_bytes_opt_(EaLength) PVOID EaBuffer, _In_ ULONG EaLength);



	VentroAPI NTSTATUS zw_query_information_file(_In_ HANDLE FileHandle, _Out_ PIO_STATUS_BLOCK IoStatusBlock, _Out_writes_bytes_(Length) PVOID FileInformation, _In_ ULONG Length, _In_ FILE_INFORMATION_CLASS FileInformationClass);

	VentroAPI NTSTATUS zw_read_file(_In_ HANDLE FileHandle, _In_opt_ HANDLE Event, _In_opt_ PIO_APC_ROUTINE ApcRoutine, _In_opt_ PVOID ApcContext, _Out_ PIO_STATUS_BLOCK IoStatusBlock, _Out_writes_bytes_(Length) PVOID Buffer, _In_ ULONG Length, _In_opt_ PLARGE_INTEGER ByteOffset, _In_opt_ PULONG Key);


	VentroAPI SIZE_T rtl_compare_memory(VOID* Source1, VOID* Source2, _In_ SIZE_T Length);

	VentroAPI PIMAGE_NT_HEADERS rtl_image_nt_header(PVOID kernelBase);



	VentroAPI NTSTATUS rtl_get_version(PRTL_OSVERSIONINFOW lpVersionInformation);

	VentroAPI PVOID mm_map_io_space_ex(PHYSICAL_ADDRESS PhysicalAddress, SIZE_T NumberOfBytes, ULONG Protect);

	VentroAPI VOID mm_unmap_io_space(PVOID BaseAddress, SIZE_T NumberOfBytes);

	VentroAPI PPHYSICAL_MEMORY_RANGE mm_get_physical_memory_ranges();

	VentroAPI NTSTATUS zw_query_system_information(ULONG SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);

	VentroAPI PVOID ex_allocate_pool(POOL_TYPE PoolType, SIZE_T NumberOfBytes);

	VentroAPI BOOLEAN ob_reference_object_safe(PVOID Object);

	VentroAPI void ex_free_pool_with_tag(PVOID P, ULONG TAG);



	VentroAPI VOID rtl_init_ansi_string(PANSI_STRING DestinationString, PCSZ SourceString);

	VentroAPI NTSTATUS rtl_ansi_string_to_unicode_string(PUNICODE_STRING DestinationString, PCANSI_STRING SourceString, BOOLEAN AllocateDestinationString);

	VentroAPI NTSTATUS mm_copy_virtual_memory(PEPROCESS SourceProcess, PVOID SourceAddress, PEPROCESS TargetProcess, PVOID TargetAddress, SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode, PSIZE_T ReturnSize);

	VentroAPI PEPROCESS io_get_current_process();

	VentroAPI NTSTATUS zw_allocate_virtual_memory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);



	VentroAPI PPEB ps_get_process_peb(PEPROCESS Process);

	VentroAPI LONG rtl_compare_unicode_string(PCUNICODE_STRING String1, PCUNICODE_STRING String2, BOOLEAN CaseInSensitive);

	VentroAPI VOID rtl_free_unicode_string(PUNICODE_STRING UnicodeString);

	VentroAPI LONG_PTR obf_dereference_object(PVOID Object);

#if (NTDDI_VERSION >= NTDDI_WIN8)
	VentroAPI NTSTATUS mm_copy_memory(PVOID TargetAddress, MM_COPY_ADDRESS SourceAddress, SIZE_T NumberOfBytes, ULONG Flags, PSIZE_T NumberOfBytesTransferred);
#endif


	VentroAPI PVOID ps_get_process_section_base_address(PEPROCESS Process);

	VentroAPI NTSTATUS zw_query_virtual_memory(HANDLE ProcessHandle, PVOID BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength);

	VentroAPI NTSTATUS zw_free_virtual_memory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeType);

	VentroAPI NTSTATUS io_create_driver(PUNICODE_STRING Driver, PDRIVER_INITIALIZE INIT);

	VentroAPI PMDL io_allocate_mdl(PVOID VirtualAddress, ULONG Length, BOOLEAN SecondaryBuffer, BOOLEAN ChargeQuota, PIRP Irp);

	VentroAPI VOID mm_probe_and_lock_pages(PMDL MemoryDescriptorList, KPROCESSOR_MODE AccessMode, LOCK_OPERATION Operation);

	VentroAPI PVOID mm_map_locked_pages_specify_cache(PMDL MemoryDescriptorList, KPROCESSOR_MODE AccessMode, MEMORY_CACHING_TYPE CacheType, PVOID RequestedAddress, ULONG BugCheckOnFailure, ULONG Priority);

	VentroAPI NTSTATUS mm_protect_mdl_system_address(PMDL MemoryDescriptorList, ULONG NewProtect);

	VentroAPI VOID mm_unmap_locked_pages(PVOID BaseAddress, PMDL MemoryDescriptorList);

	VentroAPI VOID mm_unlock_pages(PMDL MemoryDescriptorList);

	VentroAPI VOID io_free_mdl(PMDL Mdl);

	VentroAPI VOID iof_complete_request(PIRP Irp, CCHAR PriorityBoost);

	VentroAPI VOID rtl_init_unicode_string(PUNICODE_STRING DestinationString, PCWSTR SourceString);

	VentroAPI VOID io_delete_device(PDEVICE_OBJECT DeviceObject);

	VentroAPI NTSTATUS io_create_device(PDRIVER_OBJECT DriverObject, ULONG DeviceExtensionSize, PUNICODE_STRING DeviceName, DEVICE_TYPE DeviceType, ULONG DeviceCharacteristics, BOOLEAN Exclusive, PDEVICE_OBJECT* DeviceObject);

}

#endif
