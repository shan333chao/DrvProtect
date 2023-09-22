#pragma once
#include "imports.h" 





namespace imports {

	struct _m_imported imported = { 0 };


	VentroAPI PDEVICE_OBJECT io_get_device_attachment_base_ref(PDEVICE_OBJECT DeviceObject) {
	
		return reinterpret_cast<PDEVICE_OBJECT(*)(PDEVICE_OBJECT)> (imported.io_get_device_attachment_base_ref)(DeviceObject);
	}

	PDEVICE_OBJECT io_get_related_device_object(PFILE_OBJECT FileObject) {
		return reinterpret_cast<PDEVICE_OBJECT(*)(PFILE_OBJECT)> (imported.io_get_related_device_object)(FileObject);

	}


	VOID FASTCALL ex_release_resource_lite(PERESOURCE Resource) {
		return reinterpret_cast<VOID(*)(PERESOURCE)> (imported.ex_release_resource_lite)(Resource);
	}

	BOOLEAN		ex_acquire_resource_exclusive_lite(
		_Inout_ _Requires_lock_not_held_(*_Curr_)
		_When_(return != 0, _Acquires_exclusive_lock_(*_Curr_))
		PERESOURCE Resource,
		_In_ _Literal_ BOOLEAN Wait
	) {
		return reinterpret_cast<BOOLEAN(*)(PERESOURCE, BOOLEAN)> (imported.ex_acquire_resource_exclusive_lite)(Resource, Wait);

	}


	VentroAPI NTSTATUS ob_reference_object_by_handle_with_tag(
		HANDLE Handle,
		ACCESS_MASK DesiredAccess,
		POBJECT_TYPE ObjectType,
		KPROCESSOR_MODE AccessMode,
		ULONG Tag,
		PVOID* Object,
		POBJECT_HANDLE_INFORMATION HandleInformation
	) {

		return reinterpret_cast<NTSTATUS(*)(HANDLE, ACCESS_MASK, POBJECT_TYPE, KPROCESSOR_MODE, ULONG, PVOID*, POBJECT_HANDLE_INFORMATION)> (imported.ob_reference_object_by_handle_with_tag)(Handle, DesiredAccess, ObjectType, AccessMode, Tag, Object, HandleInformation);
	}

	VentroAPI ULONG rtl_random_ex(PULONG Seed) {
		return reinterpret_cast<ULONG(*)(PULONG)> (imported.rtl_random_ex)(Seed);
	}
	VentroAPI NTSTATUS ob_close_handle(HANDLE Handle, KPROCESSOR_MODE PreviousMode) {
		return reinterpret_cast<NTSTATUS(*)(HANDLE, KPROCESSOR_MODE)> (imported.ob_close_handle)(Handle, PreviousMode);
	}
	VentroAPI NTSTATUS 	 io_create_file_ex(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG Disposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength, CREATE_FILE_TYPE CreateFileType, PVOID InternalParameters, ULONG Options, PIO_DRIVER_CREATE_CONTEXT DriverContext) {

		return reinterpret_cast<NTSTATUS(*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG, CREATE_FILE_TYPE, PVOID, ULONG, PIO_DRIVER_CREATE_CONTEXT)> (imported.io_create_file_ex)(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, Disposition, CreateOptions, EaBuffer, EaLength, CreateFileType, InternalParameters, Options, DriverContext);
	}

	VentroAPI PVOID	rtl_lookup_element_generic_table_avl(_In_ PRTL_AVL_TABLE Table, _In_ PVOID Buffer) {
		return reinterpret_cast<PVOID(*)(PRTL_AVL_TABLE, PVOID)> (imported.rtl_lookup_element_generic_table_avl)(Table, Buffer);
	}

	VentroAPI BOOLEAN rtl_delete_element_generic_table_avl(_In_ PRTL_AVL_TABLE Table, _In_ PVOID Buffer) {
		return reinterpret_cast<BOOLEAN(*)(PRTL_AVL_TABLE, PVOID)> (imported.rtl_delete_element_generic_table_avl)(Table, Buffer);

	}
	VentroAPI VOID ex_delete_lookaside_list_ex(PLOOKASIDE_LIST_EX Lookaside) {

		return reinterpret_cast<VOID(*)(PLOOKASIDE_LIST_EX)> (imported.ex_delete_lookaside_list_ex)(Lookaside);
	}

	VentroAPI	NTSTATUS ex_initialize_lookaside_list_ex(_Out_ PLOOKASIDE_LIST_EX Lookaside, _In_opt_ PALLOCATE_FUNCTION_EX Allocate, _In_opt_ PFREE_FUNCTION_EX Free, _In_ POOL_TYPE PoolType, _In_ ULONG Flags, _In_ SIZE_T Size, _In_ ULONG Tag, _In_ USHORT Depth) {

		return reinterpret_cast<NTSTATUS(*)(PLOOKASIDE_LIST_EX, PALLOCATE_FUNCTION_EX, PFREE_FUNCTION_EX, POOL_TYPE, ULONG, SIZE_T, ULONG, USHORT)> (imported.ex_initialize_lookaside_list_ex)(Lookaside, Allocate, Free, PoolType, Flags, Size, Tag, Depth);
	}


	VentroAPI BOOLEAN mm_flush_image_section(_In_ PSECTION_OBJECT_POINTERS SectionObjectPointer, _In_ MMFLUSH_TYPE FlushType) {

		return reinterpret_cast<BOOLEAN(*)(PSECTION_OBJECT_POINTERS, MMFLUSH_TYPE)> (imported.mm_flush_image_section)(SectionObjectPointer, FlushType);
	}

	VentroAPI NTSTATUS zw_delete_file(_In_ POBJECT_ATTRIBUTES ObjectAttributes) {

		return reinterpret_cast<NTSTATUS(*)(POBJECT_ATTRIBUTES)> (imported.zw_delete_file)(ObjectAttributes);
	}


	VentroAPI  NTSTATUS rtl_delete_registry_value(ULONG RelativeTo, PCWSTR Path, PCWSTR ValueName) {

		return reinterpret_cast<NTSTATUS(*)(ULONG, PCWSTR, PCWSTR)> (imported.rtl_delete_registry_value)(RelativeTo, Path, ValueName);
	}
	VentroAPI NTSTATUS zw_open_key(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes)
	{
		return reinterpret_cast<NTSTATUS(*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES)> (imported.zw_open_key)(KeyHandle, DesiredAccess, ObjectAttributes);

	}

	VentroAPI NTSTATUS zw_delete_key(HANDLE KeyHandle)
	{
		return reinterpret_cast<NTSTATUS(*)(HANDLE)> (imported.zw_delete_key)(KeyHandle);
	}

	VentroAPI PVOID rtl_find_exported_routine_by_name(_In_ PVOID ImageBase, _In_ PCCH RoutineName)
	{
		return reinterpret_cast<PVOID(*)(PVOID, PCCH)> (imported.rtl_find_exported_routine_by_name)(ImageBase, RoutineName);
	}

	VentroAPI PKTHREAD ke_get_current_thread(VOID)
	{
		return reinterpret_cast<PKTHREAD(*)(VOID)> (imported.ke_get_current_thread)();
	}

	VentroAPI PEPROCESS ps_get_thread_process(PETHREAD Thread)
	{
		return reinterpret_cast<PEPROCESS(*)(PETHREAD)> (imported.ps_get_thread_process)(Thread);
	}

	VentroAPI NTSTATUS io_query_file_dos_device_name(_In_  PFILE_OBJECT FileObject, _Out_ POBJECT_NAME_INFORMATION* ObjectNameInformation)
	{
		return reinterpret_cast<NTSTATUS(*)(PFILE_OBJECT, POBJECT_NAME_INFORMATION*)> (imported.io_query_file_dos_device_name)(FileObject, ObjectNameInformation);
	}

	VentroAPI PVOID ke_stack_attach_process(PRKPROCESS PROCESS, PRKAPC_STATE ApcState)
	{
		return reinterpret_cast<PVOID(*)(PRKPROCESS, PRKAPC_STATE)> (imported.ke_stack_attach_process)(PROCESS, ApcState);
	}

	VentroAPI PVOID ke_unstack_detach_process(PRKAPC_STATE ApcState)
	{
		return reinterpret_cast<PVOID(*)(PRKAPC_STATE)> (imported.ke_unstack_detach_process)(ApcState);
	}

	VentroAPI PVOID mm_get_system_routine_address(PUNICODE_STRING SystemRoutineName)
	{
		return reinterpret_cast<PVOID(*)(PUNICODE_STRING)> (imported.mm_get_system_routine_address)(SystemRoutineName);
	}

	VentroAPI PVOID mm_map_io_space(_In_ PHYSICAL_ADDRESS PhysicalAddress, _In_ SIZE_T NumberOfBytes, _In_ MEMORY_CACHING_TYPE CacheType)
	{
		return reinterpret_cast<PVOID(*)(PHYSICAL_ADDRESS, SIZE_T, MEMORY_CACHING_TYPE)> (imported.mm_map_io_space)(PhysicalAddress, NumberOfBytes, CacheType);
	}


	VentroAPI NTSTATUS io_get_device_object_pointer(_In_  PUNICODE_STRING ObjectName, _In_  ACCESS_MASK DesiredAccess, _Out_ PFILE_OBJECT* FileObject, _Out_ PDEVICE_OBJECT* DeviceObject)
	{
		return reinterpret_cast<NTSTATUS(*)(PUNICODE_STRING, ACCESS_MASK, PFILE_OBJECT*, PDEVICE_OBJECT*)> (imported.io_get_device_object_pointer)(ObjectName, DesiredAccess, FileObject, DeviceObject);
	}


	VentroAPI PHYSICAL_ADDRESS mm_get_physical_address(PVOID BaseAddress)
	{
		return reinterpret_cast<PHYSICAL_ADDRESS(*)(PVOID)> (imported.mm_get_physical_address)(BaseAddress);
	}


	VentroAPI BOOLEAN mm_is_address_valid(PVOID VirtualAddress)
	{
		return reinterpret_cast<BOOLEAN(*)(PVOID)> (imported.mm_is_address_valid)(VirtualAddress);
	}


	VentroAPI NTSTATUS ke_delay_execution_thread(_In_ KPROCESSOR_MODE WaitMode, _In_ BOOLEAN Alertable, _In_ PLARGE_INTEGER Interval)
	{
		return reinterpret_cast<NTSTATUS(*)(KPROCESSOR_MODE, BOOLEAN, PLARGE_INTEGER)> (imported.ke_delay_execution_thread)(WaitMode, Alertable, Interval);
	}


	VentroAPI PVOID ex_allocate_pool_with_tag(POOL_TYPE PoolType, _In_ SIZE_T NumberOfBytes, _In_ ULONG Tag)
	{
		return reinterpret_cast<PVOID(*)(POOL_TYPE, SIZE_T, ULONG)> (imported.ex_allocate_pool_with_tag)(PoolType, NumberOfBytes, Tag);
	}


	VentroAPI KPROCESSOR_MODE ex_get_previous_mode(VOID)
	{
		return reinterpret_cast<KPROCESSOR_MODE(*)(VOID)> (imported.ex_get_previous_mode)();
	}


	VentroAPI NTSTATUS ps_create_system_thread(_Out_ PHANDLE ThreadHandle, _In_ ULONG DesiredAccess, _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes, _In_opt_  HANDLE ProcessHandle, PCLIENT_ID ClientId, PKSTART_ROUTINE StartRoutine, PVOID StartContext)
	{
		return reinterpret_cast<NTSTATUS(*)(PHANDLE, ULONG, POBJECT_ATTRIBUTES, HANDLE, PCLIENT_ID, PKSTART_ROUTINE, PVOID)> (imported.ps_create_system_thread)(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, ClientId, StartRoutine, StartContext);
	}

	VentroAPI NTSTATUS zw_close(HANDLE Handle)
	{
		return reinterpret_cast<NTSTATUS(*)(HANDLE)> (imported.zw_close)(Handle);
	}

	VentroAPI NTSTATUS nt_trace_control(ULONG FunctionCode, PVOID InBuffer, ULONG InBufferLen, PVOID OutBuffer, ULONG OutBufferLen, PULONG ReturnLength)
	{
		return reinterpret_cast<NTSTATUS(*)(ULONG, PVOID, ULONG, PVOID, ULONG, PULONG)> (imported.nt_trace_control)(FunctionCode, InBuffer, InBufferLen, OutBuffer, OutBufferLen, ReturnLength);
	}


	VentroAPI VOID mm_build_mdl_for_non_paged_pool(PMDL MemoryDescriptorList)
	{
		return reinterpret_cast<VOID(*)(PMDL)> (imported.mm_build_mdl_for_non_paged_pool)(MemoryDescriptorList);
	}


	VentroAPI NTSTATUS ps_get_process_exit_status(PEPROCESS Process)
	{
		return reinterpret_cast<NTSTATUS(*)(PEPROCESS)> (imported.ps_get_process_exit_status)(Process);
	}


	VentroAPI PACCESS_TOKEN ps_reference_primary_token(PEPROCESS Process)
	{
		return reinterpret_cast<PACCESS_TOKEN(*)(PEPROCESS)> (imported.ps_reference_primary_token)(Process);
	}

	VentroAPI PVOID ps_get_process_wow64_process(PEPROCESS Process)
	{
		return reinterpret_cast<PVOID(*)(PEPROCESS)> (imported.ps_get_process_wow64_process)(Process);
	}


	VentroAPI PUCHAR ps_get_process_image_file_name(PEPROCESS Process)
	{
		return reinterpret_cast<PUCHAR(*)(PEPROCESS)> (imported.ps_get_process_image_file_name)(Process);
	}
	VentroAPI NTSTATUS ps_reference_process_file_pointer(IN PEPROCESS Process, OUT PVOID* OutFileObject)
	{
		return reinterpret_cast<NTSTATUS(*)(PEPROCESS, PVOID*)> (imported.ps_reference_process_file_pointer)(Process, OutFileObject);
	}
	VentroAPI VOID ke_initialize_guarded_mutex(PKGUARDED_MUTEX Mutex)
	{
		return reinterpret_cast<VOID(*)(PKGUARDED_MUTEX)> (imported.ke_initialize_guarded_mutex)(Mutex);
	}

	VentroAPI VOID ke_acquire_guarded_mutex(PKGUARDED_MUTEX Mutex)
	{
		return reinterpret_cast<VOID(*)(PKGUARDED_MUTEX)> (imported.ke_acquire_guarded_mutex)(Mutex);
	}
	VentroAPI VOID ke_release_guarded_mutex(PKGUARDED_MUTEX Mutex)
	{
		return reinterpret_cast<VOID(*)(PKGUARDED_MUTEX)> (imported.ke_release_guarded_mutex)(Mutex);
	}

	VentroAPI HANDLE ps_get_process_id(PEPROCESS Process)
	{
		return reinterpret_cast<HANDLE(*)(PEPROCESS)> (imported.ps_get_process_id)(Process);
	}
	VentroAPI HANDLE ps_get_current_process_id(VOID)
	{
		return reinterpret_cast<HANDLE(*)(VOID)> (imported.ps_get_current_process_id)();
	}

	VentroAPI HANDLE ps_get_current_thread_id(VOID)
	{
		return reinterpret_cast<HANDLE(*)(VOID)> (imported.ps_get_current_thread_id)();
	}


	VentroAPI ULONG ps_get_process_session_id(PEPROCESS Process)
	{
		return reinterpret_cast<ULONG(*)(PEPROCESS)> (imported.ps_get_process_session_id)(Process);
	}

	VentroAPI NTSTATUS zw_create_file(_Out_ PHANDLE FileHandle, _In_ ACCESS_MASK DesiredAccess, _In_ POBJECT_ATTRIBUTES ObjectAttributes, _Out_ PIO_STATUS_BLOCK IoStatusBlock, _In_opt_ PLARGE_INTEGER AllocationSize, _In_ ULONG FileAttributes, _In_ ULONG ShareAccess, _In_ ULONG CreateDisposition, _In_ ULONG CreateOptions, _In_reads_bytes_opt_(EaLength) PVOID EaBuffer, _In_ ULONG EaLength)
	{
		return reinterpret_cast<NTSTATUS(*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG)> (imported.zw_create_file)(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
	}



	VentroAPI NTSTATUS zw_query_information_file(_In_ HANDLE FileHandle, _Out_ PIO_STATUS_BLOCK IoStatusBlock, _Out_writes_bytes_(Length) PVOID FileInformation, _In_ ULONG Length, _In_ FILE_INFORMATION_CLASS FileInformationClass)
	{
		return reinterpret_cast<NTSTATUS(*)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS)> (imported.zw_query_information_file)(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
	}

	VentroAPI NTSTATUS zw_read_file(_In_ HANDLE FileHandle, _In_opt_ HANDLE Event, _In_opt_ PIO_APC_ROUTINE ApcRoutine, _In_opt_ PVOID ApcContext, _Out_ PIO_STATUS_BLOCK IoStatusBlock, _Out_writes_bytes_(Length) PVOID Buffer, _In_ ULONG Length, _In_opt_ PLARGE_INTEGER ByteOffset, _In_opt_ PULONG Key)
	{
		return reinterpret_cast<NTSTATUS(*)(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG)> (imported.zw_read_file)(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
	}


	VentroAPI SIZE_T rtl_compare_memory(VOID* Source1, VOID* Source2, _In_ SIZE_T Length)
	{
		return reinterpret_cast<SIZE_T(*)(VOID*, VOID*, SIZE_T)> (imported.rtl_compare_memory)(Source1, Source2, Length);
	}

	VentroAPI PIMAGE_NT_HEADERS rtl_image_nt_header(PVOID kernelBase)
	{
		return reinterpret_cast<PIMAGE_NT_HEADERS(*)(PVOID)> (imported.rtl_image_nt_header)(kernelBase);
	}



	VentroAPI NTSTATUS rtl_get_version(PRTL_OSVERSIONINFOW lpVersionInformation)
	{
		return reinterpret_cast<NTSTATUS(*)(PRTL_OSVERSIONINFOW)> (imported.rtl_get_version)(lpVersionInformation);
	}

	VentroAPI PVOID mm_map_io_space_ex(PHYSICAL_ADDRESS PhysicalAddress, SIZE_T NumberOfBytes, ULONG Protect)
	{
		return reinterpret_cast<PVOID(*)(PHYSICAL_ADDRESS, SIZE_T, ULONG)>(imported.mm_map_io_space_ex)(PhysicalAddress, NumberOfBytes, Protect);
	}

	VentroAPI VOID mm_unmap_io_space(PVOID BaseAddress, SIZE_T NumberOfBytes)
	{
		return reinterpret_cast<VOID(*)(PVOID, SIZE_T)>(imported.mm_unmap_io_space)(BaseAddress, NumberOfBytes);
	}

	VentroAPI PPHYSICAL_MEMORY_RANGE mm_get_physical_memory_ranges()
	{
		return reinterpret_cast<PPHYSICAL_MEMORY_RANGE(*)()>(imported.mm_get_physical_memory_ranges)();
	}

	VentroAPI NTSTATUS zw_query_system_information(ULONG SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength)
	{
		return reinterpret_cast<NTSTATUS(*)(ULONG, PVOID, ULONG, PULONG)> (imported.zw_query_system_information)(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
	}

	VentroAPI PVOID ex_allocate_pool(POOL_TYPE PoolType, SIZE_T NumberOfBytes)
	{
		return reinterpret_cast<PVOID(*)(POOL_TYPE, SIZE_T)>(imported.ex_allocate_pool)(PoolType, NumberOfBytes);
	}

	VentroAPI BOOLEAN ob_reference_object_safe(PVOID Object)
	{
		return reinterpret_cast<BOOLEAN(*)(PVOID)> (imported.ob_reference_object_safe)(Object);
	}

	VentroAPI void ex_free_pool_with_tag(PVOID P, ULONG TAG)
	{
		return reinterpret_cast<void(*)(PVOID, ULONG)> (imported.ex_free_pool_with_tag)(P, TAG);
	}



	VentroAPI VOID rtl_init_ansi_string(PANSI_STRING DestinationString, PCSZ SourceString)
	{
		return reinterpret_cast<VOID(*)(PANSI_STRING, PCSZ)> (imported.rtl_init_ansi_string)(DestinationString, SourceString);
	}

	VentroAPI NTSTATUS rtl_ansi_string_to_unicode_string(PUNICODE_STRING DestinationString, PCANSI_STRING SourceString, BOOLEAN AllocateDestinationString)
	{
		return reinterpret_cast<NTSTATUS(*)(PUNICODE_STRING, PCANSI_STRING, BOOLEAN)> (imported.rtl_ansi_string_to_unicode_string)(DestinationString, SourceString, AllocateDestinationString);
	}

	VentroAPI NTSTATUS mm_copy_virtual_memory(PEPROCESS SourceProcess, PVOID SourceAddress, PEPROCESS TargetProcess, PVOID TargetAddress, SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode, PSIZE_T ReturnSize)
	{
		return reinterpret_cast<NTSTATUS(*)(PEPROCESS, PVOID, PEPROCESS, PVOID, SIZE_T, KPROCESSOR_MODE, PSIZE_T)> (imported.mm_copy_virtual_memory)(SourceProcess, SourceAddress, TargetProcess, TargetAddress, BufferSize, PreviousMode, ReturnSize);
	}

	VentroAPI PEPROCESS io_get_current_process()
	{
		return reinterpret_cast<PEPROCESS(*)()> (imported.io_get_current_process)();
	}

	VentroAPI NTSTATUS zw_allocate_virtual_memory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect)
	{
		return reinterpret_cast<NTSTATUS(*)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG)> (imported.zw_allocate_virtual_memory)(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
	}

	VentroAPI NTSTATUS ps_lookup_process_by_process_id(HANDLE ProcessId, PEPROCESS* Process)
	{
		return reinterpret_cast<NTSTATUS(*)(HANDLE, PEPROCESS*)> (imported.ps_lookup_process_by_process_id)(ProcessId, Process);
	}

	VentroAPI PPEB ps_get_process_peb(PEPROCESS Process)
	{
		return reinterpret_cast<PPEB(*)(PEPROCESS)> (imported.ps_get_process_peb)(Process);
	}

	VentroAPI LONG rtl_compare_unicode_string(PCUNICODE_STRING String1, PCUNICODE_STRING String2, BOOLEAN CaseInSensitive)
	{
		return reinterpret_cast<LONG(*)(PCUNICODE_STRING, PCUNICODE_STRING, BOOLEAN)> (imported.rtl_compare_unicode_string)(String1, String2, CaseInSensitive);
	}

	VentroAPI VOID rtl_free_unicode_string(PUNICODE_STRING UnicodeString)
	{
		return reinterpret_cast<VOID(*)(PUNICODE_STRING)> (imported.rtl_free_unicode_string)(UnicodeString);
	}

	VentroAPI LONG_PTR obf_dereference_object(PVOID Object)
	{
		return reinterpret_cast<LONG_PTR(*)(PVOID)>(imported.obf_dereference_object)(Object);
	}

#if (NTDDI_VERSION >= NTDDI_WIN8)
	VentroAPI NTSTATUS mm_copy_memory(PVOID TargetAddress, MM_COPY_ADDRESS SourceAddress, SIZE_T NumberOfBytes, ULONG Flags, PSIZE_T NumberOfBytesTransferred)
	{
		return reinterpret_cast<NTSTATUS(*)(PVOID, MM_COPY_ADDRESS, SIZE_T, ULONG, PSIZE_T)>(imported.mm_copy_memory)(TargetAddress, SourceAddress, NumberOfBytes, Flags, NumberOfBytesTransferred);
	}
#endif


	VentroAPI PVOID ps_get_process_section_base_address(PEPROCESS Process)
	{
		return reinterpret_cast<PVOID(*)(PEPROCESS)>(imported.ps_get_process_section_base_address)(Process);
	}

	VentroAPI NTSTATUS zw_query_virtual_memory(HANDLE ProcessHandle, PVOID BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength)
	{
		return reinterpret_cast<NTSTATUS(*)(HANDLE, PVOID, MEMORY_INFORMATION_CLASS, PVOID, SIZE_T, PSIZE_T)>(imported.zw_query_virtual_memory)(ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation, MemoryInformationLength, ReturnLength);
	}

	VentroAPI NTSTATUS zw_free_virtual_memory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeType)
	{
		return reinterpret_cast<NTSTATUS(*)(HANDLE, PVOID*, PSIZE_T, ULONG)>(imported.zw_free_virtual_memory)(ProcessHandle, BaseAddress, RegionSize, FreeType);
	}

	VentroAPI NTSTATUS io_create_driver(PUNICODE_STRING Driver, PDRIVER_INITIALIZE INIT)
	{
		return reinterpret_cast<NTSTATUS(*)(PUNICODE_STRING, PDRIVER_INITIALIZE)>(imported.io_create_driver)(Driver, INIT);
	}

	VentroAPI PMDL io_allocate_mdl(PVOID VirtualAddress, ULONG Length, BOOLEAN SecondaryBuffer, BOOLEAN ChargeQuota, PIRP Irp)
	{
		return reinterpret_cast<PMDL(*)(PVOID, ULONG, BOOLEAN, BOOLEAN, PIRP)>(imported.io_allocate_mdl)(VirtualAddress, Length, SecondaryBuffer, ChargeQuota, Irp);
	}

	VentroAPI VOID mm_probe_and_lock_pages(PMDL MemoryDescriptorList, KPROCESSOR_MODE AccessMode, LOCK_OPERATION Operation)
	{
		return reinterpret_cast<VOID(*)(PMDL, KPROCESSOR_MODE, LOCK_OPERATION)>(imported.mm_probe_and_lock_pages)(MemoryDescriptorList, AccessMode, Operation);
	}

	VentroAPI PVOID mm_map_locked_pages_specify_cache(PMDL MemoryDescriptorList, KPROCESSOR_MODE AccessMode, MEMORY_CACHING_TYPE CacheType, PVOID RequestedAddress, ULONG BugCheckOnFailure, ULONG Priority)
	{
		return reinterpret_cast<PVOID(*)(PMDL, KPROCESSOR_MODE, MEMORY_CACHING_TYPE, PVOID, ULONG, ULONG)>(imported.mm_map_locked_pages_specify_cache)(MemoryDescriptorList, AccessMode, CacheType, RequestedAddress, BugCheckOnFailure, Priority);
	}

	VentroAPI NTSTATUS mm_protect_mdl_system_address(PMDL MemoryDescriptorList, ULONG NewProtect)
	{
		return reinterpret_cast<NTSTATUS(*)(PMDL, ULONG)>(imported.mm_protect_mdl_system_address)(MemoryDescriptorList, NewProtect);
	}

	VentroAPI VOID mm_unmap_locked_pages(PVOID BaseAddress, PMDL MemoryDescriptorList)
	{
		return reinterpret_cast<VOID(*)(PVOID, PMDL)>(imported.mm_unmap_locked_pages)(BaseAddress, MemoryDescriptorList);
	}

	VentroAPI VOID mm_unlock_pages(PMDL MemoryDescriptorList)
	{
		return reinterpret_cast<VOID(*)(PMDL)>(imported.mm_unlock_pages)(MemoryDescriptorList);
	}

	VentroAPI VOID io_free_mdl(PMDL Mdl)
	{
		return reinterpret_cast<VOID(*)(PMDL)>(imported.io_free_mdl)(Mdl);
	}

	VentroAPI VOID iof_complete_request(PIRP Irp, CCHAR PriorityBoost)
	{
		return reinterpret_cast<VOID(*)(PIRP, CCHAR)>(imported.iof_complete_request)(Irp, PriorityBoost);
	}

	VentroAPI VOID rtl_init_unicode_string(PUNICODE_STRING DestinationString, PCWSTR SourceString)
	{
		return reinterpret_cast<VOID(*)(PUNICODE_STRING, PCWSTR)>(imported.rtl_init_unicode_string)(DestinationString, SourceString);
	}

	VentroAPI VOID io_delete_device(PDEVICE_OBJECT DeviceObject)
	{
		return reinterpret_cast<VOID(*)(PDEVICE_OBJECT)>(imported.io_delete_device)(DeviceObject);
	}

	VentroAPI NTSTATUS io_create_device(PDRIVER_OBJECT DriverObject, ULONG DeviceExtensionSize, PUNICODE_STRING DeviceName, DEVICE_TYPE DeviceType, ULONG DeviceCharacteristics, BOOLEAN Exclusive, PDEVICE_OBJECT* DeviceObject)
	{
		return reinterpret_cast<NTSTATUS(*)(PDRIVER_OBJECT, ULONG, PUNICODE_STRING, DEVICE_TYPE, ULONG, BOOLEAN, PDEVICE_OBJECT*)>(imported.io_create_device)(DriverObject, DeviceExtensionSize, DeviceName, DeviceType, DeviceCharacteristics, Exclusive, DeviceObject);
	}



}
