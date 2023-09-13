#include "../includes.h"
#include "../SSDT/Functions.h"

namespace sthread { 
	NTSTATUS   MyNtCreateThreadEx(ULONG pid, PVOID ShellCodeAddr, PVOID Argument);
}