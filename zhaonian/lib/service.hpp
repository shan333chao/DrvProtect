#pragma once
#include <Windows.h>
#include <string>
#include <filesystem>
#include "nt.hpp"

namespace service
{
	ULONG RegisterAndStart(const std::wstring& driver_path,const std::wstring& driver_name);
	bool StopAndRemove(const std::wstring& driver_name);
};