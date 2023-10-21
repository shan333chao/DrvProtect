#include "ProtectRoute.h"
#pragma once

NTSTATUS ProtectRoute::StartProtect()
{
	if (Utils::InitOsVersion().dwBuildNumber <= 7601)
	{
		Log("win7 win7win7win7win7win7win7win7win7win7win7win7win7win7win7win7win7win7\n");
		return	ProtectWindow7::StartProtect();
	}
	else {
		return	ProtectWindow::StartProtect();
	}
}

NTSTATUS ProtectRoute::InitProtectWindow()
{
	if (Utils::InitOsVersion().dwBuildNumber <= 7601)
	{
		return	ProtectWindow7::SetProtectWindow();
	}
	else {
		return	ProtectWindow::SetProtectWindow();
	}
}

NTSTATUS ProtectRoute::AntiSnapWindow(ULONG32 hwnd)
{
	if (Utils::InitOsVersion().dwBuildNumber <= 7601)
	{
		return	ProtectWindow7::AntiSnapWindow(hwnd);
	}
	else {
		return	ProtectWindow::AntiSnapWindow(hwnd);
	}

}

BOOLEAN ProtectRoute::RemoveProtectWindow()
{
	if (Utils::InitOsVersion().dwBuildNumber <= 7601)
	{
		return	ProtectWindow7::RemoveProtectWindow();
	}
	else {
		return	ProtectWindow::RemoveProtectWindow();
	}
}

HANDLE ProtectRoute::GetWindowThread(HANDLE hwnd)
{
	if (Utils::InitOsVersion().dwBuildNumber <= 7601)
	{
		return	ProtectWindow7::GetWindowThread(hwnd);
	}
	else {
		return	ProtectWindow::GetWindowThread(hwnd);
	}
}

NTSTATUS ProtectRoute::SetCommHook(CommCallBack callBackFun)
{

 
		return	ProtectWindow::InitCommHook(callBackFun);
 

}

ULONG ProtectRoute::SetValidate(PVOID regCode, ULONG size, ULONG time)
{

	return	ProtectWindow::SetReg(regCode,   size, time);

}

BOOLEAN ProtectRoute::ValidateReg()
{
	return ProtectWindow::ValidateReg();
}
