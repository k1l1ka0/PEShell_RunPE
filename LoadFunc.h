#pragma once
#include "stdafx.h"

LONG(WINAPI * _NtUnmapViewOfSection)(HANDLE ProcessHandle, PVOID BaseAddress);

BOOL Load_ntdll() {
	HMODULE hNtdll = GetModuleHandle(TEXT("ntdll"));
	if (hNtdll == NULL)
		return FALSE;
	
	_NtUnmapViewOfSection = (LONG(WINAPI*)(HANDLE, PVOID))(GetProcAddress(hNtdll, "NtUnmapViewOfSection"));
	if (_NtUnmapViewOfSection == NULL)
		return FALSE;
	
	return TRUE;
}