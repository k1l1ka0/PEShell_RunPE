// PE_Shell.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include "PE_Shell.h"
#include "LoadFunc.h"

_PE_INFO g_pe;


BOOL IsShelled(_PE_INFO pe)
{
	PIMAGE_SECTION_HEADER p = pe.pSectionHeader + pe.pNTHeader->FileHeader.NumberOfSections - 1;
	char pName[8] = { 0 };
	memcpy_s(pName, 8, p, 8);
	if (strcmp(pName, "ShellSec") == 0)
		return TRUE;
	return FALSE;
}



DWORD Encrypt(DWORD key, _PE_INFO& pe, _PE_INFO& shell)
{
	DWORD size = pe.dwFileSize;
	pe.pFileBufferEncrypted = (LPVOID)malloc(size);
	ZeroMemory(pe.pFileBufferEncrypted, size);
	char* encoded_arr = (char*)malloc(size);
	ZeroMemory(encoded_arr, size);
	for (DWORD i = 0;i < pe.dwFileSize;i++) {
		encoded_arr[i] = *(char*)((char*)pe.pFileBuffer + i) ^ key;
	}
	memcpy_s(pe.pFileBufferEncrypted, size, encoded_arr, size);

	DWORD newLength = shell.dwFileSize + ((size - 1) / shell.pNTHeader->OptionalHeader.FileAlignment + 1)*shell.pNTHeader->OptionalHeader.FileAlignment;
	shell.pFileBufferEncrypted = malloc(newLength);
	ZeroMemory(shell.pFileBufferEncrypted, newLength);
	
	InsertNewSection(shell.pFileBuffer, size, encoded_arr, &shell.pFileBufferEncrypted);
	shell.dwFileSize = newLength;
	shell.dwNewSecSize = size;
	free(encoded_arr);
	return 0;
}

LPVOID Decrypt(IN DWORD key, IN _PE_INFO& shell, OUT _PE_INFO& pe)
{
	if (shell.dwNewSecSize == 0)
		return NULL;

	_PE_INFO temp_pe = { 0 };
	temp_pe.dwFileSize = shell.dwNewSecSize;
	temp_pe.pFileBuffer = shell.pFileBufferEncrypted;
	ParsePEInfo(temp_pe);

	PIMAGE_SECTION_HEADER p = temp_pe.pSectionHeader + temp_pe.pNTHeader->FileHeader.NumberOfSections - 1;
	size_t size = p->SizeOfRawData;
	char* decoded_arr = (char*)malloc(size);
	LPVOID buffer = (LPVOID)((DWORD)temp_pe.pFileBuffer + p->PointerToRawData);
	ZeroMemory(decoded_arr, size);
	for (DWORD i = 0;i < size;i++) {
		decoded_arr[i] = *((char*)buffer + i) ^ key;
	}
	pe.pFileBuffer = (LPVOID)malloc(size);
	ZeroMemory(pe.pFileBuffer, size);
	memcpy_s(pe.pFileBuffer, size, decoded_arr, size);
	ParsePEInfo(pe);
	pe.dwFileSize = size;
	return (LPVOID)pe.pFileBuffer;
}

BOOL RunExE(_PE_INFO& pe)
{
	if (!Load_ntdll())
		return FALSE;

	PROCESS_INFORMATION pi = { 0 };
	STARTUPINFO si = { 0 };
	LPCONTEXT pContext;
	PDWORD dwImageBase;

	int count;
	TCHAR CurrentPath[0x1000] = { 0 };

	
	GetModuleFileName(NULL, CurrentPath, 0x1000);
	if (!CreateProcess(
		CurrentPath,
		NULL,
		NULL,
		NULL,
		FALSE,
		CREATE_SUSPENDED,
		NULL,
		NULL,
		&si,
		&pi))
		return FALSE;
	pContext = LPCONTEXT(VirtualAlloc(NULL, sizeof(pContext), MEM_COMMIT, PAGE_READWRITE));
	pContext->ContextFlags = CONTEXT_FULL;
	if (!GetThreadContext(pi.hThread, pContext))
		return FALSE;
	DWORD PEB_addr = pContext->Ebx;
	DWORD dwTargetBase = 0;
	ReadProcessMemory(pi.hProcess, LPVOID(PEB_addr + 8), &dwTargetBase, sizeof(DWORD), NULL);
	//Unmap section
	if (_NtUnmapViewOfSection(pi.hProcess, (LPVOID)dwTargetBase) != ERROR_SUCCESS)
	{
		printf("Unmap Error!\n");
		return FALSE;
	}

	//Try to allocate memory
	LPVOID remoteAddress = VirtualAllocEx(pi.hProcess, (LPVOID)pe.pOptionalHeader->ImageBase, pe.dwImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	const DWORD oldImageBase = pe.pOptionalHeader->ImageBase;
	pe.pOptionalHeader->ImageBase = (DWORD)remoteAddress;

	//Copy to Image
	pe.pImageBuffer = (LPVOID)malloc(pe.dwImageSize);
	CopyFileBufferToImageBuffer(pe.pFileBuffer, &pe.pImageBuffer);

	//Relocate
	if (oldImageBase != (DWORD)remoteAddress)
	{
		if (!FixReloc((DWORD)remoteAddress, pe)) {
			printf("Relocation error\n");
			return FALSE;
		}
	}
	
	//Write to Process Memory
	DWORD dwBytesWritten = 0;
	WriteProcessMemory(pi.hProcess, remoteAddress, pe.pImageBuffer, pe.dwImageSize, &dwBytesWritten);
	if (dwBytesWritten != pe.dwImageSize) {
		printf("Write Process Memory Failed!\n");
		return FALSE;
	}

	//Overwrite imagebase in PEB
	DWORD r_addr = (DWORD)remoteAddress;
	if (!WriteProcessMemory(pi.hProcess, LPVOID(PEB_addr + 8), &r_addr, sizeof(DWORD), &dwBytesWritten)) {
		printf("Error writing PEB!\n");
		return FALSE;
	}

	//Overwrite context
	DWORD newEP = (DWORD)remoteAddress + pe.pOptionalHeader->AddressOfEntryPoint;
	pContext->Eax = newEP;
	SetThreadContext(pi.hThread, pContext);

	//Start injected
	ResumeThread(pi.hThread);

	::CloseHandle(pi.hProcess);
	::CloseHandle(pi.hThread);

	return TRUE;
}


VOID Test()
{
	TCHAR* szFilePath = TEXT("..//PUTTY.exe");
	g_pe = { 0 };
	ReadFileToMemory(szFilePath, g_pe);
	ParsePEInfo(g_pe);
	RunExE(g_pe);
	_PE_INFO shell = { 0 };
	TCHAR szCurrentFileName[MAX_PATH] = { 0 };
	GetModuleFileName(NULL, szCurrentFileName, MAX_PATH);
	ReadFileToMemory(szCurrentFileName, shell);
	ParsePEInfo(shell);
	Encrypt(0x12, g_pe, shell);
	TCHAR szNewFileName[MAX_PATH] = { 0 };
	DWORD len = sizeof(szCurrentFileName);
	memcpy_s(szNewFileName, len, szCurrentFileName, len);
	DWORD t = _tcslen(szCurrentFileName);
	memcpy_s(szNewFileName + t-4, 10 * sizeof(TCHAR), TEXT("_shell.exe"), 10 * sizeof(TCHAR));
	_PE_INFO original_pe = { 0 };
	Decrypt(0x12, shell, original_pe);
//	MemoryToFile(original_pe.pFileBuffer, original_pe.dwFileSize, TEXT("test.exe"));
//	RunExE(original_pe);

//	MemoryToFile(shell.pFileBufferEncrypted, shell.dwFileSize, szNewFileName);
}

DWORD _tmain()
{
	Test();
	return 0;
}

