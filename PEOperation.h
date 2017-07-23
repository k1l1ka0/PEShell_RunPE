#pragma once
#include "stdafx.h"

struct _PE_INFO
{
	HANDLE hFile;
	TCHAR* lpszFileName;
	DWORD dwFileSize;
	DWORD dwNewSecSize;
	DWORD dwImageSize;
	DWORD dwHeaderSize;
	LPVOID pFileBuffer;
	LPVOID pFileBufferEncrypted;
	LPVOID pImageBuffer;
	PIMAGE_DOS_HEADER pDosHeader;
	DWORD dwSignature;
	PIMAGE_FILE_HEADER pFileHeader;
	PIMAGE_NT_HEADERS pNTHeader;
	PIMAGE_NT_HEADERS32 pNTHeader32;
	PIMAGE_NT_HEADERS64 pNTHeader64;
	PIMAGE_OPTIONAL_HEADER pOptionalHeader;
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader32;
	PIMAGE_OPTIONAL_HEADER64 pOptionalHeader64;
	PIMAGE_SECTION_HEADER pSectionHeader;
};

BOOL ReadFileToMemory(TCHAR* szFileName, _PE_INFO& pe)
{
	if (szFileName == NULL) {
		return FALSE;
	}
	pe.hFile = CreateFile(
		szFileName,
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (pe.hFile == INVALID_HANDLE_VALUE)
		return FALSE;
	pe.dwFileSize = GetFileSize(pe.hFile, NULL);
	pe.pFileBuffer = (LPVOID)malloc(pe.dwFileSize);
	ZeroMemory(pe.pFileBuffer, pe.dwFileSize);
	DWORD dwBytesRead = -1;
	ReadFile(pe.hFile, pe.pFileBuffer, pe.dwFileSize, &dwBytesRead, NULL);
	::CloseHandle(pe.hFile);
	if (dwBytesRead != pe.dwFileSize)
		return FALSE;
	
	return TRUE;
}

BOOL ParsePEInfo(_PE_INFO& pe)
{
	// Parse PE info
	pe.pDosHeader = (PIMAGE_DOS_HEADER)pe.pFileBuffer;
	pe.pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pe.pFileBuffer + pe.pDosHeader->e_lfanew);
	pe.pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pe.pFileBuffer + pe.pDosHeader->e_lfanew + 4);
	pe.pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pe.pFileBuffer + \
		pe.pDosHeader->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + pe.pNTHeader->FileHeader.SizeOfOptionalHeader);
	pe.pOptionalHeader = (PIMAGE_OPTIONAL_HEADER)((DWORD)pe.pFileBuffer + pe.pDosHeader->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER));
	pe.dwImageSize = pe.pOptionalHeader->SizeOfImage;
	pe.dwHeaderSize = pe.pOptionalHeader->SizeOfHeaders;


	if (pe.pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		printf("Not Valid PE file!\n");
		return FALSE;
	}

	return TRUE;

}

BOOL MemoryToFile(IN LPVOID pMemBuffer, IN size_t size, OUT LPCWCHAR lpszFile)
{
	HANDLE pFile;
	DWORD dwBytesWritten = 0;
	pFile = CreateFile(lpszFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	if (pFile == INVALID_HANDLE_VALUE) {
		MessageBox(NULL, TEXT("创建文件失败"), TEXT("PE Tool"), NULL);
		::CloseHandle(pFile);
		return FALSE;
	}
	WriteFile(pFile, pMemBuffer, size, &dwBytesWritten, NULL);
	if (dwBytesWritten != size) {
		MessageBox(NULL, TEXT("写入文件失败"), TEXT("PE Tool"), NULL);
		::CloseHandle(pFile);
		return FALSE;
	}

	::CloseHandle(pFile);
	return TRUE;
}

DWORD CopyFileBufferToImageBuffer(IN LPVOID pFileBuffer, OUT LPVOID* pImageFileBuffer)
{

	PIMAGE_DOS_HEADER mpDosHeader = NULL;
	PIMAGE_NT_HEADERS mpNTHeader = NULL;
	PIMAGE_FILE_HEADER mpPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 mpOptionalHeader32 = NULL;
	PIMAGE_OPTIONAL_HEADER64 mpOptionalHeader64 = NULL;
	PIMAGE_SECTION_HEADER mpSectionHeader = NULL;

	DWORD dwmImageSize = 0;
	DWORD dwmHeaderSize = 0;

	mpDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	mpNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer + mpDosHeader->e_lfanew);
	mpPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pFileBuffer + mpDosHeader->e_lfanew + 4);
	mpSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pFileBuffer + mpDosHeader->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + mpNTHeader->FileHeader.SizeOfOptionalHeader);
	if (mpPEHeader->Machine == 0x014c) {
		mpOptionalHeader32 = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pFileBuffer + mpDosHeader->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER));
		//		pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pFileBuffer + pDosHeader->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER32));
		dwmImageSize = mpOptionalHeader32->SizeOfImage;
		dwmHeaderSize = mpOptionalHeader32->SizeOfHeaders;
	}
	else if (mpPEHeader->Machine == 0x8664) {
		mpOptionalHeader64 = (PIMAGE_OPTIONAL_HEADER64)((DWORD)pFileBuffer + mpDosHeader->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER));
		//		pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pFileBuffer + pDosHeader->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER64));
		dwmImageSize = mpOptionalHeader64->SizeOfImage;
		dwmHeaderSize = mpOptionalHeader64->SizeOfHeaders;
	}


	DWORD dwSizeCopied = 0;
	char* pImage = NULL;

	if (!(pImage = (char*)malloc(dwmImageSize * sizeof(char)))) {
		printf("Error allocating memory for Image File");
		return 0;
	}

	memset(pImage, 0, dwmImageSize);

	//Copy PE Header
	memcpy_s(pImage, dwmHeaderSize, pFileBuffer, dwmHeaderSize);
	//	char* pFile = (char*)pFileBuffer;

	dwSizeCopied += dwmHeaderSize;
	//Copy Section data

	for (int i = 0; i < mpNTHeader->FileHeader.NumberOfSections;i++)
	{
		char* pFile = (char*)((DWORD)pFileBuffer + (mpSectionHeader + i)->PointerToRawData);
		//		DWORD tSize = (mpSectionHeader + i)->SizeOfRawData > (mpSectionHeader + i)->Misc.VirtualSize ? (mpSectionHeader + i)->SizeOfRawData : (mpSectionHeader + i)->Misc.VirtualSize;
		memcpy_s((LPVOID)((DWORD)pImage + (mpSectionHeader + i)->VirtualAddress), (mpSectionHeader + i)->SizeOfRawData, (LPVOID)pFile, (mpSectionHeader + i)->SizeOfRawData);
		dwSizeCopied += (mpSectionHeader + i)->SizeOfRawData;
	}

	*pImageFileBuffer = (LPVOID)pImage;
	//	free(pImage);
	return dwSizeCopied;
}

BOOL IsNullSection(IMAGE_SECTION_HEADER SectionHeader)
{
	if ((SectionHeader.Misc.VirtualSize + SectionHeader.PointerToRawData + SectionHeader.SizeOfRawData + SectionHeader.VirtualAddress + SectionHeader.Characteristics) == 0)
		return TRUE;
	return FALSE;
}

DWORD InsertNewSection(IN LPVOID pFileBuffer, IN size_t n, IN LPVOID pSectionContent, OUT LPVOID* pNewBuffer)
{
	LPVOID mpNewBuffer = NULL;

	const IMAGE_SECTION_HEADER NullSectionHeader = { 00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00 };

	PIMAGE_DOS_HEADER mpDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	PIMAGE_NT_HEADERS mpNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer + mpDosHeader->e_lfanew);
	PIMAGE_SECTION_HEADER mpSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pFileBuffer + mpDosHeader->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + mpNTHeader->FileHeader.SizeOfOptionalHeader);

	size_t unaligned_n = n;
	n = ((n - 1) / mpNTHeader->OptionalHeader.FileAlignment + 1)*mpNTHeader->OptionalHeader.FileAlignment;

	DWORD dwFileSize = (mpSectionHeader + mpNTHeader->FileHeader.NumberOfSections - 1)->PointerToRawData + (mpSectionHeader + mpNTHeader->FileHeader.NumberOfSections - 1)->SizeOfRawData + n;

	if (!(mpNewBuffer = (LPVOID)malloc(dwFileSize))) {
		printf("Error allocating memory for new buffer.\n");
		return 0;
	}

	memset(mpNewBuffer, 0, dwFileSize);
	memcpy_s(mpNewBuffer, (dwFileSize - n), pFileBuffer, (dwFileSize - n));

	mpDosHeader = (PIMAGE_DOS_HEADER)mpNewBuffer;
	mpNTHeader = (PIMAGE_NT_HEADERS)((DWORD)mpNewBuffer + mpDosHeader->e_lfanew);
	mpSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)mpNewBuffer + mpDosHeader->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + mpNTHeader->FileHeader.SizeOfOptionalHeader);

	if (((mpSectionHeader->PointerToRawData - (DWORD)mpSectionHeader + (DWORD)mpNewBuffer) >= (mpNTHeader->FileHeader.NumberOfSections + 1) * 0x28) && \
		IsNullSection(*(mpSectionHeader + mpNTHeader->FileHeader.NumberOfSections)))
	{

		//Insert new section table
		PIMAGE_SECTION_HEADER mpFirstSection = (PIMAGE_SECTION_HEADER)mpSectionHeader;
		mpSectionHeader += mpNTHeader->FileHeader.NumberOfSections;
		mpNTHeader->FileHeader.NumberOfSections++;
		mpNTHeader->OptionalHeader.SizeOfImage += n;
		//copy the first section header into the last;
		memcpy_s(mpSectionHeader, sizeof(IMAGE_SECTION_HEADER), mpFirstSection, sizeof(IMAGE_SECTION_HEADER));
		*(mpSectionHeader + 1) = NullSectionHeader;
		memcpy_s(mpSectionHeader, 0x8, "ShellSec", 0x8);
		mpSectionHeader->Misc.VirtualSize = n;
		DWORD tmpSize = (mpSectionHeader - 1)->SizeOfRawData > (mpSectionHeader - 1)->Misc.VirtualSize ? (mpSectionHeader - 1)->SizeOfRawData : (mpSectionHeader - 1)->Misc.VirtualSize;
		mpSectionHeader->VirtualAddress = (mpSectionHeader - 1)->VirtualAddress + ((int)((tmpSize - 1) / mpNTHeader->OptionalHeader.SectionAlignment) + 1)*(mpNTHeader->OptionalHeader.SectionAlignment);
		mpSectionHeader->SizeOfRawData = n;
		mpSectionHeader->PointerToRawData = (mpSectionHeader - 1)->PointerToRawData + (mpSectionHeader - 1)->SizeOfRawData;
		mpSectionHeader->Characteristics |= (0x60000020);
		//Copy section content into new section
		PBYTE pSecCont = (PBYTE)((DWORD)mpNewBuffer + mpSectionHeader->PointerToRawData);
		//memcpy_s(pSecCont, unaligned_n, pSectionContent, unaligned_n);
		memcpy_s(pSecCont, n, pSectionContent, n);

		*pNewBuffer = mpNewBuffer;
		return (DWORD)mpSectionHeader->PointerToRawData;
	}
	return 0;
}

DWORD RvaToRaw(IN PIMAGE_SECTION_HEADER pSectionHeader, IN PIMAGE_NT_HEADERS pNTHeader, IN DWORD dwRva)
{
	size_t i = 0;
	PIMAGE_SECTION_HEADER mpSectionHeader = pSectionHeader;
	if (dwRva == 0 || dwRva <= pNTHeader->OptionalHeader.SizeOfHeaders)
		return dwRva;
	for (i = 0;i < pNTHeader->FileHeader.NumberOfSections;i++) {
		if (dwRva >= mpSectionHeader->VirtualAddress&&dwRva < mpSectionHeader->VirtualAddress + mpSectionHeader->Misc.VirtualSize)
			break;
		mpSectionHeader++;
	}
	return (dwRva - mpSectionHeader->VirtualAddress + mpSectionHeader->PointerToRawData);
}

//Fix relocation, if flag = 0, fix in file; else fix in memory 
BOOL FixReloc(IN DWORD dwLoadImageBase, _PE_INFO& pe, DWORD flag=0)
{
	DWORD dwIncrement = dwLoadImageBase - pe.pOptionalHeader->ImageBase;
	if (pe.pOptionalHeader->DataDirectory[5].VirtualAddress == 0)
		return FALSE;
	PIMAGE_BASE_RELOCATION pReloc = (PIMAGE_BASE_RELOCATION)((DWORD)pe.pFileBuffer + RvaToRaw(pe.pSectionHeader, pe.pNTHeader, pe.pOptionalHeader->DataDirectory[5].VirtualAddress));

	while (pReloc->SizeOfBlock && pReloc->SizeOfBlock < 0x100000)
	{
		PDWORD pTypeOffset = (PDWORD)((DWORD)pReloc + sizeof(IMAGE_BASE_RELOCATION));
		DWORD dwCount = (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

		for (int i = 0;i < dwCount;i++)
		{
			if (!*pTypeOffset)			//不需要重定位
				continue;
			DWORD dwPointerToRva = (*pTypeOffset & 0x0FFF) + pReloc->VirtualAddress;
			PDWORD pRelocItem = (PDWORD)((DWORD)pe.pFileBuffer + RvaToRaw(pe.pSectionHeader, pe.pNTHeader, dwPointerToRva));
			*(pRelocItem) += dwIncrement;
			pTypeOffset++;
		}

		pReloc = (PIMAGE_BASE_RELOCATION)((DWORD)pReloc + pReloc->SizeOfBlock);
	}
	return TRUE;
}
