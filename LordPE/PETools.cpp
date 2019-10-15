#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include <locale.h>
#include "PETools.h"

// ���Դ��ڴ�ӡ
void dbgPrintf(const wchar_t* format, ...)
{
	setlocale(LC_ALL, "");

	wchar_t* strBuffer = (wchar_t*)malloc(100 * sizeof(wchar_t));
	if (!strBuffer)
		return;

	va_list vlArgs;
	va_start(vlArgs, format);
	vswprintf_s(strBuffer, 100, format, vlArgs);
	va_end(vlArgs);
	OutputDebugString(strBuffer);
	free(strBuffer);
}

PIMAGE_DOS_HEADER getDosHeader(void* pFileBuffer)
{
	return (PIMAGE_DOS_HEADER)pFileBuffer;
}

PIMAGE_NT_HEADERS getNTHeader(void* pFileBuffer)
{
	return (PIMAGE_NT_HEADERS)((size_t)pFileBuffer + getDosHeader(pFileBuffer)->e_lfanew);
}

PIMAGE_FILE_HEADER getFileHeader(void* pFileBuffer)
{
	return (PIMAGE_FILE_HEADER)((size_t)getNTHeader(pFileBuffer) + 4);
}

PIMAGE_OPTIONAL_HEADER32 getOptionalHeader(void* pFileBuffer)
{
	return (PIMAGE_OPTIONAL_HEADER32)((size_t)getFileHeader(pFileBuffer) + IMAGE_SIZEOF_FILE_HEADER);
}

PIMAGE_OPTIONAL_HEADER64 getOptionalHeader64(void* pFileBuffer)
{
	return (PIMAGE_OPTIONAL_HEADER64)((size_t)getFileHeader(pFileBuffer) + IMAGE_SIZEOF_FILE_HEADER);
}

PIMAGE_SECTION_HEADER getSectionHeader(void* pFileBuffer)
{
	return (PIMAGE_SECTION_HEADER)((size_t)getOptionalHeader(pFileBuffer) + getFileHeader(pFileBuffer)->SizeOfOptionalHeader);
}

void* rvaToFa(void* pFileBuffer, size_t rva)
{
	if (!pFileBuffer)
	{
		return NULL;
	}

	PIMAGE_FILE_HEADER pFileHeader = getFileHeader(pFileBuffer);
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = getOptionalHeader(pFileBuffer);
	PIMAGE_SECTION_HEADER pSectionHeader = getSectionHeader(pFileBuffer);

	if (rva < pOptionalHeader->SizeOfHeaders)
	{
		return (void*)((size_t)pFileBuffer + rva);
	}

	for (size_t i = 0; i < pFileHeader->NumberOfSections; i++)
	{
		if (rva >= pSectionHeader->VirtualAddress && rva < pSectionHeader->VirtualAddress + pSectionHeader->SizeOfRawData) {
			return (void*)((size_t)pFileBuffer + rva - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData);
		}
		pSectionHeader++;
	}

	dbgPrintf(L"rvaת��ʧ��\n");
	return NULL;
}

void* getDataDirectory(void* pFileBuffer, size_t index)
{
	PIMAGE_DATA_DIRECTORY dataDirectory = NULL;
	if (getOptionalHeader(pFileBuffer)->Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
	{
		dataDirectory = getOptionalHeader(pFileBuffer)->DataDirectory;
	}
	else
	{
		dataDirectory = getOptionalHeader64(pFileBuffer)->DataDirectory;
	}

	size_t dataDirectoryRva = dataDirectory[index].VirtualAddress;
	return dataDirectoryRva ? rvaToFa(pFileBuffer, dataDirectoryRva) : NULL;
}

size_t readPEFile(const wchar_t* pFilePath, void** ppFileBuffer)
{
	if (!pFilePath)
	{
		return 0;
	}

	// ���ļ�
	FILE* pFile = NULL;
	_wfopen_s(&pFile, pFilePath, L"rb");
	if (!pFile)
	{
		dbgPrintf(L"���ļ�ʧ��");
		return 0;
	}

	// �����ļ���С
	fseek(pFile, 0, SEEK_END);
	size_t fileSize = ftell(pFile);
	fseek(pFile, 0, SEEK_SET);

	// �����ڴ�
	void* pFileBuffer = malloc(fileSize);
	if (!pFileBuffer)
	{
		fclose(pFile);
		dbgPrintf(L"�����ڴ�ʧ��");
		return 0;
	}
	memset(pFileBuffer, 0, fileSize);

	// ��ȡ�ļ�
	if (!fread(pFileBuffer, fileSize, 1, pFile))
	{
		fclose(pFile);
		free(pFileBuffer);
		dbgPrintf(L"��ȡ�ļ�ʧ��");
		return 0;
	}

	*ppFileBuffer = pFileBuffer;

	// �ر��ļ�
	fclose(pFile);

	return fileSize;
}