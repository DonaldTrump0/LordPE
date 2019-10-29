#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include <locale.h>
#include "PETools.h"

PIMAGE_DOS_HEADER getDosHeader(void* pFileBuffer) {
	return (PIMAGE_DOS_HEADER)pFileBuffer;
}

PIMAGE_NT_HEADERS getNTHeader(void* pFileBuffer) {
	return (PIMAGE_NT_HEADERS)((size_t)pFileBuffer + getDosHeader(pFileBuffer)->e_lfanew);
}

PIMAGE_FILE_HEADER getFileHeader(void* pFileBuffer) {
	return (PIMAGE_FILE_HEADER)((size_t)getNTHeader(pFileBuffer) + 4);
}

PIMAGE_OPTIONAL_HEADER32 getOptionalHeader32(void* pFileBuffer) {
	return (PIMAGE_OPTIONAL_HEADER32)((size_t)getFileHeader(pFileBuffer) + IMAGE_SIZEOF_FILE_HEADER);
}

PIMAGE_OPTIONAL_HEADER64 getOptionalHeader64(void* pFileBuffer) {
	return (PIMAGE_OPTIONAL_HEADER64)((size_t)getFileHeader(pFileBuffer) + IMAGE_SIZEOF_FILE_HEADER);
}

PIMAGE_SECTION_HEADER getFirstSectionHeader(void* pFileBuffer) {
	return (PIMAGE_SECTION_HEADER)((size_t)getOptionalHeader32(pFileBuffer) + getFileHeader(pFileBuffer)->SizeOfOptionalHeader);
}

PIMAGE_SECTION_HEADER getLastSectionHeader(void* pFileBuffer) {
	return getFirstSectionHeader(pFileBuffer) + getFileHeader(pFileBuffer)->NumberOfSections - 1;
}

void dbgPrintf(const wchar_t* format, ...) {
	setlocale(LC_ALL, "");

	wchar_t strBuffer[100];
	va_list vlArgs;
	va_start(vlArgs, format);
	vswprintf_s(strBuffer, 100, format, vlArgs);
	va_end(vlArgs);

	OutputDebugString(strBuffer);
}

void* getDataDirectory(void* pFileBuffer, size_t index) {
	PIMAGE_DATA_DIRECTORY dataDirectory = NULL;
	if (getOptionalHeader32(pFileBuffer)->Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
		dataDirectory = getOptionalHeader32(pFileBuffer)->DataDirectory;
	}
	else {
		dataDirectory = getOptionalHeader64(pFileBuffer)->DataDirectory;
	}

	size_t dataDirectoryRva = dataDirectory[index].VirtualAddress;
	return dataDirectoryRva ? rvaToFa(pFileBuffer, dataDirectoryRva) : NULL;
}

// �������϶���
size_t dataAlignUp(size_t data, size_t base) {
	// ���base == 0����data��base����������ֱ�ӷ���data
	if (!base || !(data % base)) {
		return data;
	}
	return (data / base + 1) * base;
}

void* rvaToFa(void* pFileBuffer, size_t rva) {
	if (!pFileBuffer) {
		return NULL;
	}

	PIMAGE_FILE_HEADER pFileHeader = getFileHeader(pFileBuffer);
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = getOptionalHeader32(pFileBuffer);
	PIMAGE_SECTION_HEADER pSectionHeader = getFirstSectionHeader(pFileBuffer);

	if (rva < pOptionalHeader->SizeOfHeaders) {
		return (void*)((size_t)pFileBuffer + rva);
	}

	for (size_t i = 0; i < pFileHeader->NumberOfSections; i++) {
		if (rva >= pSectionHeader->VirtualAddress && rva < pSectionHeader->VirtualAddress + pSectionHeader->SizeOfRawData) {
			return (void*)((size_t)pFileBuffer + rva - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData);
		}
		pSectionHeader++;
	}

	dbgPrintf(L"rvaת��ʧ��\n");
	return NULL;
}

// ��ԭ·�����������ļ���
wchar_t* createNewFilePath(const wchar_t* pOldFilePath, const wchar_t* addedStr) {
	size_t newSize = wcslen(pOldFilePath) + 50;
	wchar_t* pNewFilePath = (wchar_t*)malloc(newSize * sizeof(wchar_t));
	if (!pNewFilePath) {
		wprintf(L"�����ڴ�ʧ��\n");
		return NULL;
	}
	memset(pNewFilePath, 0, newSize * sizeof(wchar_t));

	wcscpy_s(pNewFilePath, newSize, pOldFilePath);
	wchar_t* dest = wcsrchr(pNewFilePath, L'.');
	wchar_t ext[10];
	wcscpy_s(ext, 10, dest);
	*dest = 0;
	wcscat_s(pNewFilePath, newSize, L"-");
	wcscat_s(pNewFilePath, newSize, addedStr);
	wcscat_s(pNewFilePath, newSize, ext);
	return pNewFilePath;
}

size_t readFile(const wchar_t* pFilePath, void** ppFileBuffer) {
	if (!pFilePath) {
		return 0;
	}

	// ���ļ�
	FILE* pFile = NULL;
	_wfopen_s(&pFile, pFilePath, L"rb");
	if (!pFile) {
		dbgPrintf(L"���ļ�ʧ��");
		return 0;
	}

	// �����ļ���С
	fseek(pFile, 0, SEEK_END);
	size_t fileSize = ftell(pFile);
	fseek(pFile, 0, SEEK_SET);

	// �����ڴ�
	void* pFileBuffer = malloc(fileSize);
	if (!pFileBuffer) {
		fclose(pFile);
		dbgPrintf(L"�����ڴ�ʧ��");
		return 0;
	}
	memset(pFileBuffer, 0, fileSize);

	// ��ȡ�ļ�
	if (!fread(pFileBuffer, fileSize, 1, pFile)) {
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

size_t writeToFile(const wchar_t* pFilePath, const void* pFileBuffer, size_t fileSize)
{
	// ���������ļ�
	FILE* pFile = NULL;
	_wfopen_s(&pFile, pFilePath, L"wb+");
	if (!pFile) {
		wprintf(L"�����ļ�ʧ��\n");
		return 0;
	}

	// д�뵽�ļ�
	size_t n = fwrite(pFileBuffer, fileSize, 1, pFile);
	if (!n) {
		wprintf(L"д�뵽�ļ�ʧ��\n");
		fclose(pFile);
		return 0;
	}

	// �ر��ļ�
	fclose(pFile);

	return fileSize;
}

// ����½�
size_t addNewSection(const wchar_t* pFilePath, void** ppNewFileBuffer, size_t newSectionSize) {
	// �½�����
	char NEW_SECTION_NAME[8] = ".new";

	// ���У��
	if (!pFilePath) {
		wprintf(L"pFilePathΪNULL\n");
		return 0;
	}

	// ��newSectionSize��0x1000����
	newSectionSize = dataAlignUp(newSectionSize ? newSectionSize : 1, 0x1000);

	// ��ȡ�ļ�
	void* pFileBuffer = NULL;
	readFile(pFilePath, &pFileBuffer);
	if (!pFileBuffer) {
		wprintf(L"��ȡ�ļ�ʧ��\n");
		return 0;
	}

	// ��ȡPE�ļ�����ͷ��
	PIMAGE_DOS_HEADER pDosHeader = getDosHeader(pFileBuffer);
	PIMAGE_NT_HEADERS pNTHeaders = getNTHeader(pFileBuffer);
	PIMAGE_FILE_HEADER pFileHeader = getFileHeader(pFileBuffer);
	PIMAGE_OPTIONAL_HEADER pOptionalHeader = getOptionalHeader32(pFileBuffer);
	PIMAGE_SECTION_HEADER pFirstSectionHeader = getFirstSectionHeader(pFileBuffer);
	PIMAGE_SECTION_HEADER pLastSectionHeader = getLastSectionHeader(pFileBuffer);
	PIMAGE_SECTION_HEADER pNewSectionHeader = getLastSectionHeader(pFileBuffer) + 1;

	// �ƶ�PE�ļ�ͷ��������Dosͷ�������������
	size_t IMAGE_SIZEOF_DOS_HEADER = 64;
	size_t movedSize = (size_t)pNewSectionHeader - (size_t)pNTHeaders;
	memmove((void*)((size_t)pFileBuffer + IMAGE_SIZEOF_DOS_HEADER), (void*)pNTHeaders, movedSize);
	memset((void*)((size_t)pFileBuffer + IMAGE_SIZEOF_DOS_HEADER + movedSize),
		0, (size_t)pNTHeaders - ((size_t)pFileBuffer + IMAGE_SIZEOF_DOS_HEADER));
	pDosHeader->e_lfanew = IMAGE_SIZEOF_DOS_HEADER;

	// ���»�ȡPE�ļ�����ͷ��
	pFileHeader = getFileHeader(pFileBuffer);
	pOptionalHeader = getOptionalHeader32(pFileBuffer);
	pFirstSectionHeader = getFirstSectionHeader(pFileBuffer);
	pLastSectionHeader = getLastSectionHeader(pFileBuffer);
	pNewSectionHeader = getLastSectionHeader(pFileBuffer) + 1;

	// �ж��Ƿ����㹻�Ŀռ�
	if (pOptionalHeader->SizeOfHeaders - ((size_t)pNewSectionHeader - (size_t)pFileBuffer) < 80) {
		printf("PE�ļ�ͷ���ռ䲻��\n");
		free(pFileBuffer);
		return 0;
	}

	// ��д�½�����
	memset(pNewSectionHeader, 0, 80);
	pFileHeader->NumberOfSections++;
	pOptionalHeader->SizeOfImage = dataAlignUp(pOptionalHeader->SizeOfImage, 0x1000) + newSectionSize;
	memcpy(pNewSectionHeader->Name, NEW_SECTION_NAME, 8);
	pNewSectionHeader->Misc.VirtualSize = newSectionSize;
	pNewSectionHeader->VirtualAddress = pOptionalHeader->SizeOfImage - newSectionSize;
	pNewSectionHeader->SizeOfRawData = newSectionSize;
	pNewSectionHeader->PointerToRawData = pLastSectionHeader->PointerToRawData + pLastSectionHeader->SizeOfRawData;
	// �������нڵĺϲ�����
	size_t mergeCharacteristics = 0;
	for (size_t i = 0; i < pFileHeader->NumberOfSections; i++) {
		mergeCharacteristics |= (pFirstSectionHeader + i)->Characteristics;
	}
	pNewSectionHeader->Characteristics = mergeCharacteristics;

	// �����ڴ�
	size_t newSize = pNewSectionHeader->PointerToRawData + pNewSectionHeader->SizeOfRawData;
	void* pNewFileBuffer = malloc(newSize);
	if (!pNewFileBuffer) {
		wprintf(L"�����ڴ�ʧ��\n");
		free(pFileBuffer);
		return 0;
	}
	memset(pNewFileBuffer, 0, newSize);

	// ���Ƶ��µ��ļ�������
	memcpy(pNewFileBuffer, pFileBuffer, newSize - newSectionSize);
	*ppNewFileBuffer = pNewFileBuffer;

	// �ͷ��ڴ�
	free(pFileBuffer);

	return newSize;
}

// �ӿ�
bool addShellCode(const wchar_t* pSrcPath, const wchar_t* pShellPath) {
	// ���У��
	if (!pSrcPath || !pShellPath) {
		wprintf(L"pSrcPath��pShellPathΪNULL\n");
		return false;
	}

	// ��ȡsrc�ļ�
	void* pSrcBuffer = NULL;
	size_t srcSize = readFile(pSrcPath, &pSrcBuffer);
	if (!pSrcBuffer) {
		wprintf(L"��ȡsrc�ļ�ʧ��\n");
		return false;
	}

	// ��ȡshell�ļ������section
	void* pNewShellBuffer = NULL;
	size_t newShellSize = addNewSection(pShellPath, &pNewShellBuffer, srcSize);
	if (!pNewShellBuffer) {
		wprintf(L"Ϊshell�ļ����sectionʧ��\n");
		free(pSrcBuffer);
		return false;
	}

	// ����src(��λȡ��)
	char* p = (char*)pSrcBuffer;
	for (size_t i = 0; i < srcSize; i++) {
		p[i] = ~p[i];
	}

	// ��src���Ƶ�shell���½���
	memcpy((void*)((size_t)pNewShellBuffer + getLastSectionHeader(pNewShellBuffer)->PointerToRawData), pSrcBuffer, srcSize);

	// �������ļ���
	wchar_t* newFilePath = createNewFilePath(pShellPath, L"�ӿ�");
	if (!newFilePath) {
		wprintf(L"�������ļ���ʧ��\n");
		free(pSrcBuffer);
		free(pNewShellBuffer);
		return false;
	}

	// �����µ�shell
	writeToFile(newFilePath, pNewShellBuffer, newShellSize);

	// �ͷ��ڴ�
	free(pSrcBuffer);
	free(pNewShellBuffer);
	free(newFilePath);

	return true;
}