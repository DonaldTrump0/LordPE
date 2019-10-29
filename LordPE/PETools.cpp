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

// 数据向上对齐
size_t dataAlignUp(size_t data, size_t base) {
	// 如果base == 0或者data是base的整数倍，直接返回data
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

	dbgPrintf(L"rva转换失败\n");
	return NULL;
}

// 在原路径上生成新文件名
wchar_t* createNewFilePath(const wchar_t* pOldFilePath, const wchar_t* addedStr) {
	size_t newSize = wcslen(pOldFilePath) + 50;
	wchar_t* pNewFilePath = (wchar_t*)malloc(newSize * sizeof(wchar_t));
	if (!pNewFilePath) {
		wprintf(L"申请内存失败\n");
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

	// 打开文件
	FILE* pFile = NULL;
	_wfopen_s(&pFile, pFilePath, L"rb");
	if (!pFile) {
		dbgPrintf(L"打开文件失败");
		return 0;
	}

	// 计算文件大小
	fseek(pFile, 0, SEEK_END);
	size_t fileSize = ftell(pFile);
	fseek(pFile, 0, SEEK_SET);

	// 申请内存
	void* pFileBuffer = malloc(fileSize);
	if (!pFileBuffer) {
		fclose(pFile);
		dbgPrintf(L"申请内存失败");
		return 0;
	}
	memset(pFileBuffer, 0, fileSize);

	// 读取文件
	if (!fread(pFileBuffer, fileSize, 1, pFile)) {
		fclose(pFile);
		free(pFileBuffer);
		dbgPrintf(L"读取文件失败");
		return 0;
	}

	*ppFileBuffer = pFileBuffer;

	// 关闭文件
	fclose(pFile);

	return fileSize;
}

size_t writeToFile(const wchar_t* pFilePath, const void* pFileBuffer, size_t fileSize)
{
	// 创建并打开文件
	FILE* pFile = NULL;
	_wfopen_s(&pFile, pFilePath, L"wb+");
	if (!pFile) {
		wprintf(L"创建文件失败\n");
		return 0;
	}

	// 写入到文件
	size_t n = fwrite(pFileBuffer, fileSize, 1, pFile);
	if (!n) {
		wprintf(L"写入到文件失败\n");
		fclose(pFile);
		return 0;
	}

	// 关闭文件
	fclose(pFile);

	return fileSize;
}

// 添加新节
size_t addNewSection(const wchar_t* pFilePath, void** ppNewFileBuffer, size_t newSectionSize) {
	// 新节名字
	char NEW_SECTION_NAME[8] = ".new";

	// 入参校验
	if (!pFilePath) {
		wprintf(L"pFilePath为NULL\n");
		return 0;
	}

	// 将newSectionSize按0x1000对齐
	newSectionSize = dataAlignUp(newSectionSize ? newSectionSize : 1, 0x1000);

	// 读取文件
	void* pFileBuffer = NULL;
	readFile(pFilePath, &pFileBuffer);
	if (!pFileBuffer) {
		wprintf(L"读取文件失败\n");
		return 0;
	}

	// 获取PE文件各个头部
	PIMAGE_DOS_HEADER pDosHeader = getDosHeader(pFileBuffer);
	PIMAGE_NT_HEADERS pNTHeaders = getNTHeader(pFileBuffer);
	PIMAGE_FILE_HEADER pFileHeader = getFileHeader(pFileBuffer);
	PIMAGE_OPTIONAL_HEADER pOptionalHeader = getOptionalHeader32(pFileBuffer);
	PIMAGE_SECTION_HEADER pFirstSectionHeader = getFirstSectionHeader(pFileBuffer);
	PIMAGE_SECTION_HEADER pLastSectionHeader = getLastSectionHeader(pFileBuffer);
	PIMAGE_SECTION_HEADER pNewSectionHeader = getLastSectionHeader(pFileBuffer) + 1;

	// 移动PE文件头部，覆盖Dos头后面的无用数据
	size_t IMAGE_SIZEOF_DOS_HEADER = 64;
	size_t movedSize = (size_t)pNewSectionHeader - (size_t)pNTHeaders;
	memmove((void*)((size_t)pFileBuffer + IMAGE_SIZEOF_DOS_HEADER), (void*)pNTHeaders, movedSize);
	memset((void*)((size_t)pFileBuffer + IMAGE_SIZEOF_DOS_HEADER + movedSize),
		0, (size_t)pNTHeaders - ((size_t)pFileBuffer + IMAGE_SIZEOF_DOS_HEADER));
	pDosHeader->e_lfanew = IMAGE_SIZEOF_DOS_HEADER;

	// 重新获取PE文件各个头部
	pFileHeader = getFileHeader(pFileBuffer);
	pOptionalHeader = getOptionalHeader32(pFileBuffer);
	pFirstSectionHeader = getFirstSectionHeader(pFileBuffer);
	pLastSectionHeader = getLastSectionHeader(pFileBuffer);
	pNewSectionHeader = getLastSectionHeader(pFileBuffer) + 1;

	// 判断是否有足够的空间
	if (pOptionalHeader->SizeOfHeaders - ((size_t)pNewSectionHeader - (size_t)pFileBuffer) < 80) {
		printf("PE文件头部空间不足\n");
		free(pFileBuffer);
		return 0;
	}

	// 填写新节属性
	memset(pNewSectionHeader, 0, 80);
	pFileHeader->NumberOfSections++;
	pOptionalHeader->SizeOfImage = dataAlignUp(pOptionalHeader->SizeOfImage, 0x1000) + newSectionSize;
	memcpy(pNewSectionHeader->Name, NEW_SECTION_NAME, 8);
	pNewSectionHeader->Misc.VirtualSize = newSectionSize;
	pNewSectionHeader->VirtualAddress = pOptionalHeader->SizeOfImage - newSectionSize;
	pNewSectionHeader->SizeOfRawData = newSectionSize;
	pNewSectionHeader->PointerToRawData = pLastSectionHeader->PointerToRawData + pLastSectionHeader->SizeOfRawData;
	// 计算所有节的合并属性
	size_t mergeCharacteristics = 0;
	for (size_t i = 0; i < pFileHeader->NumberOfSections; i++) {
		mergeCharacteristics |= (pFirstSectionHeader + i)->Characteristics;
	}
	pNewSectionHeader->Characteristics = mergeCharacteristics;

	// 申请内存
	size_t newSize = pNewSectionHeader->PointerToRawData + pNewSectionHeader->SizeOfRawData;
	void* pNewFileBuffer = malloc(newSize);
	if (!pNewFileBuffer) {
		wprintf(L"申请内存失败\n");
		free(pFileBuffer);
		return 0;
	}
	memset(pNewFileBuffer, 0, newSize);

	// 复制到新的文件缓冲区
	memcpy(pNewFileBuffer, pFileBuffer, newSize - newSectionSize);
	*ppNewFileBuffer = pNewFileBuffer;

	// 释放内存
	free(pFileBuffer);

	return newSize;
}

// 加壳
bool addShellCode(const wchar_t* pSrcPath, const wchar_t* pShellPath) {
	// 入参校验
	if (!pSrcPath || !pShellPath) {
		wprintf(L"pSrcPath或pShellPath为NULL\n");
		return false;
	}

	// 读取src文件
	void* pSrcBuffer = NULL;
	size_t srcSize = readFile(pSrcPath, &pSrcBuffer);
	if (!pSrcBuffer) {
		wprintf(L"读取src文件失败\n");
		return false;
	}

	// 读取shell文件并添加section
	void* pNewShellBuffer = NULL;
	size_t newShellSize = addNewSection(pShellPath, &pNewShellBuffer, srcSize);
	if (!pNewShellBuffer) {
		wprintf(L"为shell文件添加section失败\n");
		free(pSrcBuffer);
		return false;
	}

	// 加密src(按位取反)
	char* p = (char*)pSrcBuffer;
	for (size_t i = 0; i < srcSize; i++) {
		p[i] = ~p[i];
	}

	// 将src复制到shell的新节内
	memcpy((void*)((size_t)pNewShellBuffer + getLastSectionHeader(pNewShellBuffer)->PointerToRawData), pSrcBuffer, srcSize);

	// 生成新文件名
	wchar_t* newFilePath = createNewFilePath(pShellPath, L"加壳");
	if (!newFilePath) {
		wprintf(L"生成新文件名失败\n");
		free(pSrcBuffer);
		free(pNewShellBuffer);
		return false;
	}

	// 保存新的shell
	writeToFile(newFilePath, pNewShellBuffer, newShellSize);

	// 释放内存
	free(pSrcBuffer);
	free(pNewShellBuffer);
	free(newFilePath);

	return true;
}