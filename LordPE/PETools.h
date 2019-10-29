#pragma once

// 获取PE文件各个头部的fa
PIMAGE_DOS_HEADER getDosHeader(void* pFileBuffer);
PIMAGE_NT_HEADERS getNTHeader(void* pFileBuffer);
PIMAGE_FILE_HEADER getFileHeader(void* pFileBuffer);
PIMAGE_OPTIONAL_HEADER32 getOptionalHeader32(void* pFileBuffer);
PIMAGE_OPTIONAL_HEADER64 getOptionalHeader64(void* pFileBuffer);
PIMAGE_SECTION_HEADER getFirstSectionHeader(void* pFileBuffer);
PIMAGE_SECTION_HEADER getLastSectionHeader(void* pFileBuffer);

// 调试窗口打印
void dbgPrintf(const wchar_t* format, ...);

// 获取第i个数据目录表的fa
void* getDataDirectory(void* pFileBuffer, size_t index);

void* rvaToFa(void* pFileBuffer, size_t rva);

// 读取文件
size_t readFile(const wchar_t* pFilePath, void** ppFileBuffer);

// 写入到文件
size_t writeToFile(const wchar_t* pFilePath, const void* pFileBuffer, size_t fileSize);

// 加壳
bool addShellCode(const wchar_t* pSrcPath, const wchar_t* pShellPath);