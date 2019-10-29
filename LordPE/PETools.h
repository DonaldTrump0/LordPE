#pragma once

// ��ȡPE�ļ�����ͷ����fa
PIMAGE_DOS_HEADER getDosHeader(void* pFileBuffer);
PIMAGE_NT_HEADERS getNTHeader(void* pFileBuffer);
PIMAGE_FILE_HEADER getFileHeader(void* pFileBuffer);
PIMAGE_OPTIONAL_HEADER32 getOptionalHeader32(void* pFileBuffer);
PIMAGE_OPTIONAL_HEADER64 getOptionalHeader64(void* pFileBuffer);
PIMAGE_SECTION_HEADER getFirstSectionHeader(void* pFileBuffer);
PIMAGE_SECTION_HEADER getLastSectionHeader(void* pFileBuffer);

// ���Դ��ڴ�ӡ
void dbgPrintf(const wchar_t* format, ...);

// ��ȡ��i������Ŀ¼���fa
void* getDataDirectory(void* pFileBuffer, size_t index);

void* rvaToFa(void* pFileBuffer, size_t rva);

// ��ȡ�ļ�
size_t readFile(const wchar_t* pFilePath, void** ppFileBuffer);

// д�뵽�ļ�
size_t writeToFile(const wchar_t* pFilePath, const void* pFileBuffer, size_t fileSize);

// �ӿ�
bool addShellCode(const wchar_t* pSrcPath, const wchar_t* pShellPath);