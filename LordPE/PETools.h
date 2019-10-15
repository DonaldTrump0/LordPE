#pragma once

void dbgPrintf(const wchar_t* format, ...);

PIMAGE_DOS_HEADER getDosHeader(void* pFileBuffer);
PIMAGE_NT_HEADERS getNTHeader(void* pFileBuffer);
PIMAGE_FILE_HEADER getFileHeader(void* pFileBuffer);
PIMAGE_OPTIONAL_HEADER32 getOptionalHeader(void* pFileBuffer);
PIMAGE_OPTIONAL_HEADER64 getOptionalHeader64(void* pFileBuffer);
PIMAGE_SECTION_HEADER getSectionHeader(void* pFileBuffer);

void* rvaToFa(void* pFileBuffer, size_t rva);

void* getDataDirectory(void* pFileBuffer, size_t index);

size_t readPEFile(const wchar_t* pFilePath, void** ppFileBuffer);