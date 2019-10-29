#include <stdio.h>
#include <Windows.h>

/*************************************************************
	仅在VC++ 6.0下编译的ShellCode并且加节后才能成功运行
*************************************************************/

// 不显示控制台窗口
#pragma comment(linker, "/subsystem:\"windows\" /entry:\"mainCRTStartup\"")

// 定义ZwUnmapViewOfSection函数，返回值0~0x7FFFFFFF是正确状态，而0x80000000~0xFFFFFFFF是错误状态。
typedef LONG(__stdcall* pZwUnmapViewOfSection)(HANDLE ProcessHandle, PVOID BaseAddress);
pZwUnmapViewOfSection ZwUnmapViewOfSection;


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

PIMAGE_SECTION_HEADER getFirstSectionHeader(void* pFileBuffer) {
	return (PIMAGE_SECTION_HEADER)((size_t)getOptionalHeader32(pFileBuffer) + getFileHeader(pFileBuffer)->SizeOfOptionalHeader);
}

PIMAGE_SECTION_HEADER getLastSectionHeader(void* pFileBuffer) {
	return getFirstSectionHeader(pFileBuffer) + getFileHeader(pFileBuffer)->NumberOfSections - 1;
}

void* rvaToFa(void* pFileBuffer, size_t rva) {
	if (!pFileBuffer) {
		printf("pFileBuffer为NULL\n");
		return NULL;
	}

	PIMAGE_FILE_HEADER pFileHeader = getFileHeader(pFileBuffer);
	PIMAGE_OPTIONAL_HEADER pOptionalHeader = getOptionalHeader32(pFileBuffer);
	PIMAGE_SECTION_HEADER pFirstSectionHeader = getFirstSectionHeader(pFileBuffer);

	// rva在PE头内部
	if (rva < pOptionalHeader->SizeOfHeaders) {
		return (void*)((size_t)pFileBuffer + rva);
	}

	// rva在PE各个节内部
	PIMAGE_SECTION_HEADER pNextSectionHeader = pFirstSectionHeader;
	for (size_t i = 0; i < pFileHeader->NumberOfSections; i++) {
		if (rva >= pNextSectionHeader->VirtualAddress && rva < pNextSectionHeader->VirtualAddress + pNextSectionHeader->SizeOfRawData) {
			return (void*)((size_t)pFileBuffer + rva - pNextSectionHeader->VirtualAddress + pNextSectionHeader->PointerToRawData);
		}
		pNextSectionHeader++;
	}

	printf("rva转换失败\n");
	return NULL;
}

// 获取相应数据表的起始fa
void* getDataDirectory(void* pFileBuffer, size_t index) {
	size_t dataDirectoryRva = getOptionalHeader32(pFileBuffer)->DataDirectory[index].VirtualAddress;
	return dataDirectoryRva ? rvaToFa(pFileBuffer, dataDirectoryRva) : NULL;
}

// 读文件
size_t readFile(const char* pFilePath, void** ppFileBuffer) {
	// 入参校验
	if (!pFilePath) {
		printf("pFilePath为NULL\n");
		return 0;
	}

	// 打开文件
	FILE* pFile = fopen(pFilePath, "rb");
	if (!pFile) {
		printf("打开文件失败\n");
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
		printf("申请内存失败\n");
		return 0;
	}
	memset(pFileBuffer, 0, fileSize);

	// 读取文件
	if (!fread(pFileBuffer, fileSize, 1, pFile)) {
		fclose(pFile);
		free(pFileBuffer);
		printf("读取文件失败\n");
		return 0;
	}

	// 存储pFileBuffer
	*ppFileBuffer = pFileBuffer;

	// 关闭文件
	fclose(pFile);

	return fileSize;
}

// 拉伸
size_t copyFileBufferToImageBuffer(void* pFileBuffer, void** ppImageBuffer) {
	if (!pFileBuffer) {
		printf("pFileBuffer为NULL\n");
		return 0;
	}

	PIMAGE_FILE_HEADER pFileHeader = getFileHeader(pFileBuffer);
	PIMAGE_OPTIONAL_HEADER pOptionalHeader = getOptionalHeader32(pFileBuffer);
	PIMAGE_SECTION_HEADER pFirstSectionHeader = getFirstSectionHeader(pFileBuffer);

	// 申请内存
	void* pImageBuffer = malloc(pOptionalHeader->SizeOfImage);
	if (!pImageBuffer) {
		printf("申请内存失败\n");
		return 0;
	}
	memset(pImageBuffer, 0, pOptionalHeader->SizeOfImage);

	// 复制头部
	memcpy(pImageBuffer, pFileBuffer, pOptionalHeader->SizeOfHeaders);

	// 复制各个节
	PIMAGE_SECTION_HEADER pNextSectionHeader = pFirstSectionHeader;
	for (size_t i = 0; i < pFileHeader->NumberOfSections; i++) {
		void* dst = (void*)((size_t)pImageBuffer + pNextSectionHeader->VirtualAddress);
		void* src = (void*)((size_t)pFileBuffer + pNextSectionHeader->PointerToRawData);
		size_t size = pNextSectionHeader->SizeOfRawData;
		memcpy(dst, src, size);
		pNextSectionHeader++;
	}

	*ppImageBuffer = pImageBuffer;

	return pOptionalHeader->SizeOfImage;
}

// 修改ImageBase
bool modifyImageBase(void* pFileBuffer, size_t newImageBase) {
	if (!pFileBuffer) {
		printf("pFileBuffer为NULL\n");
		return false;
	}

	PIMAGE_OPTIONAL_HEADER pOptionalHeader32 = getOptionalHeader32(pFileBuffer);
	PIMAGE_BASE_RELOCATION pBaseRelocation = (PIMAGE_BASE_RELOCATION)getDataDirectory(pFileBuffer, 5);

	if (!pBaseRelocation) {
		printf("没有重定位表\n");
		return false;
	}

	while (pBaseRelocation->VirtualAddress) {
		unsigned short* t = (unsigned short*)((size_t)pBaseRelocation + 8);
		for (size_t i = 0; i < (pBaseRelocation->SizeOfBlock - 8) / 2; i++) {
			size_t rva = (*t) & 0xFFF;
			if (rva && (((*t) >> 12) == 3)) {
				size_t* fa = (size_t*)rvaToFa(pFileBuffer, rva + pBaseRelocation->VirtualAddress);
				*fa = *fa - pOptionalHeader32->ImageBase + newImageBase;
			}
			t++;
		}
		pBaseRelocation = (PIMAGE_BASE_RELOCATION)((size_t)pBaseRelocation + pBaseRelocation->SizeOfBlock);
	}

	pOptionalHeader32->ImageBase = newImageBase;

	return true;
}

// 加载ZwUnmapViewOfSection函数
bool loadZwUnmapViewOfSection() {
	HMODULE hNtModule = GetModuleHandleA("ntdll.dll");
	if (!hNtModule) {
		printf("加载ntdll.dll失败\n");
		return false;
	}
	ZwUnmapViewOfSection = (pZwUnmapViewOfSection)GetProcAddress(hNtModule, "ZwUnmapViewOfSection");
	if (!ZwUnmapViewOfSection) {
		printf("获取ZwUnmapViewOfSection失败\n");
		return false;
	}
	return true;
}

void shellcode(const char* pFilePath) {
	// 入参校验
	if (!pFilePath) {
		printf("pFilePath为NULL\n");
		return;
	}

	// 读取文件
	void* pShellFileBuffer = NULL;
	readFile(pFilePath, &pShellFileBuffer);
	if (!pShellFileBuffer) {
		printf("读取文件失败\n");
		return;
	}

	// 获取shell头部
	PIMAGE_OPTIONAL_HEADER32 pShellOptionalHeader32 = getOptionalHeader32(pShellFileBuffer);
	PIMAGE_SECTION_HEADER pShellLastSectionHeader = getLastSectionHeader(pShellFileBuffer);

	// 解密最后一个节里的src(按位取反)
	char* pSrcFileBuffer = (char*)((size_t)pShellFileBuffer + pShellLastSectionHeader->PointerToRawData);
	for (size_t i = 0; i < pShellLastSectionHeader->SizeOfRawData; i++) {
		pSrcFileBuffer[i] = ~pSrcFileBuffer[i];
	}

	// 获取src头部
	PIMAGE_OPTIONAL_HEADER32 pSrcOptionalHeader32 = getOptionalHeader32(pSrcFileBuffer);
	PIMAGE_SECTION_HEADER pSrcLastSectionHeader = getLastSectionHeader(pSrcFileBuffer);

	// 以挂起的形式创建进程(要创建的进程就是壳子本身)
	STARTUPINFOA si = { 0 };
	PROCESS_INFORMATION pi = { 0 };
	si.cb = sizeof(si);
	CreateProcessA(pFilePath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED | CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);

	// 获取外壳程序的Context
	CONTEXT ctx = { 0 };
	ctx.ContextFlags = CONTEXT_FULL;
	GetThreadContext(pi.hThread, &ctx);

	// 获取ImageBase
	size_t imageBaseAddress = ctx.Ebx + 8;
	size_t imageBase = 0;
	ReadProcessMemory(pi.hProcess, (void*)imageBaseAddress, &imageBase, 4, NULL);
	if (!imageBase) {
		printf("获取ImageBase失败，ErrorCode = 0x%X\n", GetLastError());
		TerminateProcess(pi.hProcess, 1);
		return;
	}

	// 卸载外壳程序
	size_t ntStatus = ZwUnmapViewOfSection(pi.hProcess, (void*)imageBase);
	if (ntStatus) {
		printf("卸载外壳程序失败，NTSTATUS = 0x%X\n", ntStatus);
		TerminateProcess(pi.hProcess, 1);
		return;
	}

	// 为进程申请内存，地址是src的ImageBase，大小是src的SizeOfImage
	size_t newImageBase = (size_t)VirtualAllocEx(pi.hProcess, (void*)pSrcOptionalHeader32->ImageBase,
		pSrcOptionalHeader32->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	// 若申请失败，则申请任意地址的内存
	if (!newImageBase) {
		newImageBase = (size_t)VirtualAllocEx(pi.hProcess, NULL,
			pSrcOptionalHeader32->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!newImageBase) {
			printf("为进程申请内存失败，ErrorCode = 0x%X\n", GetLastError());
			TerminateProcess(pi.hProcess, 1);
			return;
		}

		// 修复重定位表
		modifyImageBase(pSrcFileBuffer, newImageBase);
	}

	// 拉伸src
	void* pSrcImageBuffer = NULL;
	copyFileBufferToImageBuffer(pSrcFileBuffer, &pSrcImageBuffer);

	// 将拉伸后的src写入到进程内存
	if (!WriteProcessMemory(pi.hProcess, (void*)newImageBase, pSrcImageBuffer, pSrcOptionalHeader32->SizeOfImage, NULL)) {
		printf("将拉伸后的src写入到进程失败，ErrorCode = 0x%X\n", GetLastError());
		TerminateProcess(pi.hProcess, 1);
	}

	// 修改ImageBase
	if (!WriteProcessMemory(pi.hProcess, (void*)imageBaseAddress, &newImageBase, 4, NULL)) {
		printf("修改ImageBase失败，ErrorCode = 0x%X\n", GetLastError());
		TerminateProcess(pi.hProcess, 1);
	}
	// 修改OEP
	ctx.Eax = pSrcOptionalHeader32->AddressOfEntryPoint + pSrcOptionalHeader32->ImageBase;

	// 设置Context并恢复主线程
	SetThreadContext(pi.hThread, &ctx);
	ResumeThread(pi.hThread);

	// 释放内存
	free(pShellFileBuffer);
	free(pSrcImageBuffer);
}

int main(int argc, char* argv[]) {
	if (loadZwUnmapViewOfSection()) {
		shellcode(argv[0]);
	}
	return 0;
}