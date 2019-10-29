#include <stdio.h>
#include <Windows.h>

/*************************************************************
	����VC++ 6.0�±����ShellCode���Ҽӽں���ܳɹ�����
*************************************************************/

// ����ʾ����̨����
#pragma comment(linker, "/subsystem:\"windows\" /entry:\"mainCRTStartup\"")

// ����ZwUnmapViewOfSection����������ֵ0~0x7FFFFFFF����ȷ״̬����0x80000000~0xFFFFFFFF�Ǵ���״̬��
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
		printf("pFileBufferΪNULL\n");
		return NULL;
	}

	PIMAGE_FILE_HEADER pFileHeader = getFileHeader(pFileBuffer);
	PIMAGE_OPTIONAL_HEADER pOptionalHeader = getOptionalHeader32(pFileBuffer);
	PIMAGE_SECTION_HEADER pFirstSectionHeader = getFirstSectionHeader(pFileBuffer);

	// rva��PEͷ�ڲ�
	if (rva < pOptionalHeader->SizeOfHeaders) {
		return (void*)((size_t)pFileBuffer + rva);
	}

	// rva��PE�������ڲ�
	PIMAGE_SECTION_HEADER pNextSectionHeader = pFirstSectionHeader;
	for (size_t i = 0; i < pFileHeader->NumberOfSections; i++) {
		if (rva >= pNextSectionHeader->VirtualAddress && rva < pNextSectionHeader->VirtualAddress + pNextSectionHeader->SizeOfRawData) {
			return (void*)((size_t)pFileBuffer + rva - pNextSectionHeader->VirtualAddress + pNextSectionHeader->PointerToRawData);
		}
		pNextSectionHeader++;
	}

	printf("rvaת��ʧ��\n");
	return NULL;
}

// ��ȡ��Ӧ���ݱ����ʼfa
void* getDataDirectory(void* pFileBuffer, size_t index) {
	size_t dataDirectoryRva = getOptionalHeader32(pFileBuffer)->DataDirectory[index].VirtualAddress;
	return dataDirectoryRva ? rvaToFa(pFileBuffer, dataDirectoryRva) : NULL;
}

// ���ļ�
size_t readFile(const char* pFilePath, void** ppFileBuffer) {
	// ���У��
	if (!pFilePath) {
		printf("pFilePathΪNULL\n");
		return 0;
	}

	// ���ļ�
	FILE* pFile = fopen(pFilePath, "rb");
	if (!pFile) {
		printf("���ļ�ʧ��\n");
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
		printf("�����ڴ�ʧ��\n");
		return 0;
	}
	memset(pFileBuffer, 0, fileSize);

	// ��ȡ�ļ�
	if (!fread(pFileBuffer, fileSize, 1, pFile)) {
		fclose(pFile);
		free(pFileBuffer);
		printf("��ȡ�ļ�ʧ��\n");
		return 0;
	}

	// �洢pFileBuffer
	*ppFileBuffer = pFileBuffer;

	// �ر��ļ�
	fclose(pFile);

	return fileSize;
}

// ����
size_t copyFileBufferToImageBuffer(void* pFileBuffer, void** ppImageBuffer) {
	if (!pFileBuffer) {
		printf("pFileBufferΪNULL\n");
		return 0;
	}

	PIMAGE_FILE_HEADER pFileHeader = getFileHeader(pFileBuffer);
	PIMAGE_OPTIONAL_HEADER pOptionalHeader = getOptionalHeader32(pFileBuffer);
	PIMAGE_SECTION_HEADER pFirstSectionHeader = getFirstSectionHeader(pFileBuffer);

	// �����ڴ�
	void* pImageBuffer = malloc(pOptionalHeader->SizeOfImage);
	if (!pImageBuffer) {
		printf("�����ڴ�ʧ��\n");
		return 0;
	}
	memset(pImageBuffer, 0, pOptionalHeader->SizeOfImage);

	// ����ͷ��
	memcpy(pImageBuffer, pFileBuffer, pOptionalHeader->SizeOfHeaders);

	// ���Ƹ�����
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

// �޸�ImageBase
bool modifyImageBase(void* pFileBuffer, size_t newImageBase) {
	if (!pFileBuffer) {
		printf("pFileBufferΪNULL\n");
		return false;
	}

	PIMAGE_OPTIONAL_HEADER pOptionalHeader32 = getOptionalHeader32(pFileBuffer);
	PIMAGE_BASE_RELOCATION pBaseRelocation = (PIMAGE_BASE_RELOCATION)getDataDirectory(pFileBuffer, 5);

	if (!pBaseRelocation) {
		printf("û���ض�λ��\n");
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

// ����ZwUnmapViewOfSection����
bool loadZwUnmapViewOfSection() {
	HMODULE hNtModule = GetModuleHandleA("ntdll.dll");
	if (!hNtModule) {
		printf("����ntdll.dllʧ��\n");
		return false;
	}
	ZwUnmapViewOfSection = (pZwUnmapViewOfSection)GetProcAddress(hNtModule, "ZwUnmapViewOfSection");
	if (!ZwUnmapViewOfSection) {
		printf("��ȡZwUnmapViewOfSectionʧ��\n");
		return false;
	}
	return true;
}

void shellcode(const char* pFilePath) {
	// ���У��
	if (!pFilePath) {
		printf("pFilePathΪNULL\n");
		return;
	}

	// ��ȡ�ļ�
	void* pShellFileBuffer = NULL;
	readFile(pFilePath, &pShellFileBuffer);
	if (!pShellFileBuffer) {
		printf("��ȡ�ļ�ʧ��\n");
		return;
	}

	// ��ȡshellͷ��
	PIMAGE_OPTIONAL_HEADER32 pShellOptionalHeader32 = getOptionalHeader32(pShellFileBuffer);
	PIMAGE_SECTION_HEADER pShellLastSectionHeader = getLastSectionHeader(pShellFileBuffer);

	// �������һ�������src(��λȡ��)
	char* pSrcFileBuffer = (char*)((size_t)pShellFileBuffer + pShellLastSectionHeader->PointerToRawData);
	for (size_t i = 0; i < pShellLastSectionHeader->SizeOfRawData; i++) {
		pSrcFileBuffer[i] = ~pSrcFileBuffer[i];
	}

	// ��ȡsrcͷ��
	PIMAGE_OPTIONAL_HEADER32 pSrcOptionalHeader32 = getOptionalHeader32(pSrcFileBuffer);
	PIMAGE_SECTION_HEADER pSrcLastSectionHeader = getLastSectionHeader(pSrcFileBuffer);

	// �Թ������ʽ��������(Ҫ�����Ľ��̾��ǿ��ӱ���)
	STARTUPINFOA si = { 0 };
	PROCESS_INFORMATION pi = { 0 };
	si.cb = sizeof(si);
	CreateProcessA(pFilePath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED | CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);

	// ��ȡ��ǳ����Context
	CONTEXT ctx = { 0 };
	ctx.ContextFlags = CONTEXT_FULL;
	GetThreadContext(pi.hThread, &ctx);

	// ��ȡImageBase
	size_t imageBaseAddress = ctx.Ebx + 8;
	size_t imageBase = 0;
	ReadProcessMemory(pi.hProcess, (void*)imageBaseAddress, &imageBase, 4, NULL);
	if (!imageBase) {
		printf("��ȡImageBaseʧ�ܣ�ErrorCode = 0x%X\n", GetLastError());
		TerminateProcess(pi.hProcess, 1);
		return;
	}

	// ж����ǳ���
	size_t ntStatus = ZwUnmapViewOfSection(pi.hProcess, (void*)imageBase);
	if (ntStatus) {
		printf("ж����ǳ���ʧ�ܣ�NTSTATUS = 0x%X\n", ntStatus);
		TerminateProcess(pi.hProcess, 1);
		return;
	}

	// Ϊ���������ڴ棬��ַ��src��ImageBase����С��src��SizeOfImage
	size_t newImageBase = (size_t)VirtualAllocEx(pi.hProcess, (void*)pSrcOptionalHeader32->ImageBase,
		pSrcOptionalHeader32->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	// ������ʧ�ܣ������������ַ���ڴ�
	if (!newImageBase) {
		newImageBase = (size_t)VirtualAllocEx(pi.hProcess, NULL,
			pSrcOptionalHeader32->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!newImageBase) {
			printf("Ϊ���������ڴ�ʧ�ܣ�ErrorCode = 0x%X\n", GetLastError());
			TerminateProcess(pi.hProcess, 1);
			return;
		}

		// �޸��ض�λ��
		modifyImageBase(pSrcFileBuffer, newImageBase);
	}

	// ����src
	void* pSrcImageBuffer = NULL;
	copyFileBufferToImageBuffer(pSrcFileBuffer, &pSrcImageBuffer);

	// ��������srcд�뵽�����ڴ�
	if (!WriteProcessMemory(pi.hProcess, (void*)newImageBase, pSrcImageBuffer, pSrcOptionalHeader32->SizeOfImage, NULL)) {
		printf("��������srcд�뵽����ʧ�ܣ�ErrorCode = 0x%X\n", GetLastError());
		TerminateProcess(pi.hProcess, 1);
	}

	// �޸�ImageBase
	if (!WriteProcessMemory(pi.hProcess, (void*)imageBaseAddress, &newImageBase, 4, NULL)) {
		printf("�޸�ImageBaseʧ�ܣ�ErrorCode = 0x%X\n", GetLastError());
		TerminateProcess(pi.hProcess, 1);
	}
	// �޸�OEP
	ctx.Eax = pSrcOptionalHeader32->AddressOfEntryPoint + pSrcOptionalHeader32->ImageBase;

	// ����Context���ָ����߳�
	SetThreadContext(pi.hThread, &ctx);
	ResumeThread(pi.hThread);

	// �ͷ��ڴ�
	free(pShellFileBuffer);
	free(pSrcImageBuffer);
}

int main(int argc, char* argv[]) {
	if (loadZwUnmapViewOfSection()) {
		shellcode(argv[0]);
	}
	return 0;
}