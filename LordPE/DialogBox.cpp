#include <stdio.h>
#include <locale.h>
#include <Windows.h>
#include <psapi.h>
#include <commctrl.h>
#include "resource.h"
#include "DialogBox.h"
#include "PETools.h"
#pragma comment(lib, "comctl32.lib")

// �洢����Ŀ¼����Ϣ���ڴ��С
size_t INFO_SIZE = 1024 * 1024;
// ���ļ���ɸѡ��(��Ч)
//wchar_t FILE_FILTER[] = L"*.exe;*.dll;*.src;*.drv;*.sys\0";
wchar_t FILE_FILTER[] = L"All Files\0";
//��app��HINSTANCE
HINSTANCE hAppInstance = NULL;
// ���ļ���·��
wchar_t pFilePath[MAX_PATH];


// ����ʽ���ַ���׷�ӵ�info֮��
void appenInfo(wchar_t* info, const wchar_t* format, ...) {
	setlocale(LC_ALL, "");

	size_t bufSize = 100;
	wchar_t* buf = (wchar_t*)malloc(bufSize * sizeof(wchar_t));
	if (!buf) {
		return;
	}
	memset(buf, 0, bufSize * sizeof(wchar_t));

	va_list vlArgs;
	va_start(vlArgs, format);
	vswprintf_s(buf, bufSize, format, vlArgs);
	va_end(vlArgs);

	wcscat_s(info, INFO_SIZE, buf);
	free(buf);
}

// �ݹ��ӡ��Դ��
static void printResourceDirectoryRecursive(wchar_t* info, PIMAGE_RESOURCE_DIRECTORY pRootRcDir, PIMAGE_RESOURCE_DIRECTORY pRcDir, size_t depth) {
	size_t entryNum = pRcDir->NumberOfIdEntries + pRcDir->NumberOfNamedEntries;
	PIMAGE_RESOURCE_DIRECTORY_ENTRY pNextEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pRcDir + 1);
	for (size_t i = 0; i < entryNum; i++) {
		for (size_t i = 0; i < depth; i++) {
			appenInfo(info, L"  ");
		}

		if (pNextEntry->NameIsString) {
			PIMAGE_RESOURCE_DIR_STRING_U pDirString = (PIMAGE_RESOURCE_DIR_STRING_U)(pNextEntry->NameOffset + (size_t)pRootRcDir);
			for (size_t i = 0; i < pDirString->Length; i++) {
				appenInfo(info, L"%c", pDirString->NameString[i]);
			}
		}
		else {
			appenInfo(info, L"%d", pNextEntry->Id);
		}

		if (!pNextEntry->DataIsDirectory) {
			PIMAGE_DATA_DIRECTORY pDataDir = (PIMAGE_DATA_DIRECTORY)(pNextEntry->OffsetToDirectory + (size_t)pRootRcDir);
			appenInfo(info, L"  rva: %X, size: %X\r\n", pDataDir->VirtualAddress, pDataDir->Size);
		}
		else {
			PIMAGE_RESOURCE_DIRECTORY pNextRcDir = (PIMAGE_RESOURCE_DIRECTORY)(pNextEntry->OffsetToDirectory + (size_t)pRootRcDir);
			appenInfo(info, L"(%d)\r\n", pNextRcDir->NumberOfIdEntries + pNextRcDir->NumberOfNamedEntries);
			printResourceDirectoryRecursive(info, pRootRcDir, pNextRcDir, depth + 1);
		}
		pNextEntry++;
	}
}

// ���ļ������ļ�·���浽ȫ�ֱ���pFilePath
bool openFile(HWND hDlg) {
	OPENFILENAME openFileName;

	memset(pFilePath, 0, sizeof(pFilePath));
	memset(&openFileName, 0, sizeof(openFileName));

	openFileName.lStructSize = sizeof(openFileName);
	openFileName.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
	openFileName.hwndOwner = hDlg;
	openFileName.lpstrFilter = FILE_FILTER;
	openFileName.lpstrFile = pFilePath;
	openFileName.nMaxFile = MAX_PATH;

	return GetOpenFileName(&openFileName);
}


// ����һ�е������б���
void addToProcessListView(HWND hProcessList, wchar_t* processName, DWORD processID, DWORD imageBase, DWORD sizeOfImage) {
	LV_ITEM item;
	wchar_t str[20];

	memset(&item, 0, sizeof(LV_ITEM));
	item.mask = LVIF_TEXT;

	item.pszText = processName;
	item.iSubItem = 0;
	ListView_InsertItem(hProcessList, &item);

	wsprintf(str, L"%u", processID);
	item.pszText = str;
	item.iSubItem = 1;
	ListView_SetItem(hProcessList, &item);

	wsprintf(str, L"%X", imageBase);
	item.pszText = str;
	item.iSubItem = 2;
	ListView_SetItem(hProcessList, &item);

	wsprintf(str, L"%X", sizeOfImage);
	item.pszText = str;
	item.iSubItem = 3;
	ListView_SetItem(hProcessList, &item);
}

// ����һ�е�ģ���б���
void addToModuleListView(HWND hModuleList, size_t index, wchar_t* moduleName, DWORD moduleAddr) {
	LVITEM item;
	memset(&item, 0, sizeof(LV_ITEM));
	item.mask = LVIF_TEXT;

	item.pszText = moduleName;
	item.iItem = index;
	item.iSubItem = 0;
	ListView_InsertItem(hModuleList, &item);

	wchar_t str[20];
	wsprintf(str, L"%X", moduleAddr);
	item.pszText = str;
	item.iSubItem = 1;
	ListView_SetItem(hModuleList, &item);
}

// ����һ�е��ڱ���
void addToSectionListView(HWND hListSection, wchar_t* name, size_t vOffset, size_t vSize, size_t rOffset, size_t rSize, size_t flags) {
	LVITEM item;
	memset(&item, 0, sizeof(LV_ITEM));
	item.mask = LVIF_TEXT;

	item.pszText = name;
	item.iSubItem = 0;
	ListView_InsertItem(hListSection, &item);

	wchar_t str[20];
	wsprintf(str, L"%X", vOffset);
	item.pszText = str;
	item.iSubItem = 1;
	ListView_SetItem(hListSection, &item);

	wsprintf(str, L"%X", vSize);
	item.pszText = str;
	item.iSubItem = 2;
	ListView_SetItem(hListSection, &item);

	wsprintf(str, L"%X", rOffset);
	item.pszText = str;
	item.iSubItem = 3;
	ListView_SetItem(hListSection, &item);

	wsprintf(str, L"%X", rSize);
	item.pszText = str;
	item.iSubItem = 4;
	ListView_SetItem(hListSection, &item);

	wsprintf(str, L"%X", flags);
	item.pszText = str;
	item.iSubItem = 5;
	ListView_SetItem(hListSection, &item);
}

// �������н���(����û��Ȩ�޷��ʵĽ���)
void enumProcess(HWND hProcessList) {
	// ��ȡ���н���Id
	DWORD processIDs[1024], cbNeeded;
	EnumProcesses(processIDs, sizeof(processIDs), &cbNeeded);

	// ���������Ŀ
	DWORD processNum = cbNeeded / sizeof(DWORD);

	// ����ÿ������
	for (size_t i = 0; i < processNum; i++) {
		// ��ȡ���̵�handle
		HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processIDs[i]);
		// ���Ծܾ����ʵĽ���
		if (!hProcess) {
			continue;
		}

		HMODULE hModule;
		MODULEINFO moduleInfo;
		wchar_t processName[MAX_PATH] = L"<unknown>";
		memset(&moduleInfo, 0, sizeof(MODULEINFO));

		// ��ȡ���̵��׸�ģ�飬���Ծܾ����ʵĽ���
		if (EnumProcessModules(hProcess, &hModule, sizeof(hModule), &cbNeeded)) {
			// ��ȡ������Ϣ
			GetModuleBaseName(hProcess, hModule, processName, sizeof(processName) / sizeof(wchar_t));
			GetModuleInformation(hProcess, hModule, &moduleInfo, sizeof(MODULEINFO));
			// ���뵽�����б�
			addToProcessListView(hProcessList, processName, processIDs[i], (DWORD)hModule, moduleInfo.SizeOfImage);
		}

		// �ͷŽ��̵�handle
		CloseHandle(hProcess);
	}
}

// �������̵�����ģ��
void enumModule(HWND hModuleList, HWND hProcessList) {
	// �������ģ��
	ListView_DeleteAllItems(hModuleList);

	// ��ȡѡ����
	DWORD row = SendMessage(hProcessList, LVM_GETNEXTITEM, -1, LVNI_SELECTED);
	if (row == -1) {
		return;
	}

	wchar_t pidStr[30];
	LV_ITEM item;
	memset(pidStr, 0, sizeof(pidStr));
	memset(&item, 0, sizeof(LV_ITEM));

	// ��ȡpid
	item.iSubItem = 1;		// Ҫ��ȡ����
	item.pszText = pidStr;	// ָ���洢����Ļ�����
	item.cchTextMax = 30;	// ָ����������С
	SendMessage(hProcessList, LVM_GETITEMTEXT, row, (DWORD)&item);

	// ��ȡ���̵�handle
	DWORD pid;
	swscanf_s(pidStr, L"%u", &pid);
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (!hProcess) {
		return;
	}

	HMODULE hModule[1024];
	DWORD cbNeeded = 0;
	memset(hModule, 0, sizeof(hModule));

	// ��ȡ����ģ��
	EnumProcessModules(hProcess, hModule, sizeof(hModule), &cbNeeded);
	// ��������ģ��
	size_t index = 0;
	for (size_t i = 0; i < cbNeeded / sizeof(DWORD); i++) {
		// ��ȡģ������
		wchar_t moduleName[MAX_PATH] = L"<unknown>";
		GetModuleBaseName(hProcess, hModule[i], moduleName, sizeof(moduleName) / sizeof(wchar_t));
		// ��ģ����Ϣ���뵽ģ���б�����
		addToModuleListView(hModuleList, index++, moduleName, (DWORD)hModule[i]);
	}
}

// ��������Section
void enumSection(HWND hSectionList) {
	// ��ȡPE�ļ�
	void* pFileBuffer = NULL;
	readFile(pFilePath, &pFileBuffer);
	if (!pFileBuffer) {
		return;
	}

	PIMAGE_FILE_HEADER pFileHeader = getFileHeader(pFileBuffer);
	PIMAGE_SECTION_HEADER pSectionHeader = getFirstSectionHeader(pFileBuffer);

	for (int i = pFileHeader->NumberOfSections - 1; i >= 0; i--) {
		wchar_t name[9];
		memset(name, 0, sizeof(name));
		for (size_t j = 0; j < 8; j++) {
			name[j] = pSectionHeader[i].Name[j];
		}

		addToSectionListView(hSectionList, name, pSectionHeader[i].VirtualAddress, pSectionHeader[i].Misc.VirtualSize,
			pSectionHeader[i].PointerToRawData, pSectionHeader[i].SizeOfRawData, pSectionHeader[i].Characteristics);
	}

	free(pFileBuffer);
}


// ��ʼ�������б���
void initProcessListView(HWND hDlg) {
	LV_COLUMN column;
	memset(&column, 0, sizeof(column));

	// ��ȡIDC_LIST_PROCESS���
	HWND hListProcess = GetDlgItem(hDlg, IDC_LIST_PROCESS);
	// ��������ѡ��								
	SendMessage(hListProcess, LVM_SETEXTENDEDLISTVIEWSTYLE, LVS_EX_FULLROWSELECT, LVS_EX_FULLROWSELECT);

	// ��һ��								
	column.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
	column.pszText = (wchar_t*)L"Process";					// �б���				
	column.cx = 150;										// �п�
	column.iSubItem = 0;									// Index of subitem associated with the column
	ListView_InsertColumn(hListProcess, 0, &column);
	// �ڶ���								
	column.pszText = (wchar_t*)L"PID";
	column.cx = 50;
	column.iSubItem = 1;
	ListView_InsertColumn(hListProcess, 1, &column);
	// ������								
	column.pszText = (wchar_t*)L"ImageBase";
	column.cx = 100;
	column.iSubItem = 2;
	ListView_InsertColumn(hListProcess, 2, &column);
	// ������								
	column.pszText = (wchar_t*)L"ImageSize";
	column.cx = 100;
	column.iSubItem = 3;
	ListView_InsertColumn(hListProcess, 3, &column);

	enumProcess(hListProcess);
}

// ��ʼ��ģ���б���
void initModuleListView(HWND hwndDlg) {
	LV_COLUMN col;
	memset(&col, 0, sizeof(LV_COLUMN));

	HWND hwndModuleList = GetDlgItem(hwndDlg, IDC_LIST_MODULE);

	ListView_SetExtendedListViewStyle(hwndModuleList, LVS_EX_FULLROWSELECT);

	//��һ��								
	col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
	col.pszText = (wchar_t*)L"ModuleName";
	col.cx = 150;
	col.iSubItem = 0;
	ListView_InsertColumn(hwndModuleList, 0, &col);
	//�ڶ���							
	col.pszText = (wchar_t*)L"ModuleAddress";
	col.cx = 200;
	col.iSubItem = 1;
	ListView_InsertColumn(hwndModuleList, 1, &col);
}

// ��ʼ��PEViewer����
void initPEHeaderInfo(HWND hDlg) {
	// ��ȡPE�ļ�
	void* pFileBuffer = NULL;
	readFile(pFilePath, &pFileBuffer);
	if (!pFileBuffer) {
		return;
	}

	PIMAGE_DOS_HEADER pDosHeader = getDosHeader(pFileBuffer);
	PIMAGE_FILE_HEADER pFileHeader = getFileHeader(pFileBuffer);
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = getOptionalHeader32(pFileBuffer);

	wchar_t buf[20];
	wsprintf(buf, L"%X", pOptionalHeader->AddressOfEntryPoint);
	SendDlgItemMessage(hDlg, IDC_EDIT_ENTRY_POINT, WM_SETTEXT, 0, (DWORD)buf);
	wsprintf(buf, L"%X", pOptionalHeader->ImageBase);
	SendDlgItemMessage(hDlg, IDC_EDIT_IMAGE_BASE, WM_SETTEXT, 0, (DWORD)buf);
	wsprintf(buf, L"%X", pOptionalHeader->SizeOfImage);
	SendDlgItemMessage(hDlg, IDC_EDIT_SIZE_OF_IMAGE, WM_SETTEXT, 0, (DWORD)buf);
	wsprintf(buf, L"%X", pOptionalHeader->BaseOfCode);
	SendDlgItemMessage(hDlg, IDC_EDIT_BASE_OF_CODE, WM_SETTEXT, 0, (DWORD)buf);
	wsprintf(buf, L"%X", pOptionalHeader->BaseOfData);
	SendDlgItemMessage(hDlg, IDC_EDIT_BASE_OF_DATA, WM_SETTEXT, 0, (DWORD)buf);
	wsprintf(buf, L"%X", pOptionalHeader->SectionAlignment);
	SendDlgItemMessage(hDlg, IDC_EDIT_SECTION_ALIGNMENT, WM_SETTEXT, 0, (DWORD)buf);
	wsprintf(buf, L"%X", pOptionalHeader->FileAlignment);
	SendDlgItemMessage(hDlg, IDC_EDIT_FILE_ALIGNMENT, WM_SETTEXT, 0, (DWORD)buf);
	wsprintf(buf, L"%X", pDosHeader->e_magic);
	SendDlgItemMessage(hDlg, IDC_EDIT_MAGIC, WM_SETTEXT, 0, (DWORD)buf);
	wsprintf(buf, L"%X", pOptionalHeader->Subsystem);
	SendDlgItemMessage(hDlg, IDC_EDIT_SUB_SYSTEM, WM_SETTEXT, 0, (DWORD)buf);
	wsprintf(buf, L"%X", pFileHeader->NumberOfSections);
	SendDlgItemMessage(hDlg, IDC_EDIT_NUMBER_OF_SECTIONS, WM_SETTEXT, 0, (DWORD)buf);
	wsprintf(buf, L"%X", pFileHeader->TimeDateStamp);
	SendDlgItemMessage(hDlg, IDC_EDIT_TIME_DATE_STAMP, WM_SETTEXT, 0, (DWORD)buf);
	wsprintf(buf, L"%X", pOptionalHeader->SizeOfHeaders);
	SendDlgItemMessage(hDlg, IDC_EDIT_SIZE_OF_HEADERS, WM_SETTEXT, 0, (DWORD)buf);
	wsprintf(buf, L"%X", pFileHeader->Characteristics);
	SendDlgItemMessage(hDlg, IDC_EDIT_CHARACTERISTICS, WM_SETTEXT, 0, (DWORD)buf);
	wsprintf(buf, L"%X", pOptionalHeader->CheckSum);
	SendDlgItemMessage(hDlg, IDC_EDIT_CHECK_SUM, WM_SETTEXT, 0, (DWORD)buf);
	wsprintf(buf, L"%X", pFileHeader->SizeOfOptionalHeader);
	SendDlgItemMessage(hDlg, IDC_EDIT_SIZE_OF_OPTIONAL_HEADER, WM_SETTEXT, 0, (DWORD)buf);
	wsprintf(buf, L"%X", pOptionalHeader->NumberOfRvaAndSizes);
	SendDlgItemMessage(hDlg, IDC_EDIT_NUM_OF_RVA_AND_SIZES, WM_SETTEXT, 0, (DWORD)buf);

	free(pFileBuffer);
}

// ��ʼ��SectionTable����
void initSectionTable(HWND hDlg) {
	LV_COLUMN column;
	memset(&column, 0, sizeof(column));

	//��ȡIDC_LIST_SECTION_TABLE���								
	HWND hListSection = GetDlgItem(hDlg, IDC_LIST_SECTION_TABLE);
	//��������ѡ��								
	SendMessage(hListSection, LVM_SETEXTENDEDLISTVIEWSTYLE, 0, LVS_EX_FULLROWSELECT);

	//��һ��								
	column.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
	column.pszText = (wchar_t*)L"Name";				//�б���				
	column.cx = 80;										//�п�
	column.iSubItem = 0;
	ListView_InsertColumn(hListSection, 0, &column);
	//�ڶ���								
	column.pszText = (wchar_t*)L"VOffset";
	column.cx = 80;
	column.iSubItem = 1;
	ListView_InsertColumn(hListSection, 1, &column);
	//������								
	column.pszText = (wchar_t*)L"VSize";
	column.cx = 80;
	column.iSubItem = 2;
	ListView_InsertColumn(hListSection, 2, &column);
	//������								
	column.pszText = (wchar_t*)L"ROffset";
	column.cx = 80;
	column.iSubItem = 3;
	ListView_InsertColumn(hListSection, 3, &column);
	//������								
	column.pszText = (wchar_t*)L"RSize";
	column.cx = 80;
	column.iSubItem = 4;
	ListView_InsertColumn(hListSection, 4, &column);
	//������								
	column.pszText = (wchar_t*)L"Flags";
	column.cx = 80;
	column.iSubItem = 5;
	ListView_InsertColumn(hListSection, 5, &column);

	enumSection(hListSection);
}

// ��ʼ��DirectoryTable����
void initDirectoryTable(HWND hDlg) {
	void* pFileBuffer = NULL;
	readFile(pFilePath, &pFileBuffer);
	if (!pFileBuffer) {
		return;
	}

	PIMAGE_DOS_HEADER pDosHeader = getDosHeader(pFileBuffer);
	PIMAGE_FILE_HEADER pFileHeader = getFileHeader(pFileBuffer);
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = getOptionalHeader32(pFileBuffer);

	wchar_t buf[20];
	wsprintf(buf, L"%X", pOptionalHeader->DataDirectory[0].VirtualAddress);
	SendDlgItemMessage(hDlg, IDC_EDIT_DATA_DIRECTORY_RVA0, WM_SETTEXT, 0, (DWORD)buf);
	wsprintf(buf, L"%X", pOptionalHeader->DataDirectory[0].Size);
	SendDlgItemMessage(hDlg, IDC_EDIT_DATA_DIRECTORY_SIZE0, WM_SETTEXT, 0, (DWORD)buf);
	wsprintf(buf, L"%X", pOptionalHeader->DataDirectory[1].VirtualAddress);
	SendDlgItemMessage(hDlg, IDC_EDIT_DATA_DIRECTORY_RVA1, WM_SETTEXT, 0, (DWORD)buf);
	wsprintf(buf, L"%X", pOptionalHeader->DataDirectory[1].Size);
	SendDlgItemMessage(hDlg, IDC_EDIT_DATA_DIRECTORY_SIZE1, WM_SETTEXT, 0, (DWORD)buf);
	wsprintf(buf, L"%X", pOptionalHeader->DataDirectory[2].VirtualAddress);
	SendDlgItemMessage(hDlg, IDC_EDIT_DATA_DIRECTORY_RVA2, WM_SETTEXT, 0, (DWORD)buf);
	wsprintf(buf, L"%X", pOptionalHeader->DataDirectory[2].Size);
	SendDlgItemMessage(hDlg, IDC_EDIT_DATA_DIRECTORY_SIZE2, WM_SETTEXT, 0, (DWORD)buf);
	wsprintf(buf, L"%X", pOptionalHeader->DataDirectory[3].VirtualAddress);
	SendDlgItemMessage(hDlg, IDC_EDIT_DATA_DIRECTORY_RVA3, WM_SETTEXT, 0, (DWORD)buf);
	wsprintf(buf, L"%X", pOptionalHeader->DataDirectory[3].Size);
	SendDlgItemMessage(hDlg, IDC_EDIT_DATA_DIRECTORY_SIZE3, WM_SETTEXT, 0, (DWORD)buf);
	wsprintf(buf, L"%X", pOptionalHeader->DataDirectory[4].VirtualAddress);
	SendDlgItemMessage(hDlg, IDC_EDIT_DATA_DIRECTORY_RVA4, WM_SETTEXT, 0, (DWORD)buf);
	wsprintf(buf, L"%X", pOptionalHeader->DataDirectory[4].Size);
	SendDlgItemMessage(hDlg, IDC_EDIT_DATA_DIRECTORY_SIZE4, WM_SETTEXT, 0, (DWORD)buf);
	wsprintf(buf, L"%X", pOptionalHeader->DataDirectory[5].VirtualAddress);
	SendDlgItemMessage(hDlg, IDC_EDIT_DATA_DIRECTORY_RVA5, WM_SETTEXT, 0, (DWORD)buf);
	wsprintf(buf, L"%X", pOptionalHeader->DataDirectory[5].Size);
	SendDlgItemMessage(hDlg, IDC_EDIT_DATA_DIRECTORY_SIZE5, WM_SETTEXT, 0, (DWORD)buf);
	wsprintf(buf, L"%X", pOptionalHeader->DataDirectory[6].VirtualAddress);
	SendDlgItemMessage(hDlg, IDC_EDIT_DATA_DIRECTORY_RVA6, WM_SETTEXT, 0, (DWORD)buf);
	wsprintf(buf, L"%X", pOptionalHeader->DataDirectory[6].Size);
	SendDlgItemMessage(hDlg, IDC_EDIT_DATA_DIRECTORY_SIZE6, WM_SETTEXT, 0, (DWORD)buf);
	wsprintf(buf, L"%X", pOptionalHeader->DataDirectory[7].VirtualAddress);
	SendDlgItemMessage(hDlg, IDC_EDIT_DATA_DIRECTORY_RVA7, WM_SETTEXT, 0, (DWORD)buf);
	wsprintf(buf, L"%X", pOptionalHeader->DataDirectory[7].Size);
	SendDlgItemMessage(hDlg, IDC_EDIT_DATA_DIRECTORY_SIZE7, WM_SETTEXT, 0, (DWORD)buf);
	wsprintf(buf, L"%X", pOptionalHeader->DataDirectory[8].VirtualAddress);
	SendDlgItemMessage(hDlg, IDC_EDIT_DATA_DIRECTORY_RVA8, WM_SETTEXT, 0, (DWORD)buf);
	wsprintf(buf, L"%X", pOptionalHeader->DataDirectory[8].Size);
	SendDlgItemMessage(hDlg, IDC_EDIT_DATA_DIRECTORY_SIZE8, WM_SETTEXT, 0, (DWORD)buf);
	wsprintf(buf, L"%X", pOptionalHeader->DataDirectory[9].VirtualAddress);
	SendDlgItemMessage(hDlg, IDC_EDIT_DATA_DIRECTORY_RVA9, WM_SETTEXT, 0, (DWORD)buf);
	wsprintf(buf, L"%X", pOptionalHeader->DataDirectory[9].Size);
	SendDlgItemMessage(hDlg, IDC_EDIT_DATA_DIRECTORY_SIZE9, WM_SETTEXT, 0, (DWORD)buf);
	wsprintf(buf, L"%X", pOptionalHeader->DataDirectory[10].VirtualAddress);
	SendDlgItemMessage(hDlg, IDC_EDIT_DATA_DIRECTORY_RVA10, WM_SETTEXT, 0, (DWORD)buf);
	wsprintf(buf, L"%X", pOptionalHeader->DataDirectory[10].Size);
	SendDlgItemMessage(hDlg, IDC_EDIT_DATA_DIRECTORY_SIZE10, WM_SETTEXT, 0, (DWORD)buf);
	wsprintf(buf, L"%X", pOptionalHeader->DataDirectory[11].VirtualAddress);
	SendDlgItemMessage(hDlg, IDC_EDIT_DATA_DIRECTORY_RVA11, WM_SETTEXT, 0, (DWORD)buf);
	wsprintf(buf, L"%X", pOptionalHeader->DataDirectory[11].Size);
	SendDlgItemMessage(hDlg, IDC_EDIT_DATA_DIRECTORY_SIZE11, WM_SETTEXT, 0, (DWORD)buf);
	wsprintf(buf, L"%X", pOptionalHeader->DataDirectory[12].VirtualAddress);
	SendDlgItemMessage(hDlg, IDC_EDIT_DATA_DIRECTORY_RVA12, WM_SETTEXT, 0, (DWORD)buf);
	wsprintf(buf, L"%X", pOptionalHeader->DataDirectory[12].Size);
	SendDlgItemMessage(hDlg, IDC_EDIT_DATA_DIRECTORY_SIZE12, WM_SETTEXT, 0, (DWORD)buf);
	wsprintf(buf, L"%X", pOptionalHeader->DataDirectory[13].VirtualAddress);
	SendDlgItemMessage(hDlg, IDC_EDIT_DATA_DIRECTORY_RVA13, WM_SETTEXT, 0, (DWORD)buf);
	wsprintf(buf, L"%X", pOptionalHeader->DataDirectory[13].Size);
	SendDlgItemMessage(hDlg, IDC_EDIT_DATA_DIRECTORY_SIZE13, WM_SETTEXT, 0, (DWORD)buf);
	wsprintf(buf, L"%X", pOptionalHeader->DataDirectory[14].VirtualAddress);
	SendDlgItemMessage(hDlg, IDC_EDIT_DATA_DIRECTORY_RVA14, WM_SETTEXT, 0, (DWORD)buf);
	wsprintf(buf, L"%X", pOptionalHeader->DataDirectory[14].Size);
	SendDlgItemMessage(hDlg, IDC_EDIT_DATA_DIRECTORY_SIZE14, WM_SETTEXT, 0, (DWORD)buf);
	wsprintf(buf, L"%X", pOptionalHeader->DataDirectory[15].VirtualAddress);
	SendDlgItemMessage(hDlg, IDC_EDIT_DATA_DIRECTORY_RVA15, WM_SETTEXT, 0, (DWORD)buf);
	wsprintf(buf, L"%X", pOptionalHeader->DataDirectory[15].Size);
	SendDlgItemMessage(hDlg, IDC_EDIT_DATA_DIRECTORY_SIZE15, WM_SETTEXT, 0, (DWORD)buf);

	free(pFileBuffer);
}

// ��ʼ��ExportTable����
void initExportTable(HWND hDlg) {
	// ��ȡ�ļ�
	void* pFileBuffer = NULL;
	readFile(pFilePath, &pFileBuffer);
	if (!pFileBuffer) {
		return;
	}

	// ��ȡĿ¼��
	PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)getDataDirectory(pFileBuffer, 0);
	if (!pExportDirectory) {
		free(pFileBuffer);
		return;
	}

	// ���뻺��
	size_t bufsize = 100;
	wchar_t* buf = (wchar_t*)malloc(bufsize * sizeof(wchar_t));
	wchar_t* info = (wchar_t*)malloc(INFO_SIZE * sizeof(wchar_t));
	if (!buf || !info) {
		return;
	}
	memset(info, 0, INFO_SIZE * sizeof(wchar_t));

	mbstowcs_s(NULL, buf, bufsize, (char*)rvaToFa(pFileBuffer, pExportDirectory->Name), _TRUNCATE);
	appenInfo(info, L"Name: %s\r\n", buf);
	appenInfo(info, L"Base: %X\r\n", pExportDirectory->Base);
	appenInfo(info, L"NumberOfFunctions: %X\r\n", pExportDirectory->NumberOfFunctions);
	appenInfo(info, L"NumberOfNames: %X\r\n", pExportDirectory->NumberOfNames);
	appenInfo(info, L"AddressOfFunctions: %X\r\n", pExportDirectory->AddressOfFunctions);
	appenInfo(info, L"AddressOfNames: %X\r\n", pExportDirectory->AddressOfNames);
	appenInfo(info, L"AddressOfNameOrdinals: %X\r\n", pExportDirectory->AddressOfNameOrdinals);

	appenInfo(info, L"\r\nFunction Table\r\n");
	for (size_t i = 0; i < pExportDirectory->NumberOfFunctions; i++) {
		appenInfo(info, L"Rva%d: %X\r\n", i, *((size_t*)rvaToFa(pFileBuffer, pExportDirectory->AddressOfFunctions) + i));
	}

	appenInfo(info, L"\r\nName Table\r\n");
	for (size_t i = 0; i < pExportDirectory->NumberOfNames; i++) {
		size_t rva = *((size_t*)rvaToFa(pFileBuffer, pExportDirectory->AddressOfNames) + i);
		mbstowcs_s(NULL, buf, bufsize, (char*)rvaToFa(pFileBuffer, rva), _TRUNCATE);
		appenInfo(info, L"Name%d: %s\r\n", i, buf);
	}

	appenInfo(info, L"\r\nNameOrdinal Table\r\n");
	for (size_t i = 0; i < pExportDirectory->NumberOfNames; i++) {
		appenInfo(info, L"NameOrdinal%d: %X\r\n", i, *((short*)rvaToFa(pFileBuffer, pExportDirectory->AddressOfNameOrdinals) + i));
	}

	SendDlgItemMessage(hDlg, IDC_EDIT_EXPORT_TABLE, WM_SETTEXT, 0, (DWORD)info);

	free(pFileBuffer);
	free(buf);
	free(info);
}

// ��ʼ��ImportTable����
void initImportTable(HWND hDlg) {
	void* pFileBuffer = NULL;
	readFile(pFilePath, &pFileBuffer);
	if (!pFileBuffer) {
		return;
	}

	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)getDataDirectory(pFileBuffer, 1);
	if (!pImportDescriptor) {
		free(pFileBuffer);
		return;
	}

	size_t bufsize = 100;
	wchar_t* buf = (wchar_t*)malloc(bufsize * sizeof(wchar_t));
	wchar_t* info = (wchar_t*)malloc(INFO_SIZE * sizeof(wchar_t));
	if (!buf || !info) {
		return;
	}
	memset(info, 0, INFO_SIZE * sizeof(wchar_t));

	while (pImportDescriptor->OriginalFirstThunk) {
		// ����dll������
		mbstowcs_s(NULL, buf, bufsize, (char*)rvaToFa(pFileBuffer, pImportDescriptor->Name), _TRUNCATE);
		appenInfo(info, L"Name: %s\r\n", buf);

		// ��ӡINT��
		appenInfo(info, L"INT: \r\n");
		if (getOptionalHeader32(pFileBuffer)->Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
			// 32λINT��(IMAGE_THUNK_DATA32)
			PDWORD thunkDataArr = (PDWORD)rvaToFa(pFileBuffer, pImportDescriptor->OriginalFirstThunk);
			while (*thunkDataArr) {
				if ((*thunkDataArr) & 0x80000000) {
					// �������
					appenInfo(info, L"  %X\r\n", (*thunkDataArr) & 0x7FFFFFFF);
				}
				else {
					// ��������
					mbstowcs_s(NULL, buf, bufsize, ((PIMAGE_IMPORT_BY_NAME)rvaToFa(pFileBuffer, (*thunkDataArr) & 0x7FFFFFFF))->Name, _TRUNCATE);
					appenInfo(info, L"  %s\r\n", buf);
				}
				thunkDataArr++;
			}
		}
		else {
			// 64λINT��(IMAGE_THUNK_DATA64)
			PULONGLONG thunkDataArr = (PULONGLONG)rvaToFa(pFileBuffer, pImportDescriptor->OriginalFirstThunk);
			while (*thunkDataArr) {
				if ((*thunkDataArr) & 0x8000000000000000) {
					// �������
					appenInfo(info, L"  %llX\r\n", (*thunkDataArr) & 0x7FFFFFFFFFFFFFFF);
				}
				else {
					// ��������
					mbstowcs_s(NULL, buf, bufsize, ((PIMAGE_IMPORT_BY_NAME)rvaToFa(pFileBuffer, (*thunkDataArr) & 0x7FFFFFFFFFFFFFFF))->Name, _TRUNCATE);
					appenInfo(info, L"  %s\r\n", buf);
				}
				thunkDataArr++;
			}
		}

		// ��ӡԤ����IAT��(���û��Ԥ�������INT��һ��������ӡ)
		if (pImportDescriptor->TimeDateStamp) {
			appenInfo(info, L"IAT(Ԥ����): \r\n");
			PDWORD thunkDataArr = (PDWORD)rvaToFa(pFileBuffer, pImportDescriptor->FirstThunk);
			while (*thunkDataArr) {
				appenInfo(info, L"  %X\r\n", *thunkDataArr);
			}
		}

		appenInfo(info, L"************************************************\r\n");
		pImportDescriptor++;
	}

	SendDlgItemMessage(hDlg, IDC_EDIT_IMPORT_TABLE, WM_SETTEXT, 0, (DWORD)info);

	free(pFileBuffer);
	free(buf);
	free(info);
}

// ��ʼ��ResourceTable����
void initResourceTable(HWND hDlg) {
	void* pFileBuffer = NULL;
	readFile(pFilePath, &pFileBuffer);
	if (!pFileBuffer) {
		return;
	}

	PIMAGE_RESOURCE_DIRECTORY pRootRcDir = (PIMAGE_RESOURCE_DIRECTORY)getDataDirectory(pFileBuffer, 2);
	if (!pRootRcDir) {
		free(pFileBuffer);
		return;
	}

	wchar_t* info = (wchar_t*)malloc(INFO_SIZE * sizeof(wchar_t));
	if (!info) {
		return;
	}
	memset(info, 0, INFO_SIZE * sizeof(wchar_t));

	// �ݹ��ӡ
	printResourceDirectoryRecursive(info, pRootRcDir, pRootRcDir, 0);

	SendDlgItemMessage(hDlg, IDC_EDIT_RESOURCE_TABLE, WM_SETTEXT, 0, (DWORD)info);

	free(pFileBuffer);
	free(info);
}

// ��ʼ��RelocationTable����
void initRelocationTable(HWND hDlg) {
	void* pFileBuffer = NULL;
	readFile(pFilePath, &pFileBuffer);
	if (!pFileBuffer) {
		return;
	}

	PIMAGE_BASE_RELOCATION pBaseRelocation = (PIMAGE_BASE_RELOCATION)getDataDirectory(pFileBuffer, 5);
	if (!pBaseRelocation) {
		free(pFileBuffer);
		return;
	}

	size_t bufsize = 100;
	wchar_t* buf = (wchar_t*)malloc(bufsize * sizeof(wchar_t));
	wchar_t* info = (wchar_t*)malloc(INFO_SIZE * sizeof(wchar_t));
	if (!buf || !info) {
		return;
	}
	memset(info, 0, INFO_SIZE * sizeof(wchar_t));

	while (pBaseRelocation->VirtualAddress) {
		appenInfo(info, L"VirtualAddress: %X SizeOfBlock: %X\r\n", pBaseRelocation->VirtualAddress, pBaseRelocation->SizeOfBlock);
		unsigned short* t = (unsigned short*)((size_t)pBaseRelocation + 8);
		for (size_t i = 0; i < (pBaseRelocation->SizeOfBlock - 8) / 2; i++) {
			size_t rva = (*t) & 0xFFF;
			appenInfo(info, L"%d: %X : %X\r\n", i, rva == 0 ? 0 : rva + pBaseRelocation->VirtualAddress, (*t) >> 12);
			t++;
		}
		pBaseRelocation = (PIMAGE_BASE_RELOCATION)((size_t)pBaseRelocation + pBaseRelocation->SizeOfBlock);
		appenInfo(info, L"**********************************\r\n");
	}

	SendDlgItemMessage(hDlg, IDC_EDIT_RELOCATION_TABLE, WM_SETTEXT, 0, (DWORD)info);

	free(pFileBuffer);
	free(buf);
	free(info);
}

// ��ʼ��BoundImportTable����
void initBoundImportTable(HWND hDlg) {
	void* pFileBuffer = NULL;
	readFile(pFilePath, &pFileBuffer);
	if (!pFileBuffer) {
		return;
	}

	PIMAGE_BOUND_IMPORT_DESCRIPTOR pBoundImportDirectory = (PIMAGE_BOUND_IMPORT_DESCRIPTOR)getDataDirectory(pFileBuffer, 11);
	if (!pBoundImportDirectory) {
		free(pFileBuffer);
		return;
	}

	size_t bufsize = 100;
	wchar_t* buf = (wchar_t*)malloc(bufsize * sizeof(wchar_t));
	wchar_t* info = (wchar_t*)malloc(INFO_SIZE * sizeof(wchar_t));
	if (!buf || !info) {
		return;
	}
	memset(info, 0, INFO_SIZE * sizeof(wchar_t));

	PIMAGE_BOUND_IMPORT_DESCRIPTOR pNext = pBoundImportDirectory;
	while (pNext->TimeDateStamp) {
		appenInfo(info, L"TimeDateStamp: %X\r\n", pNext->TimeDateStamp);
		mbstowcs_s(NULL, buf, bufsize, (char*)(pNext->OffsetModuleName + (size_t)pBoundImportDirectory), _TRUNCATE);
		appenInfo(info, L"ModuleName: %s\r\n", buf);

		appenInfo(info, L"BoundForwarderRef:\r\n");
		size_t cnt = pNext->NumberOfModuleForwarderRefs;
		for (size_t i = 0; i < cnt; i++) {
			pNext++;
			mbstowcs_s(NULL, buf, bufsize, (char*)(pNext->OffsetModuleName + (size_t)pBoundImportDirectory), _TRUNCATE);
			appenInfo(info, L"\tModuleName: %s\tTimeDateStamp: %X\r\n", buf, pNext->TimeDateStamp);
		}
		pNext++;
		appenInfo(info, L"************************************************\r\n");
	}

	SendDlgItemMessage(hDlg, IDC_EDIT_BOUND_IMPORT_TABLE, WM_SETTEXT, 0, (DWORD)info);

	free(pFileBuffer);
	free(buf);
	free(info);
}

// ��ʼ��IatTable����
void initIatTable(HWND hDlg) {
	void* pFileBuffer = NULL;
	readFile(pFilePath, &pFileBuffer);
	if (!pFileBuffer) {
		return;
	}

	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)getDataDirectory(pFileBuffer, 1);
	if (!pImportDescriptor) {
		free(pFileBuffer);
		return;
	}

	size_t bufsize = 100;
	wchar_t* buf = (wchar_t*)malloc(bufsize * sizeof(wchar_t));
	wchar_t* info = (wchar_t*)malloc(INFO_SIZE * sizeof(wchar_t));
	if (!buf || !info) {
		return;
	}
	memset(info, 0, INFO_SIZE * sizeof(wchar_t));

	// 32λIAT
	if (getOptionalHeader32(pFileBuffer)->Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
		PDWORD pIat = (PDWORD)getDataDirectory(pFileBuffer, 12);
		while (pImportDescriptor->FirstThunk) {
			if (pImportDescriptor->TimeDateStamp) {
				appenInfo(info, L"IAT(Ԥ����): \r\n");
				while (*pIat) {
					appenInfo(info, L"  %X\r\n", *pIat);
					pIat++;
				}
			}
			else {
				appenInfo(info, L"IAT: \r\n");
				while (*pIat) {
					if ((*pIat) & 0x80000000) {
						// �������
						appenInfo(info, L"  %X\r\n", (*pIat) & 0x7FFFFFFF);
					}
					else {
						// ��������
						mbstowcs_s(NULL, buf, bufsize, ((PIMAGE_IMPORT_BY_NAME)rvaToFa(pFileBuffer, (*pIat) & 0x7FFFFFFF))->Name, _TRUNCATE);
						appenInfo(info, L"  %s\r\n", buf);
					}
					pIat++;
				}
			}
			appenInfo(info, L"************************************************\r\n");
			pIat++;
			pImportDescriptor++;
		}
	}
	// 64λIAT
	else {
		PULONGLONG pIat = (PULONGLONG)getDataDirectory(pFileBuffer, 12);
		while (pImportDescriptor->FirstThunk) {
			if (pImportDescriptor->TimeDateStamp) {
				appenInfo(info, L"IAT(Ԥ����): \r\n");
				while (*pIat) {
					appenInfo(info, L"  %llX\r\n", *pIat);
					pIat++;
				}
			}
			else {
				appenInfo(info, L"IAT: \r\n");
				while (*pIat) {
					if ((*pIat) & 0x8000000000000000) {
						// �������
						appenInfo(info, L"  %llX\r\n", (*pIat) & 0x7FFFFFFFFFFFFFFF);
					}
					else {
						// ��������
						mbstowcs_s(NULL, buf, bufsize, ((PIMAGE_IMPORT_BY_NAME)rvaToFa(pFileBuffer, (*pIat) & 0x7FFFFFFFFFFFFFFF))->Name, _TRUNCATE);
						appenInfo(info, L"  %s\r\n", buf);
					}
					pIat++;
				}
			}
			appenInfo(info, L"************************************************\r\n");
			pIat++;
			pImportDescriptor++;
		}
	}

	SendDlgItemMessage(hDlg, IDC_EDIT_IAT_TABLE, WM_SETTEXT, 0, (DWORD)info);

	free(pFileBuffer);
	free(buf);
	free(info);
}


// ֻ��WM_CLOSE�Ĵ��ڻص�����
BOOL CALLBACK CloseDialogProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
	if (uMsg == WM_CLOSE) {
		EndDialog(hDlg, 0);
		return TRUE;
	}
	return FALSE;
}

// ExportTable���ڻص�����
BOOL CALLBACK ExportTableDialogProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
	switch (uMsg) {
	case WM_INITDIALOG:
		initExportTable(hDlg);
		return TRUE;

	case WM_CLOSE:
		EndDialog(hDlg, 0);
		return TRUE;
	}
	return FALSE;
}

// ImportTable���ڻص�����
BOOL CALLBACK ImportTableDialogProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
	switch (uMsg) {
	case WM_INITDIALOG:
		initImportTable(hDlg);
		return TRUE;

	case WM_CLOSE:
		EndDialog(hDlg, 0);
		return TRUE;
	}
	return FALSE;
}

// ResourceTable���ڻص�����
BOOL CALLBACK ResourceTableDialogProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
	switch (uMsg) {
	case WM_INITDIALOG:
		initResourceTable(hDlg);
		return TRUE;

	case WM_CLOSE:
		EndDialog(hDlg, 0);
		return TRUE;
	}
	return FALSE;
}

// RelocationTable���ڻص�����
BOOL CALLBACK RelocationTableDialogProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
	switch (uMsg) {
	case WM_INITDIALOG:
		initRelocationTable(hDlg);
		return TRUE;

	case WM_CLOSE:
		EndDialog(hDlg, 0);
		return TRUE;
	}
	return FALSE;
}

// BoundImportTable���ڻص�����
BOOL CALLBACK BoundImportTableDialogProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
	switch (uMsg) {
	case WM_INITDIALOG:
		initBoundImportTable(hDlg);
		return TRUE;

	case WM_CLOSE:
		EndDialog(hDlg, 0);
		return TRUE;
	}
	return FALSE;
}

// IAT���ڻص�����
BOOL CALLBACK IatTableDialogProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
	switch (uMsg) {
	case WM_INITDIALOG:
		initIatTable(hDlg);
		return TRUE;

	case WM_CLOSE:
		EndDialog(hDlg, 0);
		return TRUE;
	}
	return FALSE;
}

// SectionTable���ڻص�����
BOOL CALLBACK SectionTableDialogProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
	switch (uMsg) {
	case WM_INITDIALOG:
		initSectionTable(hDlg);
		return TRUE;

	case WM_CLOSE:
		EndDialog(hDlg, 0);
		return TRUE;
	}

	return FALSE;
}

// DirectoryTable���ڻص�����
BOOL CALLBACK DirectoryTableDialogProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
	switch (uMsg) {
	case WM_INITDIALOG:
		initDirectoryTable(hDlg);
		return TRUE;

	case WM_CLOSE:
		EndDialog(hDlg, 0);
		return TRUE;

	case WM_COMMAND:
		switch (LOWORD(wParam)) {
		case IDC_BUTTON_DIRECTORY_TABLE_CLOSE:
			EndDialog(hDlg, 0);
			return TRUE;

		case IDC_BUTTON_EXPORT_TABLE:
			DialogBox(hAppInstance, (LPCWSTR)IDD_DIALOG_EXPORT_TABLE, hDlg, ExportTableDialogProc);
			return TRUE;

		case IDC_BUTTON_IMPORT_TABLE:
			DialogBox(hAppInstance, (LPCWSTR)IDD_DIALOG_IMPORT_TABLE, hDlg, ImportTableDialogProc);
			return TRUE;

		case IDC_BUTTON_RESOURCE:
			DialogBox(hAppInstance, (LPCWSTR)IDD_DIALOG_RESOURCE_TABLE, hDlg, ResourceTableDialogProc);
			return TRUE;

		case IDC_BUTTON_RELOCATION:
			DialogBox(hAppInstance, (LPCWSTR)IDD_DIALOG_RELOCATION_TABLE, hDlg, RelocationTableDialogProc);
			return TRUE;

		case IDC_BUTTON_BOUND_IMPORT:
			DialogBox(hAppInstance, (LPCWSTR)IDD_DIALOG_BOUND_IMPORT_TABLE, hDlg, BoundImportTableDialogProc);
			return TRUE;

		case IDC_BUTTON_IAT:
			DialogBox(hAppInstance, (LPCWSTR)IDD_DIALOG_IAT_TABLE, hDlg, IatTableDialogProc);
			return TRUE;
		}
	}
	return FALSE;
}

// PEViewer���ڻص�����
BOOL CALLBACK PEViewerDialogProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
	switch (uMsg) {
	case WM_INITDIALOG:
		initPEHeaderInfo(hDlg);
		return TRUE;

	case WM_CLOSE:
		EndDialog(hDlg, 0);
		return TRUE;

	case WM_COMMAND:
		switch (LOWORD(wParam)) {
		case IDC_BUTTON_PE_VIEWER_CLOSE:
			EndDialog(hDlg, 0);
			return TRUE;

		case IDC_BUTTON_SECTION_TABLE:
			DialogBox(hAppInstance, (LPCWSTR)IDD_DIALOG_SECTION_TABLE, hDlg, SectionTableDialogProc);
			return TRUE;

		case IDC_BUTTON_DIRECTORY_TABLE:
			DialogBox(hAppInstance, (LPCWSTR)IDD_DIALOG_DIRECTORY_TABLE, hDlg, DirectoryTableDialogProc);
			return TRUE;
		}
	}
	return FALSE;
}

// AddShell���ڻص�����
BOOL CALLBACK AddShellDialogProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
	switch (uMsg) {
	case WM_CLOSE:
		EndDialog(hDlg, 0);
		return TRUE;

	case WM_COMMAND:
		switch (LOWORD(wParam)) {
		case IDC_BUTTON_SHELL_PATH:
			if (openFile(hDlg)) {
				SetWindowText(GetDlgItem(hDlg, IDC_EDIT_SHELL_PATH), pFilePath);
			}
			return TRUE;

		case IDC_BUTTON_SRC_PATH:
			if (openFile(hDlg)) {
				SetWindowText(GetDlgItem(hDlg, IDC_EDIT_SRC_PATH), pFilePath);
			}
			return TRUE;

		case IDC_BUTTON_START:
			wchar_t pShellPath[MAX_PATH];
			wchar_t pSrcPath[MAX_PATH];
			GetWindowText(GetDlgItem(hDlg, IDC_EDIT_SHELL_PATH), pShellPath, MAX_PATH);
			GetWindowText(GetDlgItem(hDlg, IDC_EDIT_SRC_PATH), pSrcPath, MAX_PATH);
			if (addShellCode(pSrcPath, pShellPath)) {
				MessageBox(hDlg, L"Succeed", L"[ Add Shell ]", MB_ICONINFORMATION);
			}
			else {
				MessageBox(hDlg, L"Failed", L"[ Add Shell ]", MB_ICONWARNING);
			}
			return TRUE;
		}
	}
	return FALSE;
}

// �����ڻص�����
BOOL CALLBACK MainDialogProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
	switch (uMsg) {
	case WM_INITDIALOG: {
		// ����ͼ��
		HICON hIcon = LoadIcon(hAppInstance, (LPCWSTR)IDI_ICON_ICON);
		// ����ͼ��
		SendMessage(hDlg, WM_SETICON, ICON_BIG, (DWORD)hIcon);
		SendMessage(hDlg, WM_SETICON, ICON_SMALL, (DWORD)hIcon);
		// ��ʼ�������б�
		initProcessListView(hDlg);
		initModuleListView(hDlg);
		return TRUE;
	}

	case WM_CLOSE:
		EndDialog(hDlg, 0);
		return TRUE;

	case WM_NOTIFY:
		if (wParam == IDC_LIST_PROCESS && ((LPNMHDR)lParam)->code == NM_CLICK) {
			enumModule(GetDlgItem(hDlg, IDC_LIST_MODULE), GetDlgItem(hDlg, IDC_LIST_PROCESS));
		}
		return TRUE;

	case WM_COMMAND:
		switch (LOWORD(wParam)) {
		case IDC_BUTTON_PE_VIEWER:
			if (openFile(hDlg)) {
				DialogBox(hAppInstance, (LPCWSTR)IDD_DIALOG_PE_VIEWER, hDlg, PEViewerDialogProc);
			}
			return TRUE;
		
		case IDC_BUTTON_ADD_SHELLCODE:
			DialogBox(hAppInstance, (LPCWSTR)IDD_DIALOG_ADD_SHELL, hDlg, AddShellDialogProc);
			return TRUE;

		case IDC_BUTTON_ABOUT:
			DialogBox(hAppInstance, (LPCWSTR)IDD_DIALOG_ABOUT, hDlg, CloseDialogProc);
			return TRUE;

		case IDC_BUTTON_EXIT:
			EndDialog(hDlg, 0);
			return TRUE;
		}
	}
	return FALSE;
}


void initApp(HINSTANCE hInstance) {
	hAppInstance = hInstance;

	// ���ز�ע��common control classes
	INITCOMMONCONTROLSEX icex;
	icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
	icex.dwICC = ICC_WIN95_CLASSES;
	InitCommonControlsEx(&icex);

	DialogBox(hInstance, (LPCWSTR)IDD_DIALOG_MAIN, NULL, MainDialogProc);
}