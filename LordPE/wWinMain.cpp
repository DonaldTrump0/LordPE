#include <windows.h>
#include "resource.h"

HINSTANCE hAppInstance = NULL;

BOOL CALLBACK DialogProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg)
	{
	case WM_INITDIALOG:

		return TRUE;
	case WM_CLOSE:
		EndDialog(hwndDlg, 0);
		return TRUE;
	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case IDC_BUTTON_PE:
			return TRUE;
		case IDC_BUTTON_ABOUT:
			return TRUE;
		case IDC_BUTTON_LOGOUT:
			return TRUE;
		}
	}
	return FALSE;
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow)
{
	hAppInstance = hInstance;
	DialogBox(hInstance, (LPCWSTR)IDD_DIALOG_MAIN, NULL, DialogProc);
	return 0;
}