// SystemObject.cpp : Defines the entry point for the application.
//

#include "stdafx.h"
#include "SystemObject.h"


// ȫ�ֱ���:
HINSTANCE g_hInst = NULL;														// ��ǰʵ��
HWND g_hMainDlg = NULL;															// �����ھ��
TCHAR g_szDlgTitle[MAX_LOADSTRING] = { 0 };						// �������ı�
INT_PTR iListSortType = 0;

typedef struct tagItemData
{
	UINT Index;
	UINT Width;
	WCHAR Title[0x20];
}ITEMDATA, *PITEMDATA;

ITEMDATA stItemData[] = {
	{ HandleVaule, 100, L"���ֵ" },
	{ HandleType, 100, L"�������" },
	{ HandleProcessId, 100, L"��������ID" },
	{ HandleName, 500, L"������" }
};

BOOL __stdcall UpdateSystemHandle(LPARAM lParam);


LPWSTR pFilePath = L"T:\\Sources\\VC++\\LSP_Hook\\Release\\LHelper.dll";


int CALLBACK ListCompareFunc(LPARAM lParam1, LPARAM lParam2, LPARAM lParamSort)
{
	MessageBoxW(NULL, L"ListCompareFunc", L"SystemObject", MB_OK);

	return 1;
}

//////////////////////////////////////////////////////////////////////////
//	
//
BOOL DelFile(LPWSTR pFilePath)
{
	BOOL bResult = TRUE;

	__try
	{
		if (DeleteFileW(pFilePath))			__leave;
		if (MoveFileExW(pFilePath, L"c:\\temp.tmp", MOVEFILE_REPLACE_EXISTING))			{ DeleteFileW(L"c:\\temp.tmp"); __leave; }
		MoveFileExW(pFilePath, NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
		MessageBoxW(NULL, L"�´�����ʱɾ���ļ�! ", L"LSP_Hook", MB_OK);
		bResult = FALSE;
	}
	__finally
	{

	}

	return bResult;
}

//////////////////////////////////////////////////////////////////////////
//	����һ��
//
BOOL SetListItem(WPARAM wParam, LPARAM lParam)
{
	BOOL bResult = FALSE;
	HWND hList = NULL;
	LPWSTR pText = NULL;
	LVITEM lv = { 0 };

	__try
	{
		hList = GetDlgItem(g_hMainDlg, IDC_LIST_HANDLE);
		if (!IsWindow(hList) || !wParam)				__leave;
		pText = new WCHAR[0x500];
		lv.mask = LVIF_TEXT;
		lv.iItem = ListView_GetItemCount(hList) - 1;
		lv.iSubItem = wParam;
		switch (wParam)
		{
		case HandleType:
			swprintf_s(pText, 0x500, L"%s", (LPVOID)lParam);
			break;
		case HandleProcessId:
			swprintf_s(pText, 0x500, L"%d", (LPVOID)lParam);
			break;
		case HandleName:
			wcscpy_s(pText, 0x200, (LPWSTR)lParam);
			break;
		default:
			__leave;
		}
		lv.pszText = pText;
		bResult = ListView_SetItem(hList, &lv);
	}
	__finally
	{
		delete[] pText;
	}

	return bResult;
}

//////////////////////////////////////////////////////////////////////////
//	�����µ�һ��
//
BOOL InsertHandleItem(WPARAM wParam, LPARAM lParam)
{
	BOOL bResult = FALSE;
	HWND hList = NULL;
	LPWSTR pText = NULL;
	LVITEM lv = { 0 };

	__try
	{
		hList = GetDlgItem(g_hMainDlg, IDC_LIST_HANDLE);
		if (!IsWindow(hList))				__leave;
		pText = new WCHAR[0x200];
		lv.iItem = ListView_GetItemCount(hList);
		lv.mask = LVIF_TEXT | LVIF_PARAM;
		swprintf_s(pText, 0x200, L"0x%p", (LPVOID)lParam);
		lv.pszText = pText;
		lv.lParam = lParam;
		bResult = ListView_InsertItem(hList, &lv);
	}
	__finally
	{
		delete[] pText;
	}

	return bResult;
}

//////////////////////////////////////////////////////////////////////////
//	���ڳ�ʼ������
//
BOOL Cls_OnInitDialog(HWND hwnd, HWND hwndFocus, LPARAM lParam)
{
	BOOL bResult = TRUE;
	HICON hIcon = NULL;
	HWND hList = NULL;
	LVCOLUMNW lc = { 0 };

	hIcon = (HICON)LoadImage(g_hInst, MAKEINTRESOURCE(IDI_ICO_MAIN), IMAGE_ICON, 0, 0, LR_SHARED + LR_DEFAULTSIZE);
	SNDMSG(hwnd, WM_SETICON, ICON_BIG, (LPARAM)hIcon);					//����ICONͼ��
	SNDMSG(hwnd, WM_SETICON, ICON_SMALL, (LPARAM)hIcon);

	// ��ʼ��ȫ���ַ���
	LoadString(g_hInst, IDS_APP_TITLE, g_szDlgTitle, MAX_LOADSTRING);

	//	���öԻ������
	SetWindowText(hwnd, g_szDlgTitle);

	if (GetWindowID(hwndFocus) != IDOK)				//���Ĭ�Ͽؼ��Ƿ�ΪIDOK
	{
		SetFocus(GetDlgItem(hwnd, IDOK));					//�������, ��IDOK����ΪĬ�Ͽؼ�
		bResult = FALSE;
	}

	//	TODO: �Ի����ʼ������
	hList = GetDlgItem(hwnd, IDC_LIST_HANDLE);
	ListView_SetExtendedListViewStyleEx(hList, NULL, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
	lc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
	lc.fmt = LVCFMT_LEFT;
	for (UINT u = 0; u < _countof(stItemData); u++)
	{
		lc.iSubItem = stItemData[u].Index;
		lc.cx = stItemData[u].Width;
		lc.pszText = stItemData[u].Title;
		ListView_InsertColumn(hList, u, &lc);
	}
	ListView_SortItems(hList, ListCompareFunc, NULL);

	return SetDlgMsgResult(hwnd, WM_INITDIALOG, bResult);				//���� WM_INITDIALOG ��Ϣ�ķ���ֵ
}

//////////////////////////////////////////////////////////////////////////
//	ϵͳ�������
//
void Cls_OnSysCommand(HWND hwnd, UINT cmd, int x, int y)
{
}

//////////////////////////////////////////////////////////////////////////
//	�������
//
void Cls_OnCommand(HWND hwnd, int id, HWND hwndCtl, UINT codeNotify)
{
	switch (id)
	{
	case IDOK:
		CloseHandle((HANDLE)_beginthreadex(NULL, NULL, (unsigned(__stdcall *) (void *))UpdateSystemHandle, NULL, NULL, NULL));
		break;
	case IDCANCEL:
		SNDMSG(hwnd, WM_CLOSE, NULL, NULL);
		break;
	default:
		FORWARD_WM_COMMAND(hwnd, id, hwndCtl, codeNotify, DefWindowProc);			//����ϵͳĬ�ϴ���
	}
}

//////////////////////////////////////////////////////////////////////////
//	�رմ���
//
void Cls_OnClose(HWND hwnd)
{

	DestroyWindow(hwnd);
}

//////////////////////////////////////////////////////////////////////////
//	���ٴ���
//
void Cls_OnDestroy(HWND hwnd)
{
	PostQuitMessage(0);
}

void Cls_OnCommNotify(HWND hwnd, int cid, UINT flags){

}

//////////////////////////////////////////////////////////////////////////
//	���Ի�����Ϣ�ص�����
//
LRESULT CALLBACK MainMsgDlgProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	LRESULT lResult = 0;

	switch (uMsg)
	{
		HANDLE_MSG(hWnd, WM_COMMAND, Cls_OnCommand);
		HANDLE_MSG(hWnd, WM_CLOSE, Cls_OnClose);
		HANDLE_MSG(hWnd, WM_DESTROY, Cls_OnDestroy);
		HANDLE_MSG(hWnd, WM_INITDIALOG, Cls_OnInitDialog);
		HANDLE_MSG(hWnd, WM_SYSCOMMAND, Cls_OnSysCommand);
	case UM_INSERTITEM:
		return InsertHandleItem(wParam, lParam);
	case UM_SETITEM:
		return SetListItem(wParam, lParam);
// 	case WM_NOTIFY:
// 		if (((LPNMLISTVIEW)lParam)->hdr->idFrom == IDC_LIST_HANDLE && ((LPNMLISTVIEW)lParam)->hdr->code == LVN_COLUMNCLICK)
// 		{
// 
// 		}
// 		break;
	}

	return lResult;
}

//////////////////////////////////////////////////////////////////////////
//	��ʼ���ؼ������Ի��򴰿�
//
BOOL InitInstances(HINSTANCE hInstance, INT nShowCmd)
{
	BOOL bResult = FALSE;
	INITCOMMONCONTROLSEX stIcex = { 0 };                //ĳЩ�ؼ���Ҫ

	__try
	{
		stIcex.dwSize = sizeof(stIcex);                //���ô˽ṹ��Ĵ�С
		stIcex.dwICC = ICC_INTERNET_CLASSES + ICC_WIN95_CLASSES;        //�ؼ���ʽ
		InitCommonControlsEx(&stIcex);        //��ʼ���ؼ���

		g_hInst = hInstance;                        //����ʵ�������ȫ�ֱ���
		g_hMainDlg = CreateDialog(hInstance, MAKEINTRESOURCE(IDD_DLG_MAIN), NULL, (DLGPROC)MainMsgDlgProc);  //����Dialog����,���Ѿ�����ݸ�ȫ�ֱ���
		if (!g_hMainDlg)				__leave;

		//TODO: Ӧ�ó����ʼ������

		ShowWindow(g_hMainDlg, SW_SHOWNORMAL);
		UpdateWindow(g_hMainDlg);
		bResult = TRUE;
	}
	__finally
	{

	}

	return bResult;
}

//////////////////////////////////////////////////////////////////////////
//	Ӧ�ó�����ں���
//
INT APIENTRY _tWinMain(HINSTANCE hInstance,
	HINSTANCE hPrevInstance,
	LPTSTR lpCmdLine,
	INT nCmdShow)
{
	MSG msg = { 0 };
	HACCEL hAccelTable = NULL;

	if (InitInstances(hInstance, nCmdShow)) //��ʼ��ʵ��
	{
		hAccelTable = LoadAccelerators(hInstance, MAKEINTRESOURCE(IDR_MAINFRAME));					//������ټ���

		while (GetMessage(&msg, NULL, 0, 0))                //��Ϣѭ��
		{
			if (TranslateAccelerator(g_hMainDlg, hAccelTable, &msg) || !IsDialogMessage(g_hMainDlg, &msg)) //��Ϣ����
			{
				TranslateMessage(&msg);
				DispatchMessage(&msg);
			}
		}
	}

	return (INT)msg.wParam;
}
