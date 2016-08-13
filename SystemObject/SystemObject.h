#pragma once

#include "resource.h"


#define MAX_LOADSTRING 100

enum enumHandleInfo
{
	HandleVaule,
	HandleType,
	HandleProcessId,
	HandleName
};

#define UM_INSERTITEM WM_USER+0x100
#define UM_SETITEM	WM_USER+0x101



extern HINSTANCE g_hInst;														// 当前实例
extern HWND g_hMainDlg;														// 主窗口句柄
