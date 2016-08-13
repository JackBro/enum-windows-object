#include "stdafx.h"
#include "SystemInfoDef.h"
#include "SystemObject.h"


//////////////////////////////////////////////////////////////////////////
//	
//
BOOL SetHandleName(LPWSTR pName)
{
	BOOL bResult = FALSE;
	LPWSTR pHandleName = NULL;
	UINT_PTR uLen = 0;

	__try
	{
		if (!pName)		__leave;
		uLen = wcslen(pName);
		pHandleName = new WCHAR[uLen+1];
		wcscpy_s(pHandleName, uLen + 1, pName);
		bResult = SendMessageW(g_hMainDlg, UM_SETITEM, HandleName, (LPARAM)pHandleName);
	}
	__finally
	{

	}

	return bResult;
}

//////////////////////////////////////////////////////////////////////////
//	句柄所属进程ID
//
BOOL SetHandleProcessId(DWORD dwPid)
{
	BOOL bResult = FALSE;

	__try
	{
		bResult = SendMessageW(g_hMainDlg, UM_SETITEM, HandleProcessId, dwPid);
	}
	__finally
	{

	}

	return bResult;
}

//////////////////////////////////////////////////////////////////////////
//	句柄类型
//
BOOL SetHandleType(HANDLE hHandle, DWORD dwTypeVaule)
{
	BOOL bResult = FALSE;
	LPBYTE pTypeInfo = NULL;
	ZwQueryObject pfnZwQueryObject = NULL;
	NTSTATUS ntResult = STATUS_SUCCESS;
	ULONG uValue = 0;

	__try
	{
		pfnZwQueryObject = (ZwQueryObject)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "ZwQueryObject");
		if (!pfnZwQueryObject)		__leave;
		pTypeInfo = new BYTE[0x100];
		ntResult = pfnZwQueryObject(hHandle, ObjectTypeInformation, pTypeInfo, 0x100, &uValue);
		if (ntResult == STATUS_ACCESS_VIOLATION)
		{
			delete[] pTypeInfo;
			pTypeInfo = new BYTE[uValue];
			ntResult = pfnZwQueryObject(hHandle, ObjectTypeInformation, pTypeInfo, uValue, &uValue);
			if (ntResult != STATUS_SUCCESS)		__leave;
		}
		bResult = SendMessageW(g_hMainDlg, UM_SETITEM, HandleType, (LPARAM)(pTypeInfo + 0x60));
	}
	__finally
	{
		delete[] pTypeInfo;
	}

	return bResult;
}

//////////////////////////////////////////////////////////////////////////
//	添加一行
//
BOOL AddHandleItem(DWORD dwHandleVaule)
{
	BOOL bResult = FALSE;

	__try
	{
		bResult = SendMessageW(g_hMainDlg, UM_INSERTITEM, NULL, dwHandleVaule);
	}
	__finally
	{

	}

	return bResult;
}

HANDLE GetDuplicateHandle(DWORD dwProcessId, HANDLE hSource)
{
	HANDLE hResult = 0;
	HANDLE hProcess = 0;

	__try
	{
		if (GetCurrentProcessId() == dwProcessId)
			hProcess = (HANDLE)-1;
		else
			hProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, dwProcessId);
		if (!hProcess)			__leave;
		if (!DuplicateHandle(hProcess, hSource, GetCurrentProcess(), &hResult, NULL, FALSE, DUPLICATE_SAME_ACCESS))
			hResult = 0;
	}
	__finally
	{
		CloseHandle(hProcess);
	}

	return hResult;
}

//////////////////////////////////////////////////////////////////////////
//	强制删除文件
//
BOOL __stdcall UpdateSystemHandle(LPARAM lParam)
{
	BOOL bResult = FALSE;
	HANDLE hDestProcess = 0, hDupHandle = 0;
	LPBYTE pBuff = NULL;
	UNICODE_STRING* pNameInfo = NULL;
	SYSTEM_HANDLE_TABLE_ENTRY_INFO* pSystemHandle = NULL;
	DWORD dwOut = 0;
	UINT_PTR uIndex = 0;
	NTSTATUS ntResult = 0;
	ZwQuerySystemInformation pfnZwQuerySystemInformation = NULL;
	ZwOpenProcess pfnZwOpenProcess = NULL;
	ZwDuplicateObject pfnZwDuplicateObject = NULL;
	ZwQueryObject pfnZwQueryObject = NULL;
	ZwClose pfnZwClose = NULL;
	OBJECT_BASIC_INFORMATION stPOBI = { 0 };
	OBJECT_ATTRIBUTES stOA = { 0 };
	CLIENT_ID stClientID = { 0 };

	__try
	{
		pfnZwQuerySystemInformation = (ZwQuerySystemInformation)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "ZwQuerySystemInformation");
		if (!pfnZwQuerySystemInformation)		__leave;
		pfnZwOpenProcess = (ZwOpenProcess)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "ZwOpenProcess");
		if (!pfnZwOpenProcess)		__leave;
		pfnZwDuplicateObject = (ZwDuplicateObject)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "ZwDuplicateObject");
		if (!pfnZwDuplicateObject)		__leave;
		pfnZwQueryObject = (ZwQueryObject)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "ZwQueryObject");
		if (!pfnZwQueryObject)		__leave;
		pfnZwClose = (ZwClose)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "ZwClose");
		if (!pfnZwClose)		__leave;
		pNameInfo = (UNICODE_STRING*)new BYTE[0x200];

		stOA.Length = sizeof(OBJECT_ATTRIBUTES);
		stOA.RootDirectory = 0;
		stOA.ObjectName = 0;
		stOA.Attributes = 0;
		stOA.SecurityDescriptor = 0;
		stOA.SecurityQualityOfService = 0;
		stClientID.UniqueProcess = (LPVOID)GetCurrentProcessId();
		dwOut = 0x400000;
		do
		{
			pBuff = new BYTE[dwOut];
			if (pfnZwQuerySystemInformation(SystemHandleInformation, pBuff, dwOut, &dwOut) != STATUS_SUCCESS)
			{
				if (dwOut > 0x400000)
					delete[] pBuff;
				else
					__leave;
			}
			else
				break;
		} while (TRUE);
		hDestProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)stClientID.UniqueProcess);
		if (!hDestProcess)		__leave;
		pSystemHandle = (SYSTEM_HANDLE_TABLE_ENTRY_INFO*)(pBuff + 4);
		for (uIndex = 0; uIndex < *(LPDWORD)pBuff; uIndex++)			//*(LPDWORD)pBuff==句柄总数
		{
			hDupHandle = GetDuplicateHandle(pSystemHandle->UniqueProcessId, (HANDLE)pSystemHandle->HandleValue);
			if (hDupHandle)
			{
// 				ntResult = pfnZwQueryObject(hDupHandle/*hDupHandle*/, ObjectBasicInformation, &stPOBI, sizeof(stPOBI), NULL);
// 				if (ntResult == STATUS_SUCCESS)		//获得该对象信息
// 				{
					if (pfnZwQueryObject(hDupHandle/*hDupHandle*/, ObjectNameInformation, pNameInfo, 0x200, NULL) == STATUS_SUCCESS)		//获得对象名
					{
						AddHandleItem(pSystemHandle->HandleValue);			//记录句柄值
						SetHandleType(hDupHandle, pSystemHandle->ObjectTypeIndex);		//记录句柄类型
						SetHandleProcessId(pSystemHandle->UniqueProcessId);			//记录所属进程ID
						SetHandleName(pNameInfo->Buffer);
					}
// 				}
			}
			
			CloseHandle(hDupHandle);
			pSystemHandle++;
		}
	}
	__finally
	{
		CloseHandle(hDestProcess);
		delete[] pBuff;
		delete[](LPBYTE)pNameInfo;
	}

	return bResult;
}
