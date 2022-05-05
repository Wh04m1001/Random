//Credits:
//https://twitter.com/splinter_code/status/1522246799439900673 (@splinter_code)
//https://twitter.com/diversenok_zero/status/1522257797022466056 (@diversenok_zero)

#include <Windows.h>
#include <stdio.h>

#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004


//Structures

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _IO_STATUS_BLOCK {
	union {
		NTSTATUS Status;
		PVOID    Pointer;
	};
	ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

typedef struct _RTLP_CURDIR_REF {
	LONG RefCount;
	HANDLE Handle;
}RTLP_CURDIR_REF, * PRTLP_CURDIR_REF;

typedef struct _RTL_RELATIVE_NAME_U {
	UNICODE_STRING RelativeName;
	HANDLE CurDir;
	PRTLP_CURDIR_REF CurDifRef;
}RTL_RELATIVE_NAME_U, * PRTL_RELATIVE_NAME_U;
typedef struct _SYSTEM_PROCESS_ID_INFORMATION
{
	PVOID ProcessId;
	UNICODE_STRING ImageName;
}SYSTEM_PROCESS_ID_INFORMATION, * PSYSTEM_PROCESS_ID_INFORMATION;
typedef struct _FILE_PROCESS_IDS_USING_FILE_INFORMATION
{
	ULONG NumberOfProcessIdsInList;
	ULONG_PTR ProcessIdList[1];
} FILE_PROCESS_IDS_USING_FILE_INFORMATION, * PFILE_PROCESS_IDS_USING_FILE_INFORMATION;



//API's

typedef NTSTATUS(NTAPI* _NtQueryInformationFile)(
	HANDLE                 FileHandle,
	PIO_STATUS_BLOCK       IoStatusBlock,
	PVOID                  FileInformation,
	ULONG                  Length,
	int FileInformationClass
	);
typedef NTSTATUS(NTAPI* _NtQuerySystemInformation)(
	int                      SystemInformationClass,
	PVOID                    SystemInformation,
	ULONG                    SystemInformationLength,
	PULONG                   ReturnLength
	);
typedef BOOL(NTAPI* _RtlDosPathNameToNtPathName_U)(PWSTR 	DosFileName,
	PUNICODE_STRING 	NtFileName,
	PWSTR* FilePart,
	PRTL_RELATIVE_NAME_U 	RelativeName
	);
_NtQueryInformationFile NtQueryInformationFile;
_NtQuerySystemInformation NtQuerySystemInformation;
_RtlDosPathNameToNtPathName_U RtlDosPathNameToNtPathName_U;




int wmain(int argc, wchar_t** argv) {
	HANDLE hFile = NULL;
	IO_STATUS_BLOCK sb = { 0 };
	ULONG len = 0;
	ULONG ret_len = 0;
	NTSTATUS  status;
	PFILE_PROCESS_IDS_USING_FILE_INFORMATION buff = NULL;
	SYSTEM_PROCESS_ID_INFORMATION info;
	RtlZeroMemory(&info, sizeof(info));




	
	HMODULE ntdll = NULL;
	hFile = CreateFileW(L"C:\\windows\\system32\\ntdll.dll", GENERIC_READ, FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL); {
		if (hFile == INVALID_HANDLE_VALUE) {
			wprintf(L"Error: %d\n", GetLastError());
			exit(0);

		}
	}
	ntdll = LoadLibrary(L"ntdll.dll");
	if (ntdll) {
		NtQueryInformationFile = (_NtQueryInformationFile)GetProcAddress(ntdll, "NtQueryInformationFile");
		NtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");
		RtlDosPathNameToNtPathName_U = (_RtlDosPathNameToNtPathName_U)GetProcAddress(ntdll, "RtlDosPathNameToNtPathName_U");
		if (NtQueryInformationFile == NULL || NtQuerySystemInformation == NULL) {
			wprintf(L"Can't resove api's\n");
			CloseHandle(hFile);
			exit(0);
		}
	}
	len = 8192;
	buff = (PFILE_PROCESS_IDS_USING_FILE_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, len);
	if (buff != NULL) {
		status = NtQueryInformationFile(hFile, &sb, buff, len, 47);
		while (status == STATUS_INFO_LENGTH_MISMATCH) {
			len = len + 8192;
			buff = (PFILE_PROCESS_IDS_USING_FILE_INFORMATION)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, buff, len);
			status = NtQueryInformationFile(hFile, &sb, buff, len, 47);
		}
		CloseHandle(hFile);
		wprintf(L"Number of processes :%d\n", buff->NumberOfProcessIdsInList);
		for (ULONG i = 0; i < buff->NumberOfProcessIdsInList; i++) {
			info.ImageName.MaximumLength = 256 * 2;
			info.ImageName.Buffer = (PWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 256 * 2);
			info.ProcessId = (PVOID)buff->ProcessIdList[i];
			info.ImageName.Length = 0;

			status = NtQuerySystemInformation(88, &info, sizeof(info), NULL);
			if (status == 0 && info.ImageName.Buffer != NULL) {
				PWSTR process = NULL;
				UNICODE_STRING path;
				if (RtlDosPathNameToNtPathName_U(info.ImageName.Buffer, &path, &process, NULL)) {
					wprintf(L"%-50s\t%d\n", process,(DWORD)info.ProcessId);
				}
			}
			HeapFree(GetProcessHeap(), 0, info.ImageName.Buffer);
		}
		HeapFree(GetProcessHeap(), 0, buff);
	}
}
