#include <stdio.h>

#include "process.h"
#include "registry.h"
#include "utils.h"

// TODO Convert to WinAPI.
DWORD RegistryAddDword(LPCWSTR szKeyName, LPCWSTR szValueName, DWORD dwData, BOOL bOverwrite) {
	WCHAR szArgs[ARG_BUF_SIZE + 1];
	ZeroMemory(szArgs, SIZEOF_ARRAY(szArgs));

	swprintf_s(szArgs, SIZEOF_ARRAY(szArgs) - sizeof(WCHAR), L"ADD \"%s\" /v \"%s\" /t REG_DWORD /d %u%s", szKeyName, szValueName, dwData, bOverwrite ? L" /f" : L"");

	HANDLE hProcess = NULL;
	DWORD dwExitCode = 0;
	BOOL bSuccess = ProcessShellExecute(REG_EXE, szArgs, &hProcess);
	if (bSuccess == TRUE && hProcess != NULL) {
		if (GetExitCodeProcess(hProcess, &dwExitCode) == FALSE) {
			return (DWORD)-1;
		}
		// TODO Make wait timed out.
		WaitForSingleObject(hProcess, INFINITE);
	}

	return dwExitCode;
}

DWORD RegistryDeleteKey(LPCWSTR szKeyName) {
	WCHAR szArgs[ARG_BUF_SIZE + 1];
	ZeroMemory(szArgs, SIZEOF_ARRAY(szArgs));

	swprintf_s(szArgs, SIZEOF_ARRAY(szArgs) - sizeof(WCHAR), L"DELETE \"%s\" /f", szKeyName);

	HANDLE hProcess = NULL;
	DWORD dwExitCode = 0;
	BOOL bSuccess = ProcessShellExecute(REG_EXE, szArgs, &hProcess);
	if (bSuccess == TRUE && hProcess != NULL) {
		if (GetExitCodeProcess(hProcess, &dwExitCode) == FALSE) {
			return (DWORD)-1;
		}
		// TODO Make wait timed out.
		WaitForSingleObject(hProcess, INFINITE);
	}

	return dwExitCode;
}