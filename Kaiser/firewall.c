#include <stdio.h>

#include "firewall.h"
#include "process.h"
#include "utils.h"

// TODO Convert to WinAPI.
// https://docs.microsoft.com/en-us/previous-versions/windows/desktop/api/netfw/nf-netfw-inetfwservicerestriction-restrictservice
BOOL FirewallAddRuleIn(LPCWSTR szName, BOOL bTcp, USHORT nLocalPort, BOOL bAllow) {
	WCHAR szArgs[ARG_BUF_SIZE + 1];
	ZeroMemory(szArgs, SIZEOF_ARRAY(szArgs));

	swprintf_s(szArgs, SIZEOF_ARRAY(szArgs) - sizeof(WCHAR), L"advfirewall firewall add rule name=\"%s\" protocol=%s dir=in localport=%hu action=%s", 
			   szName, bTcp ? L"tcp" : L"udp", nLocalPort, bAllow ? L"allow" : L"deny");

	HANDLE hProcess = NULL;
	DWORD dwExitCode = 0;
	BOOL bSuccess = ProcessShellExecute(NETSH_EXE, szArgs, &hProcess);
	if (bSuccess == TRUE && hProcess != NULL) {
		if (GetExitCodeProcess(hProcess, &dwExitCode) == FALSE) {
			return (DWORD)-1;
		}
		// TODO Make wait timed out.
		WaitForSingleObject(hProcess, INFINITE);
	}

	return dwExitCode;
}

BOOL FirewallDeleteRule(LPCWSTR szName) {
	WCHAR szArgs[ARG_BUF_SIZE + 1];
	ZeroMemory(szArgs, SIZEOF_ARRAY(szArgs));

	swprintf_s(szArgs, SIZEOF_ARRAY(szArgs) - sizeof(WCHAR), L"advfirewall firewall delete rule name=\"%s\"", szName);

	HANDLE hProcess = NULL;
	DWORD dwExitCode = 0;
	BOOL bSuccess = ProcessShellExecute(NETSH_EXE, szArgs, &hProcess);
	if (bSuccess == TRUE && hProcess != NULL) {
		if (GetExitCodeProcess(hProcess, &dwExitCode) == FALSE) {
			return (DWORD)-1;
		}
		// TODO Make wait timed out.
		WaitForSingleObject(hProcess, INFINITE);
	}

	return dwExitCode;

	return 0;
}
