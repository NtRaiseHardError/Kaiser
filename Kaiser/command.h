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
#define OPTION_STRING_UNPATCH L"unpatch"
#define OPTION_STRING_RESUME L"resume"
#define OPTION_STRING_SUSPEND L"suspend"
#define OPTION_STRING_INTERACTIVE L"interactive"
#define OPTION_STRING_EVTLOG L"evtlog"
#define OPTION_STRING_UNINSTALL L"uninstall"
#define OPTION_STRING_ALL L"all"

#define KAISER_BANNER \
" .S    S.    .S_SSSs     .S    sSSs    sSSs   .S_sSSs    \n" \
".SS    SS.  .SS~SSSSS   .SS   d%%SP   d%%SP  .SS~YS%%b   \n" \
"S%S    S&S  S%S   SSSS  S%S  d%S'    d%S'    S%S   `S%b  \n" \
"S%S    d*S  S%S    S%S  S%S  S%|     S%S     S%S    S%S  \n" \
"S&S   .S*S  S%S SSSS%S  S&S  S&S     S&S     S%S    d*S  \n" \
"S&S_sdSSS   S&S  SSS%S  S&S  Y&Ss    S&S_Ss  S&S   .S*S  \n" \
"S&S~YSSY%b  S&S    S&S  S&S  `S&&S   S&S~SP  S&S_sdSSS   \n" \
"S&S    `S%  S&S    S&S  S&S    `S*S  S&S     S&S~YSY%b   \n" \
"S*S     S%  S*S    S&S  S*S     l*S  S*b     S*S   `S%b  \n" \
"S*S     S&  S*S    S*S  S*S    .S*P  S*S.    S*S    S%S  \n" \
"S*S     S&  S*S    S*S  S*S  sSS*S    SSSbs  S*S    S&S  \n" \
"S*S     SS  SSS    S*S  S*S  YSS'      YSSP  S*S    SSS  \n" \
"SP                 SP   SP                   SP          \n" \
"Y                  Y    Y                    Y           \n\n"

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
