#pragma once
#ifndef __PURGE_H__
#define __PURGE_H__

#include <Windows.h>

#define PURGE_BANNER L"[PURGE]"

#define STATUS_ACCESS_DENIED 0xC0000022

// https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FError%2FHARDERROR_RESPONSE_OPTION.html
typedef enum _HARDERROR_RESPONSE_OPTION {
	OptionAbortRetryIgnore,
	OptionOk,
	OptionOkCancel,
	OptionRetryCancel,
	OptionYesNo,
	OptionYesNoCancel,
	OptionShutdownSystem
} HARDERROR_RESPONSE_OPTION, *PHARDERROR_RESPONSE_OPTION;

// https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FError%2FHARDERROR_RESPONSE.html
typedef enum _HARDERROR_RESPONSE {
	ResponseReturnToCaller,
	ResponseNotHandled,
	ResponseAbort,
	ResponseCancel,
	ResponseIgnore,
	ResponseNo,
	ResponseOk,
	ResponseRetry,
	ResponseYes
} HARDERROR_RESPONSE, *PHARDERROR_RESPONSE;

void Purge(void);
void PurgeProcessMonitor(void);
ULONG PurgeMain(INT argc, LPWSTR *argv);

#endif // !__PURGE_H__
