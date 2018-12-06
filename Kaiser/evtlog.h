#pragma once
#ifndef __EVTLOG_H__
#define __EVTLOG_H__

#include <Windows.h>

#define EVTLOG_SVC_NAME L"EventLog"

#define EVTLOG_BANNER L"[EVTLOG]"

typedef enum _EVTLOG_ACTION {
	EVTLOG_PATCH,
	EVTLOG_UNPATCH,
	EVTLOG_SUSPEND,
	EVTLOG_RESUME
} EVTLOG_ACTION;

BOOL EvtlogClear(LPCWSTR szEventLogName);
BOOL EvtlogAction(CONST EVTLOG_ACTION eAction);
ULONG EvtlogMain(INT argc, LPWSTR *argv);

#endif // !__EVTLOG_H__
