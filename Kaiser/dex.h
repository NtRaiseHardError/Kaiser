#pragma once
#ifndef __DEX_H__
#define __DEX_H__

#include <Windows.h>

#define DEX_BANNER L"[DEX]"

typedef enum _DEX_ACTION {
	DEX_NON_INTERACTIVE,
	DEX_INTERACTIVE
} DEX_ACTION;

typedef struct _DEX_THREAD_ARGS {
	DEX_ACTION dAction;
	LPWSTR lpAddress;
	LPWSTR lpPort;
	LPWSTR szUrl;
	LPWSTR lpArguments;
} DEX_THREAD_ARGS, *LPDEX_THREAD_ARGS;

ULONG DexMain(INT argc, LPWSTR *argv);

#endif // !__DEX_H__
