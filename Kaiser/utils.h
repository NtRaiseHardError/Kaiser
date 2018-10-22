#pragma once
#ifndef __UTILS_H__
#define __UTILS_H__

#include <Windows.h>

#define DEBUG
#define DEBUG_BUF_SIZE 1024

#ifdef DEBUG
#define DBG_PRINT(l, _fmt, ...) Debug(l, _fmt, __VA_ARGS__)
#else
#define DBG_PRINT(l, _fmt, ...) { NOTHING; }
#endif // DEBUG

// ntdef.h
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

#define SIZEOF_ARRAY(x) sizeof(x)/sizeof(*x)

#define _1K 1024

typedef enum _DEBUG_LEVEL {
	GENERAL,
	SUCCESS,
	FAILURE,
	WARNING,
	CRITICAL
} DEBUG_LEVEL;

void Debug(DEBUG_LEVEL l, LPCWSTR fmt, ...);
void Fatal(UINT uExitCode, LPCWSTR fmt, ...);
BOOL MB2WC(LPCSTR from, LPWSTR *to);
BOOL WC2MB(LPCWSTR from, LPSTR *to);
BOOL _HeapCreate(void);
LPVOID _HeapAlloc(DWORD dwFlags, SIZE_T nSize);
LPVOID _HeapReAlloc(DWORD dwFlags, LPVOID lpMem, SIZE_T nBytes);
BOOL _HeapFree(LPVOID lpMem);

#endif // !__UTILS_H__
