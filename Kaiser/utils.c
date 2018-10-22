#include <Windows.h>
#include <stdio.h>
#include <stdarg.h>

#include "utils.h"

HANDLE g_hHeap = NULL;

void Debug(DEBUG_LEVEL l, LPCWSTR fmt, ...) {
#ifdef DEBUG
	WCHAR szDebugBuf[DEBUG_BUF_SIZE + 1];
	va_list args;

	ZeroMemory(szDebugBuf, SIZEOF_ARRAY(szDebugBuf));

	switch (l) {
		case SUCCESS:
			break;
		case FAILURE:
			break;
		case WARNING:
			break;
		case CRITICAL:
			break;
		case GENERAL:
		default:
			break;
	}

	va_start(args, fmt);
	_vswprintf_p(szDebugBuf, SIZEOF_ARRAY(szDebugBuf), fmt, args);

	// TODO: Replace by sending debug message to server?
	MessageBox(NULL, szDebugBuf, L"DEBUG MESSAGE", MB_OK);
#endif //  DEBUG
}

void Fatal(UINT uExitCode, LPCWSTR fmt, ...) {
#ifdef DEBUG
	WCHAR szDebugBuf[DEBUG_BUF_SIZE];
	va_list args;

	ZeroMemory(szDebugBuf, SIZEOF_ARRAY(szDebugBuf));

	va_start(args, fmt);
	_vswprintf_p(szDebugBuf, SIZEOF_ARRAY(szDebugBuf), fmt, args);

	MessageBox(NULL, szDebugBuf, L"FATAL ERROR", MB_OK);
#endif // DEBUG

	ExitProcess(uExitCode);
}

// Returns a heap-alloc'd string and is required to be freed by caller.
// Returned string is NULL-terminated.
// nSize represents the size of from.
// Return value is TRUE if succeeded else, FALSE. Use GetLastError to
// get the error code.
BOOL MB2WC(LPCSTR from, LPWSTR *to) {
	// Get the buffer size required for the wide char string.
	// len + 1 to NULL-terminate.
	INT len = MultiByteToWideChar(CP_UTF8, 0, from, -1, NULL, 0);

	*to = _HeapAlloc(HEAP_ZERO_MEMORY, (len + 1) * sizeof(WCHAR));
	if (*to == NULL) {
		return FALSE;
	}

	return MultiByteToWideChar(CP_UTF8, 0, from, -1, *to, len) ? TRUE : FALSE;
}

// Returns a heap-alloc'd string and is required to be freed by caller.
// Returned string is NULL-terminated.
// nSize represents the size of from.
// Return value is TRUE if succeeded else, FALSE. Use GetLastError to
// get the error code.
BOOL WC2MB(LPCWSTR from, LPSTR *to) {
	INT len = WideCharToMultiByte(CP_UTF8, 0, from, -1, NULL, 0, NULL, NULL);

	*to = _HeapAlloc(HEAP_ZERO_MEMORY, len + 1);
	if (*to == NULL) {
		return FALSE;
	}

	return WideCharToMultiByte(CP_UTF8, 0, from, -1, *to, len, NULL, NULL) ? TRUE : FALSE;
}

BOOL _HeapCreate(void) {
	g_hHeap = HeapCreate(0, 0, 0);
	if (g_hHeap == NULL) {
		return FALSE;
	}

	return TRUE;
}

LPVOID _HeapAlloc(DWORD dwFlags, SIZE_T nSize) {
	HANDLE hHeap = g_hHeap ? g_hHeap : GetProcessHeap();
	return HeapAlloc(hHeap, dwFlags, nSize);
}

LPVOID _HeapReAlloc(DWORD dwFlags, LPVOID lpMem, SIZE_T nBytes) {
	HANDLE hHeap = g_hHeap ? g_hHeap : GetProcessHeap();
	return HeapReAlloc(hHeap, dwFlags, lpMem, nBytes);
}

BOOL _HeapFree(LPVOID lpMem) {
	HANDLE hHeap = g_hHeap ? g_hHeap : GetProcessHeap();
	BOOL bSuccess = TRUE;
	if (lpMem != NULL) {
		bSuccess = HeapFree(hHeap, 0, lpMem);
	}
	// Uninitialize pointer so it cannot be reused.
	lpMem = NULL;

	return bSuccess;
}