#include "privilege.h"

// https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/debug-privilege
BOOL PrivilegeSetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege) {
	LUID luid;
	BOOL bRet = FALSE;

	if (LookupPrivilegeValue(NULL, lpszPrivilege, &luid)) {
		TOKEN_PRIVILEGES tp;

		tp.PrivilegeCount = 1;
		tp.Privileges[0].Luid = luid;
		tp.Privileges[0].Attributes = (bEnablePrivilege) ? SE_PRIVILEGE_ENABLED : 0;

		// Enable the privilege or disable all privileges.
		if (AdjustTokenPrivileges(hToken, FALSE, &tp, 0, (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) {
			// Check to see if you have proper access.
			// You may get "ERROR_NOT_ALL_ASSIGNED".
			bRet = (GetLastError() == ERROR_SUCCESS);
		}
	}
	return bRet;
}

// https://stackoverflow.com/questions/8046097/how-to-check-if-a-process-has-the-administrative-rights
ULONG PrivilegeIsElevated(PBOOL bIsElevtated) {
	*bIsElevtated = FALSE;
	HANDLE hToken = NULL;
	ULONG uError = ERROR_SUCCESS;

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken) == FALSE) {
		return GetLastError();
	}

	TOKEN_ELEVATION Elevation;
	DWORD dwSize = sizeof(TOKEN_ELEVATION);
	if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &dwSize) == FALSE) {
		uError = GetLastError();
		CloseHandle(hToken);
		return uError;
	}
	*bIsElevtated = Elevation.TokenIsElevated;

	CloseHandle(hToken);

	return ERROR_SUCCESS;
}

// https://stackoverflow.com/questions/4023586/correct-way-to-find-out-if-a-service-is-running-as-the-system-user
ULONG PrivilegeIsLocalSystem(PBOOL bIsSystem) {
	ULONG uError = ERROR_SUCCESS;
	UCHAR bTokenUser[sizeof(TOKEN_USER) + 8 + 4 * SID_MAX_SUB_AUTHORITIES];
	*bIsSystem = FALSE;

	// Open process token.
	HANDLE hToken;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken) == FALSE) {
		return GetLastError();
	}

	// Retrieve user SID.
	PTOKEN_USER pTokenUser = (PTOKEN_USER)bTokenUser;
	ULONG cbTokenUser;
	if (GetTokenInformation(hToken, TokenUser, pTokenUser, sizeof(bTokenUser), &cbTokenUser) == FALSE) {
		uError = GetLastError();
		CloseHandle(hToken);
		return uError;
	}

	CloseHandle(hToken);

	// Allocate LocalSystem well-known SID.
	SID_IDENTIFIER_AUTHORITY siaNT = SECURITY_NT_AUTHORITY;
	PSID pSystemSid = NULL;
	if (AllocateAndInitializeSid(&siaNT, 1, SECURITY_LOCAL_SYSTEM_RID, 0, 0, 0, 0, 0, 0, 0, &pSystemSid) == FALSE) {
		return GetLastError();
	}

	// Compare the user SID from the token with the LocalSystem SID.
	*bIsSystem = EqualSid(pTokenUser->User.Sid, pSystemSid);

	FreeSid(pSystemSid);

	return ERROR_SUCCESS;
}