#include "services.h"

// Returns 0 on success else, the error code from GetLastError.
ULONG ServicesGetServiceStatus(LPCWSTR szServiceName, LPSERVICE_STATUS_PROCESS ssp) {
	ULONG uError = ERROR_SUCCESS;

	SC_HANDLE hSCManager = OpenSCManager(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_CONNECT);
	if (hSCManager == NULL) {
		return GetLastError();
	}

	SC_HANDLE hService = OpenService(hSCManager, szServiceName, SERVICE_QUERY_STATUS);
	if (hService == NULL) {
		uError = GetLastError();
		CloseServiceHandle(hSCManager);
		return uError;
	}

	DWORD dwBytesNeeded = 0;
	if (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)ssp, sizeof(SERVICE_STATUS_PROCESS), &dwBytesNeeded) == FALSE) {
		uError = GetLastError();
	}

	CloseServiceHandle(hService);
	CloseServiceHandle(hSCManager);

	return uError;
}