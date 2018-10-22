#include "file.h"
#include "utils.h"

// Returns 0 on success else, 0 on fail.
INT ReadBytesFromFile(LPCWSTR lpExeName, LPBYTE *lpFileData) {
	HANDLE hFile = CreateFile(lpExeName, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		return -1;
	}

	// Assuming file does not exceed max DWORD value.
	DWORD dwFileSize = GetFileSize(hFile, NULL);
	if (dwFileSize == INVALID_FILE_SIZE) {
		CloseHandle(hFile);
		return -1;
	}

	// To be freed by caller.
	*lpFileData = _HeapAlloc(HEAP_ZERO_MEMORY, dwFileSize);
	if (*lpFileData == NULL) {
		CloseHandle(hFile);
		return -1;
	}

	// Read file contents into buffer.
	DWORD dwRead = 0;
	if (ReadFile(hFile, *lpFileData, dwFileSize, &dwRead, NULL) == FALSE) {
		_HeapFree(*lpFileData);
		CloseHandle(hFile);
		return -1;
	}

	return 0;
}