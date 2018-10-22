#include "pe.h"

// Get DOS header.
PIMAGE_DOS_HEADER PeGetDosHeader(LPCBYTE lpBytes) {
	return (PIMAGE_DOS_HEADER)lpBytes;
}

// Get NT headers.
PIMAGE_NT_HEADERS PeGetNtHeaders(LPCBYTE lpBytes) {
	return (PIMAGE_NT_HEADERS)((DWORD_PTR)lpBytes + PeGetDosHeader(lpBytes)->e_lfanew);
}

// Get File header.
// Unused but just for completeness.
PIMAGE_FILE_HEADER PeGetFileHeader(LPCBYTE lpBytes) {
	return (PIMAGE_FILE_HEADER)&(PeGetNtHeaders(lpBytes)->FileHeader);
}

// Get Optional header.
PIMAGE_OPTIONAL_HEADER PeGetOptionalHeader(LPCBYTE lpBytes) {
	return (PIMAGE_OPTIONAL_HEADER)&(PeGetNtHeaders(lpBytes)->OptionalHeader);
}

// Get section header by index.
PIMAGE_SECTION_HEADER PeGetSectionHeaderByIndex(LPCBYTE lpBytes, WORD wIndex) {
	return (PIMAGE_SECTION_HEADER)((DWORD_PTR)(IMAGE_FIRST_SECTION(PeGetNtHeaders(lpBytes))) + IMAGE_SIZEOF_SECTION_HEADER * wIndex);
}

// Verify header signatures.
BOOL PeVerifyExeHeaders(LPCBYTE lpBytes) {
	return PeGetDosHeader(lpBytes)->e_magic == IMAGE_DOS_SIGNATURE && PeGetNtHeaders(lpBytes)->Signature == IMAGE_NT_SIGNATURE;
}

// Get absolute address of entry point of executable.
DWORD PeGetAddressOfEntryPoint(LPCBYTE lpBytes) {
	// Get pointer to PE headers.
	PIMAGE_OPTIONAL_HEADER pioh = PeGetOptionalHeader(lpBytes);
	return pioh->ImageBase + pioh->AddressOfEntryPoint;
}

BOOL PeIsConsoleApplication(LPCBYTE lpBytes) {
	return PeGetOptionalHeader(lpBytes)->Subsystem == IMAGE_SUBSYSTEM_WINDOWS_CUI;
}