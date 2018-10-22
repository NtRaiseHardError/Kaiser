#pragma once
#ifndef __PE_H__
#define __PE_H__

#include <Windows.h>

PIMAGE_DOS_HEADER PeGetDosHeader(LPCBYTE lpBytes);
PIMAGE_NT_HEADERS PeGetNtHeaders(LPCBYTE lpBytes);
PIMAGE_FILE_HEADER PeGetFileHeader(LPCBYTE lpBytes);
PIMAGE_OPTIONAL_HEADER PeGetOptionalHeader(LPCBYTE lpBytes);
PIMAGE_SECTION_HEADER PeGetSectionHeaderByIndex(LPCBYTE lpBytes, WORD wIndex);
BOOL PeVerifyExeHeaders(LPCBYTE lpBytes);
DWORD PeGetAddressOfEntryPoint(LPCBYTE lpBytes);
BOOL PeIsConsoleApplication(LPCBYTE lpBytes);

#endif // !__PE_H__
