#pragma once
#ifndef __REGISTRY_H__
#define __REGISTRY_H__

#include <Windows.h>

#define REG_EXE L"reg.exe"
#define ARG_BUF_SIZE 1024

DWORD RegistryAddDword(LPCWSTR szKeyName, LPCWSTR szValueName, DWORD dwData, BOOL bOverwrite);
DWORD RegistryDeleteKey(LPCWSTR szKeyName);

#endif // !__REGISTRY_H__
