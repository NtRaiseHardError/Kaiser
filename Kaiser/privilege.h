#pragma once
#ifndef __PRIVILEGE_H__
#define __PRIVILEGE_H__

#include <Windows.h>

BOOL PrivilegeSetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege);
ULONG PrivilegeIsElevated(PBOOL bIsElevtated);
ULONG PrivilegeIsLocalSystem(PBOOL bIsSystem);

#endif // !__PRIVILEGE_H__
