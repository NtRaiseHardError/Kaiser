#pragma once
#ifndef __FIREWALL_H__
#define __FIREWALL_H__

#include <Windows.h>

#define NETSH_EXE L"netsh.exe"
#define ARG_BUF_SIZE 1024

BOOL FirewallAddRuleIn(LPCWSTR szName, BOOL bTcp, USHORT nLocalPort, BOOL bAllow);
BOOL FirewallDeleteRule(LPCWSTR szName);

#endif // !__FIREWALL_H__
