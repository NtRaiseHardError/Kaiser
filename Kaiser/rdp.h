#pragma once
#ifndef __RDP_H__
#define __RDP_H__

#include <Windows.h>

#define RDP_FIREWALL_RULE_NAME L"rdp plz"
#define RDP_BANNER L"[RDP]"

ULONG RdpMain(INT argc, LPWSTR *argv);

#endif // !__RDP_H__
