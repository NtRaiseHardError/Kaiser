#pragma once
#ifndef __MIMIKATZ_H__
#define __MIMIKATZ_H__

#include <Windows.h>

//#ifdef _DEBUG
//#define MIMIKATZ_DEFAULT_ADDRESS L"127.0.0.1"
//#else
//#define MIMIKATZ_DEFAULT_ADDRESS L"192.168.1.7"
//#endif // _DEBUG

#define MIMIKATZ_DEFAULT_ADDRESS L"127.0.0.1"
#define MIMIKATZ_DEFAULT_PORT L"8008"

#define MIMIKATZ_BANNER L"[MIMIKATZ]"

ULONG MimikatzMain(INT argc, LPWSTR *argv);

#endif // !__MIMIKATZ_H__
