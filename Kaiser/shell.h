#pragma once
#ifndef __SHELL_H__
#define __SHELL_H__

#include <Windows.h>

#define CMD_EXE L"\\cmd.exe"

//#ifdef _DEBUG
//#define SHELL_DEFAULT_ADDRESS L"127.0.0.1"
//#else
//#define SHELL_DEFAULT_ADDRESS L"192.168.1.7"
//#endif // _DEBUG

#define SHELL_DEFAULT_ADDRESS L"127.0.0.1"
#define SHELL_DEFAULT_PORT L"4242"

#define SHELL_BANNER L"[SHELL]"

ULONG ShellMain(INT argc, LPWSTR *argv);

#endif // !__SHELL_H__
