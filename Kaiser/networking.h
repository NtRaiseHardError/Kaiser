#pragma once
#ifndef __NETWORKING_H__
#define __NETWORKING_H__

#include <Windows.h>

#ifdef _DEBUG
#define ADDRESS L"127.0.0.1"
#else
#define ADDRESS L"192.168.56.1"
#endif // _DEBUG

//#define	ADDRESS L"127.0.0.1"
#define PORT L"6969"

#define NET_BUF_SIZE 1024

INT InitWsa(void);
INT FreeWsa(void);
ULONG TcpConnect(SOCKET *s, LPCWSTR address, LPCWSTR port);
INT CloseTcpSocket(SOCKET s);
INT Receive(CONST SOCKET s, LPWSTR *szRecvBuf);
INT Send(CONST SOCKET s, LPCWSTR fmt, ...);
ULONG FileDownload(LPCWSTR szUrl, LPBYTE *lpDownloaded, PSIZE_T nBytesDownloaded);

#endif // !__NETWORKING_H__
