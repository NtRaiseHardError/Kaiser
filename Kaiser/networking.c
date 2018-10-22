#include <stdio.h>
#include <WinSock2.h>	
#include <WS2tcpip.h>
#include <WinInet.h>

#include "networking.h"
#include "utils.h"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "WinInet.lib")

INT InitWsa(void) {
	WSADATA wsaData;
	INT iSuccess = WSAStartup(MAKEWORD(2, 2), &wsaData);

	// Check if Winsock DLL supports version 2.2.
	if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2) {
		FreeWsa();
	}

	return iSuccess;
}

INT FreeWsa(void) {
	return WSACleanup();
}

// Returns 0 on success else, return nonzero and sets the socket to INVALID_SOCKET.
ULONG TcpConnect(SOCKET *s, LPCWSTR lpAddress, LPCWSTR lpPort) {
	ADDRINFOW hints, *res;
	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	ULONG uSuccess = GetAddrInfoW(lpAddress, lpPort, &hints, &res);
	if (uSuccess != 0) {
		Debug(FAILURE, L"GetAddrInfo failed; error: %s", gai_strerror(uSuccess));
		uSuccess = WSAGetLastError();
		*s = INVALID_SOCKET;
		return uSuccess;
	}

	*s = WSASocket(res->ai_family, res->ai_socktype, res->ai_protocol, NULL, 0, 0);
	if (*s == INVALID_SOCKET) {
		uSuccess = WSAGetLastError();
		FreeAddrInfo(res);
		return -1;
	}

	uSuccess = connect(*s, res->ai_addr, (INT)res->ai_addrlen);
	if (uSuccess == SOCKET_ERROR) {
		uSuccess = WSAGetLastError();
		CloseTcpSocket(*s);
		FreeAddrInfo(res);
		return uSuccess;
	}

	FreeAddrInfo(res);

	return 0;
}

INT CloseTcpSocket(SOCKET s) {
	INT iSuccess = closesocket(s);
	// Uninitialise the socket.
	s = INVALID_SOCKET;

	return iSuccess;
}

// Returns 0 on success.
// szRecvBuf is heap alloc'd by MB2WC and must be freed by caller.
INT Receive(CONST SOCKET s, LPWSTR *szBuffer) {
	CHAR szRecvBuf[NET_BUF_SIZE + 1];
	ZeroMemory(szRecvBuf, SIZEOF_ARRAY(szRecvBuf));

	INT iSuccess = recv(s, szRecvBuf, (INT)sizeof(szRecvBuf) - 1, 0);
	if (iSuccess == SOCKET_ERROR && iSuccess != WSAEMSGSIZE) {
		return -1;
	}

	// Chomp.
	szRecvBuf[strcspn(szRecvBuf, "\r\n")] = 0;

	// If no or acceptable error, convert message to wide char.
	if (MB2WC(szRecvBuf, szBuffer) == FALSE) {
		return -2;
	}

	return 0;
}

// Returns 0 on success;
INT Send(CONST SOCKET s, LPCWSTR fmt, ...) {
	WCHAR szBuffer[NET_BUF_SIZE + 1];
	LPSTR szSendBuf = NULL;
	va_list args;

	ZeroMemory(szBuffer, SIZEOF_ARRAY(szBuffer));

	va_start(args, fmt);
	_vswprintf_p(szBuffer, SIZEOF_ARRAY(szBuffer) - sizeof(WCHAR), fmt, args);

	// Convert buffer to multibyte.
	if (WC2MB(szBuffer, &szSendBuf) == FALSE) {
		return -2;
	}

	// Send max NET_BUF_SIZE.
	INT iSuccess = send(s, szSendBuf, (INT)strlen(szSendBuf) > NET_BUF_SIZE ? NET_BUF_SIZE : strlen(szSendBuf), 0);
	if (iSuccess == SOCKET_ERROR) {
		return -1;
	}

	return 0;
}

// Returns 0 on success else, the error code from GetLastError.
// lpDownloaded is a pointer to the array in which the data
// will be downloaded.
// The number of bytes downloaded is returned in nBytesDownloaded.
ULONG FileDownload(LPCWSTR szUrl, LPBYTE *lpDownloaded, PSIZE_T nBytesDownloaded) {
	ULONG uError = ERROR_SUCCESS;

	HINTERNET hInternet = InternetOpen(L"KAISER", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
	if (hInternet == NULL) {
		return GetLastError();
	}

	// Open the URL.
	HINTERNET hUrl = InternetOpenUrl(hInternet, szUrl, NULL, 0, INTERNET_FLAG_EXISTING_CONNECT | INTERNET_FLAG_NO_CACHE_WRITE, 0);
	if (hUrl == NULL) {
		uError = GetLastError();
		goto fail;
	}

	// To be freed by caller.
	*lpDownloaded = _HeapAlloc(HEAP_ZERO_MEMORY, _1K);
	if (*lpDownloaded == NULL) {
		uError = GetLastError();
		goto fail_1;
	}
	*nBytesDownloaded = 0;

	// Read the file.
	DWORD dwRead = 0;
	DWORD dwTotalRead = 0;
	do {
		if (InternetReadFile(hUrl, *lpDownloaded + dwTotalRead, _1K, &dwRead) == FALSE) {
			uError = GetLastError();
			goto fail_2;
		}
		dwTotalRead += dwRead;

		// Reallocate more space.
		*lpDownloaded = _HeapReAlloc(HEAP_ZERO_MEMORY, *lpDownloaded, dwTotalRead + _1K);
		if (*lpDownloaded == NULL) {
			uError = GetLastError();
			goto fail_2;
		}
	} while (dwRead >= _1K && dwRead != 0);

	*nBytesDownloaded = dwTotalRead;

	InternetCloseHandle(hUrl);
	InternetCloseHandle(hInternet);

	return ERROR_SUCCESS;

fail_2:
	_HeapFree(*lpDownloaded);

fail_1:
	InternetCloseHandle(hUrl);

fail:
	InternetCloseHandle(hInternet);

	return uError;
}