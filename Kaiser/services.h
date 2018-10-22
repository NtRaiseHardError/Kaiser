#pragma once
#ifndef __SERVICES_H__
#define __SERVICES_H__

#include <Windows.h>

ULONG ServicesGetServiceStatus(LPCWSTR szServiceName, LPSERVICE_STATUS_PROCESS ssp);

#endif // !__SERVICES_H__
