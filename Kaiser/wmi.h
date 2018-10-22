#pragma once
#ifndef __WMI_H__
#define __WMI_H__

#include <Wbemidl.h>
#include <WbemCli.h>

typedef struct _WMI_DATA {
	//IWbemObjectSink pSink;
	//IWbemObjectSinkVtbl pSinkVtbl;

	IWbemLocator *pLoc;
	IWbemServices *pSvc;

	LONG lRef;
	BOOL bDone;
} WMI_DATA, *LPWMI_DATA;

HRESULT WmiInitialise(LPCWSTR szNamespace, LPWMI_DATA wmiData);
void WmiFree(void);
void WmiFreeData(LPWMI_DATA wmiData);
HRESULT WmiEventQueryNotification(LPWMI_DATA wmiData, IEnumWbemClassObject **ppEnum, LPCWSTR szQuery);
HRESULT WmiDeleteInstance(LPWMI_DATA wmiData, LPCWSTR szPath);

#endif // !__WMI_H__
