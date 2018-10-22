#include <Windows.h>

#include "utils.h"
#include "wmi.h"

#pragma comment(lib, "wbemuuid.lib")

static BOOL bInitWmiSec = FALSE;
static ULONG uWmiInitCount = 0;

// TODO WmiFree.

// Async sink stuff that I don't know how to get working.
/*
//static ULONG STDMETHODCALLTYPE WmiAddRef(IWbemObjectSink *this) {
//	LPWMI_DATA wmiData = (LPWMI_DATA)this;
//
//	return InterlockedIncrement(&wmiData->lRef);
//}
//
//static ULONG STDMETHODCALLTYPE WmiRelease(IWbemObjectSink *this) {
//	LPWMI_DATA wmiData = (LPWMI_DATA)this;
//
//	LONG lRef = InterlockedDecrement(&wmiData->lRef);
//	if (lRef == 0) {
//		WmiFreeData(wmiData);
//	}
//
//	ZeroMemory(wmiData, sizeof(WMI_DATA));
//
//	return lRef;
//}
//
//static HRESULT STDMETHODCALLTYPE WmiQueryInterface(IWbemObjectSink *this, REFIID riid, void** ppv) {
//	LPWMI_DATA wmiData = (LPWMI_DATA)this;
//
//	if (riid == &IID_IUnknown || riid == &IID_IWbemObjectSink) {
//		*ppv = &wmiData->pSink;
//		WmiAddRef(&wmiData->pSink);
//
//		return WBEM_S_NO_ERROR;
//	} else {
//		return E_NOINTERFACE;
//	}
//}
//
//static HRESULT STDMETHODCALLTYPE WmiIndicate(IWbemObjectSink *this, LONG lObjectCount, IWbemClassObject **apObjArray) {
//	HRESULT hRes = 0;
//	LPWMI_DATA wmiData = (LPWMI_DATA)this;
//
//	// Check if cancelling.
//	if (wmiData->bDone == TRUE) {
//		return WBEM_NO_ERROR;
//	}
//
//	VARIANT valClass, valInstName;
//	for (LONG i = 0; i < lObjectCount; i++) {
//		hRes = apObjArray[i]->lpVtbl->Get(apObjArray[i], L"__CLASS", 0, &valClass, NULL, NULL);
//		if (FAILED(hRes)) {
//			VariantClear(&valClass);
//			VariantClear(&valInstName);
//			return hRes;
//		}
//
//		hRes = apObjArray[i]->lpVtbl->Get(apObjArray[i], L"InstanceName", 0, &valInstName, NULL, NULL);
//		if (FAILED(hRes)) {
//			VariantClear(&valClass);
//			VariantClear(&valInstName);
//			return hRes;
//		}
//
//		Debug(GENERAL, L"Class: %s", valClass.bstrVal);
//	}
//
//	VariantClear(&valClass);
//	VariantClear(&valInstName);
//
//	return WBEM_NO_ERROR;
//}
//
//static HRESULT STDMETHODCALLTYPE WmiSetStatus(IWbemObjectSink *this, LONG lFlags, HRESULT hRes, BSTR strParam, IWbemClassObject *pObjParam) {
//	return WBEM_NO_ERROR;
//}
*/

// https://docs.microsoft.com/en-us/windows/desktop/WmiSdk/example--receiving-event-notifications-through-wmi-
HRESULT WmiInitialise(LPCWSTR szNamespace, LPWMI_DATA wmiData) {
	ZeroMemory(wmiData, sizeof(WMI_DATA));

	HRESULT hRes = CoInitializeEx(NULL, COINIT_MULTITHREADED);
	if (FAILED(hRes)) {
		return hRes;
	}

	uWmiInitCount++;

	if (bInitWmiSec == FALSE) {
		hRes = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
		if (FAILED(hRes)) {
			WmiFreeData(wmiData);
			return hRes;
		}

		bInitWmiSec = TRUE;
	}

	hRes = CoCreateInstance(&CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER, &IID_IWbemLocator, (LPVOID *)&wmiData->pLoc);
	if (FAILED(hRes)) {
		WmiFreeData(wmiData);
		return hRes;
	}

	BSTR bNameSpace = SysAllocString(szNamespace);
	hRes = wmiData->pLoc->lpVtbl->ConnectServer(wmiData->pLoc, bNameSpace, NULL, NULL, NULL, 0, NULL, NULL, &wmiData->pSvc);
	if (FAILED(hRes)) {
		SysFreeString(bNameSpace);
		WmiFreeData(wmiData);
		return hRes;
	}
	SysFreeString(bNameSpace);

	// EventQueryNotificationAsync
	//wmiData->pSink.lpVtbl = &wmiData->pSinkVtbl;
	//wmiData->pSinkVtbl.AddRef = WmiAddRef;
	//wmiData->pSinkVtbl.Indicate = WmiIndicate;
	//wmiData->pSinkVtbl.QueryInterface = WmiQueryInterface;
	//wmiData->pSinkVtbl.Release = WmiRelease;
	//wmiData->pSinkVtbl.SetStatus = WmiSetStatus;

	//wmiData->pSinkVtbl.AddRef(&wmiData->pSink);

	return S_OK;
}

void WmiFree(void) {
	if (uWmiInitCount > 0) {
		CoUninitialize();
		uWmiInitCount--;
	}
}

void WmiFreeData(LPWMI_DATA wmiData) {
	if (wmiData->pLoc != NULL) {
		wmiData->pLoc->lpVtbl->Release(wmiData->pLoc);
	}

	if (wmiData->pSvc != NULL) {
		wmiData->pSvc->lpVtbl->Release(wmiData->pSvc);
	}

	//if (&wmiData->pSink != NULL) {
	//	wmiData->pSink.lpVtbl->Release(&wmiData->pSink);
	//}

	WmiFree();
}

HRESULT WmiEventQueryNotification(LPWMI_DATA wmiData, IEnumWbemClassObject **ppEnum, LPCWSTR szQuery) {
	BSTR bWql = SysAllocString(L"WQL");
	BSTR bQuery = SysAllocString(szQuery);

	HRESULT hRes = wmiData->pSvc->lpVtbl->ExecNotificationQuery(wmiData->pSvc, bWql, bQuery, WBEM_FLAG_RETURN_IMMEDIATELY | WBEM_FLAG_FORWARD_ONLY, NULL, ppEnum);

	SysFreeString(bWql);
	SysFreeString(bQuery);

	return hRes;
}

HRESULT WmiDeleteInstance(LPWMI_DATA wmiData, LPCWSTR szPath) {
	BSTR bPath = SysAllocString(szPath);
	
	HRESULT hRes = wmiData->pSvc->lpVtbl->DeleteInstance(wmiData->pSvc, bPath, 0, NULL, NULL);

	SysFreeString(bPath);

	return hRes;
}