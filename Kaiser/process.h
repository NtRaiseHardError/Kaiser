#pragma once
#ifndef __PROCESS_H__
#define __PROCESS_H__

#include <Windows.h>

#include "processhollowing.h"

#ifdef _DEBUG
// TODO Revert to conhost
#define CHILD_EXE L"\\conhost.exe"
#else
#define CHILD_EXE L"\\svchost.exe"
#endif // _DEBUG

// https://processhacker.sourceforge.io/doc/ntbasic_8h.html
typedef LONG KPRIORITY;

// https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FThread%2FTHREAD_INFORMATION_CLASS.html
typedef enum _THREADINFOCLASS {
	ThreadBasicInformation,
	ThreadTimes,
	ThreadPriority,
	ThreadBasePriority,
	ThreadAffinityMask,
	ThreadImpersonationToken,
	ThreadDescriptorTableEntry,
	ThreadEnableAlignmentFaultFixup,
	ThreadEventPair,
	ThreadQuerySetWin32StartAddress,
	ThreadZeroTlsCell,
	ThreadPerformanceCount,
	ThreadAmILastThread,
	ThreadIdealProcessor,
	ThreadPriorityBoost,
	ThreadSetTlsArrayAddress,
	ThreadIsIoPending,
	ThreadHideFromDebugger
} THREADINFOCLASS, *PTHREADINFOCLASS;

// https://msdn.microsoft.com/en-us/library/gg750647.aspx?f=255&MSPPError=-2147217396
typedef struct _CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID;

// http://undocumented.ntinternals.net/index.html?page=UserMode%2FStructures%2FTHREAD_BASIC_INFORMATION.html
typedef struct _THREAD_BASIC_INFORMATION {
	NTSTATUS                ExitStatus;
	PVOID                   TebBaseAddress;
	CLIENT_ID               ClientId;
	KAFFINITY               AffinityMask;
	KPRIORITY               Priority;
	KPRIORITY               BasePriority;
} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;

// https://www.nirsoft.net/kernel_struct/vista/RTL_ACTIVATION_CONTEXT_STACK_FRAME.html
typedef struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME RTL_ACTIVATION_CONTEXT_STACK_FRAME, *PRTL_ACTIVATION_CONTEXT_STACK_FRAME;
struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME {
	PRTL_ACTIVATION_CONTEXT_STACK_FRAME Previous;
	PVOID ActivationContext; //_ACTIVATION_CONTEXT *
	ULONG Flags;
};

// https://www.nirsoft.net/kernel_struct/vista/ACTIVATION_CONTEXT_STACK.html
typedef struct _ACTIVATION_CONTEXT_STACK {
	PRTL_ACTIVATION_CONTEXT_STACK_FRAME ActiveFrame;
	LIST_ENTRY FrameListCache;
	ULONG Flags;
	ULONG NextCookieSequenceNumber;
	ULONG StackId;
} ACTIVATION_CONTEXT_STACK, *PACTIVATION_CONTEXT_STACK;

// https://www.nirsoft.net/kernel_struct/vista/GDI_TEB_BATCH.html
typedef struct _GDI_TEB_BATCH {
	ULONG Offset;
	ULONG HDC;
	ULONG Buffer[310];
} GDI_TEB_BATCH, *PGDI_TEB_BATCH;

// https://www.nirsoft.net/kernel_struct/vista/TEB_ACTIVE_FRAME_CONTEXT.html
typedef struct _TEB_ACTIVE_FRAME_CONTEXT {
	ULONG Flags;
	CHAR *FrameName;
} TEB_ACTIVE_FRAME_CONTEXT, *PTEB_ACTIVE_FRAME_CONTEXT;

// https://www.nirsoft.net/kernel_struct/vista/TEB_ACTIVE_FRAME.html
typedef struct _TEB_ACTIVE_FRAME TEB_ACTIVE_FRAME, *PTEB_ACTIVE_FRAME;
struct _TEB_ACTIVE_FRAME {
	ULONG Flags;
	PTEB_ACTIVE_FRAME Previous;
	PTEB_ACTIVE_FRAME_CONTEXT Context;
};

// https://www.nirsoft.net/kernel_struct/vista/TEB.html
typedef struct _TEB {
	NT_TIB NtTib;
	PVOID EnvironmentPointer;
	CLIENT_ID ClientId;
	PVOID ActiveRpcHandle;
	PVOID ThreadLocalStoragePointer;
	PPEB ProcessEnvironmentBlock;
	ULONG LastErrorValue;
	ULONG CountOfOwnedCriticalSections;
	PVOID CsrClientThread;
	PVOID Win32ThreadInfo;
	ULONG User32Reserved[26];
	ULONG UserReserved[5];
	PVOID WOW32Reserved;
	ULONG CurrentLocale;
	ULONG FpSoftwareStatusRegister;
	VOID *SystemReserved1[54];
	LONG ExceptionCode;
	PACTIVATION_CONTEXT_STACK ActivationContextStackPointer;
	UCHAR SpareBytes1[36];
	ULONG TxFsContext;
	GDI_TEB_BATCH GdiTebBatch;
	CLIENT_ID RealClientId;
	PVOID GdiCachedProcessHandle;
	ULONG GdiClientPID;
	ULONG GdiClientTID;
	PVOID GdiThreadLocalInfo;
	ULONG Win32ClientInfo[62];
	VOID *glDispatchTable[233];
	ULONG glReserved1[29];
	PVOID glReserved2;
	PVOID glSectionInfo;
	PVOID glSection;
	PVOID glTable;
	PVOID glCurrentRC;
	PVOID glContext;
	ULONG LastStatusValue;
	UNICODE_STRING StaticUnicodeString;
	WCHAR StaticUnicodeBuffer[261];
	PVOID DeallocationStack;
	VOID *TlsSlots[64];
	LIST_ENTRY TlsLinks;
	PVOID Vdm;
	PVOID ReservedForNtRpc;
	VOID *DbgSsReserved[2];
	ULONG HardErrorMode;
	VOID *Instrumentation[9];
	GUID ActivityId;
	PVOID SubProcessTag;
	PVOID EtwLocalData;
	PVOID EtwTraceData;
	PVOID WinSockData;
	ULONG GdiBatchCount;
	UCHAR SpareBool0;
	UCHAR SpareBool1;
	UCHAR SpareBool2;
	UCHAR IdealProcessor;
	ULONG GuaranteedStackBytes;
	PVOID ReservedForPerf;
	PVOID ReservedForOle;
	ULONG WaitingOnLoaderLock;
	PVOID SavedPriorityState;
	ULONG SoftPatchPtr1;
	PVOID ThreadPoolData;
	VOID **TlsExpansionSlots;
	ULONG ImpersonationLocale;
	ULONG IsImpersonating;
	PVOID NlsCache;
	PVOID pShimData;
	ULONG HeapVirtualAffinity;
	PVOID CurrentTransactionHandle;
	PTEB_ACTIVE_FRAME ActiveFrame;
	PVOID FlsData;
	PVOID PreferredLanguages;
	PVOID UserPrefLanguages;
	PVOID MergedPrefLanguages;
	ULONG MuiImpersonation;
	WORD CrossTebFlags;
	ULONG SpareCrossTebBits : 16;
	WORD SameTebFlags;
	ULONG DbgSafeThunkCall : 1;
	ULONG DbgInDebugPrint : 1;
	ULONG DbgHasFiberData : 1;
	ULONG DbgSkipThreadAttach : 1;
	ULONG DbgWerInShipAssertCode : 1;
	ULONG DbgRanProcessInit : 1;
	ULONG DbgClonedThread : 1;
	ULONG DbgSuppressDebugMsg : 1;
	ULONG SpareSameTebBits : 8;
	PVOID TxnScopeEnterCallback;
	PVOID TxnScopeExitCallback;
	PVOID TxnScopeContext;
	ULONG LockCount;
	ULONG ProcessRundown;
	UINT64 LastSwitchTime;
	UINT64 TotalSwitchOutTime;
	LARGE_INTEGER WaitReasonBitMap;
} TEB, *PTEB;

// https://wj32.org/wp/2010/03/30/howto-use-i_querytaginformation/
typedef enum _SC_SERVICE_TAG_QUERY_TYPE {
	ServiceNameFromTagInformation = 1,
	ServiceNamesReferencingModuleInformation,
	ServiceNameTagMappingInformation
} SC_SERVICE_TAG_QUERY_TYPE, *PSC_SERVICE_TAG_QUERY_TYPE;

// https://wj32.org/wp/2010/03/30/howto-use-i_querytaginformation/
typedef struct _SC_SERVICE_TAG_QUERY {
	ULONG ProcessId;
	ULONG ServiceTag;
	ULONG Unknown;
	PVOID Buffer;
} SC_SERVICE_TAG_QUERY, *PSC_SERVICE_TAG_QUERY;

ULONG ProcessGetPeb(HANDLE hProcess, PPEB peb);
PVOID ProcessGetBaseAddress(HANDLE hProcess);
ULONG ProcessCreateInteractiveSocketShellReflective(CONST SOCKET s, LPCBYTE lpBytes, LPWSTR lpArguments, LPPROCESS_INFORMATION pi);
ULONG ProcessCreateInteractiveSocketShell(CONST SOCKET s, LPWSTR lpExeName, LPWSTR lpArguments, LPPROCESS_INFORMATION pi);
ULONG ProcessCreateReflective(LPCBYTE lpBytes, LPWSTR lpArguments, LPPROCESS_INFORMATION pi);
INT ProcessShellExecute(LPCWSTR lpFileName, LPCWSTR lpArguments, PHANDLE hProcess);
BOOL ProcessGetProcessIds(LPDWORD dwProcessIds, DWORD dwSizeInBytes, LPDWORD dwNumProcesses);
HANDLE ProcessGetProcessById(DWORD dwProcessId, DWORD dwDesiredAccess);
ULONG ProcessGetThreadIds(DWORD dwProcessId, LPDWORD dwThreadIds, DWORD dwSizeInBytes, LPDWORD dwNumThreads);
ULONG ProcessThreadGetTeb(DWORD dwThreadId, PVOID *TebBaseAddress);
ULONG ProcessGetTagInformation(DWORD dwProcessId, ULONG uServiceTag, PSC_SERVICE_TAG_QUERY psstq);
ULONG ProcessGetSubProcessTag(HANDLE hProcess, PVOID pTebAddress, PULONG uSubProcessTag);
ULONG ProcessGetSystemModuleBase(HANDLE hProcess, LPCWSTR szModuleName, HMODULE *hModule);
ULONG ProcessPatchMemoryPattern(HANDLE hProcess, DWORD_PTR dwBaseAddress, DWORD_PTR dwEndAddress, DWORD_PTR dwOffset, LPCBYTE lpSearchPattern, SIZE_T nSearchSize, LPCBYTE lpReplacePattern, SIZE_T nReplaceSize, PBOOL bIsPatched);
ULONG ProcessSetPrivilege(HANDLE hProcess, LPCWSTR szPrivilege, BOOL bEnablePrivilege);

#endif // !__PROCESS_H__
