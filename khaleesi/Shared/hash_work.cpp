#include "pch.h"
#include "MurmurHash2A.h"
#include "PointerHashFunc.h"
#include "export_work.h"

HANDLE hash_CreateFileA(
	__in LPCSTR file_name,
	__in DWORD access,
	__in DWORD share_mode,
	__in LPSECURITY_ATTRIBUTES security,
	__in DWORD creation_disposition,
	__in DWORD flags,
	__in HANDLE template_file)
{
	const auto _hash = MurmurHash2A("CreateFileA", 12, 12);

	temp_CreateFile = static_cast<HANDLE(WINAPI *)(LPCSTR,
	                                               DWORD,
	                                               DWORD,
	                                               LPSECURITY_ATTRIBUTES,
	                                               DWORD,
	                                               DWORD,
	                                               HANDLE)>(get_api(_hash, "kernel32.dll", 12, 12));

	return temp_CreateFile(file_name, access, share_mode, security, creation_disposition, flags, template_file);
}

BOOL hash_VirtualProtect(LPVOID lpAddress,
                         SIZE_T dwSize,
                         DWORD flNewProtect,
                         PDWORD lpflOldProtect)
{
	const auto _hash = MurmurHash2A("VirtualProtect", 15, 15);

	temp_VirtualProtect = static_cast<BOOL(WINAPI*)(LPVOID,
	                                                SIZE_T,
	                                                DWORD,
	                                                PDWORD)>(get_api(_hash, "kernel32.dll", 15, 15));

	return temp_VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect);
}

LPVOID hash_VirtualAlloc(LPVOID lpAddress,
                         SIZE_T dwSize,
                         DWORD flAllocationType,
                         DWORD flProtect)
{
	const auto _hash = MurmurHash2A("VirtualAlloc", 13, 13);

	temp_VirtualAlloc = static_cast<LPVOID(WINAPI*)(LPVOID,
	                                                SIZE_T,
	                                                DWORD,
	                                                DWORD)>(get_api(_hash, "kernel32.dll", 13, 13));

	return temp_VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);
}

BOOL hash_VirtualFree(LPVOID lpAddress,
                      SIZE_T dwSize,
                      DWORD dwFreeType)
{
	const auto _hash = MurmurHash2A("VirtualFree", 12, 12);

	temp_VirtualFree = static_cast<BOOL(WINAPI*)(LPVOID,
	                                             SIZE_T,
	                                             DWORD)>(get_api(_hash, "kernel32.dll", 12, 12));

	return temp_VirtualFree(lpAddress, dwSize, dwFreeType);
}

LPVOID hash_VirtualAllocEx(HANDLE hProcess,
                           LPVOID lpAddress,
                           SIZE_T dwSize,
                           DWORD flAllocationType,
                           DWORD flProtect)
{
	const auto _hash = MurmurHash2A("VirtualAllocEx", 15, 15);

	temp_VirtualAllocEx = static_cast<LPVOID(WINAPI*)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD)>(get_api(
		_hash, "kernel32.dll", 15, 15));

	return temp_VirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect);
}

BOOL hash_VirtualFreeEx(HANDLE hProcess,
                        LPVOID lpAddress,
                        SIZE_T dwSize,
                        DWORD dwFreeType)
{
	const auto _hash = MurmurHash2A("VirtualFreeEx", 14, 14);

	temp_VirtualFreeEx = static_cast<BOOL(WINAPI*)(HANDLE,
	                                               LPVOID,
	                                               SIZE_T,
	                                               DWORD)>(get_api(_hash, "kernel32.dll", 14, 14));

	return temp_VirtualFreeEx(hProcess,
	                          lpAddress,
	                          dwSize,
	                          dwFreeType);
}

DWORD hash_QueryDosDeviceW(LPCWSTR lpDeviceName,
                           LPWSTR lpTargetPath,
                           DWORD ucchMax)
{
	const auto _hash = MurmurHash2A("QueryDosDeviceW", 16, 16);

	temp_QueryDosDeviceW = static_cast<DWORD(WINAPI*)(LPCWSTR,
	                                                  LPWSTR,
	                                                  DWORD)>(get_api(_hash, "kernel32.dll", 16, 16));

	return temp_QueryDosDeviceW(lpDeviceName,
	                            lpTargetPath,
	                            ucchMax);
}

BOOL hash_GetDiskFreeSpaceExW(LPCWSTR lpDirectoryName,
                              PULARGE_INTEGER lpFreeBytesAvailableToCaller,
                              PULARGE_INTEGER lpTotalNumberOfBytes,
                              PULARGE_INTEGER lpTotalNumberOfFreeBytes)
{
	const auto _hash = MurmurHash2A("GetDiskFreeSpaceExW", 20, 20);

	temp_GetDiskFreeSpaceExW = static_cast<BOOL(WINAPI*)(LPCWSTR,
	                                                     PULARGE_INTEGER,
	                                                     PULARGE_INTEGER,
	                                                     PULARGE_INTEGER)>(get_api(_hash, "kernel32.dll", 20, 20));

	return temp_GetDiskFreeSpaceExW(lpDirectoryName,
	                                lpFreeBytesAvailableToCaller,
	                                lpTotalNumberOfBytes,
	                                lpTotalNumberOfFreeBytes);
}

HMODULE hash_LoadLibraryW(LPCWSTR lpLibFileName)
{
	const auto _hash = MurmurHash2A("LoadLibraryW", 13, 13);

	temp_LoadLibraryW = static_cast<HMODULE(WINAPI*)(LPCWSTR)>(get_api(_hash, "kernel32.dll", 13, 13));

	return temp_LoadLibraryW(lpLibFileName);
}

BOOL hash_GetModuleHandleExW(DWORD dwFlags,
                             LPCWSTR lpModuleName,
                             HMODULE* phModule)
{
	const auto _hash = MurmurHash2A("GetModuleHandleExW", 19, 19);

	temp_GetModuleHandleExW = static_cast<BOOL(WINAPI*)(DWORD,
	                                                    LPCWSTR,
	                                                    HMODULE*)>(get_api(_hash, "kernel32.dll", 19, 19));

	return temp_GetModuleHandleExW(dwFlags,
	                               lpModuleName,
	                               phModule);
}

DWORD hash_GetModuleFileNameW(HMODULE hModule,
                              LPWSTR lpFilename,
                              DWORD nSize)
{	
	const auto lenSeed = 19;
	const auto _hash = MurmurHash2A("GetModuleFileNameW", lenSeed, lenSeed);

	temp_GetModuleFileNameW = static_cast<DWORD(WINAPI*)(HMODULE,
	                                                     LPWSTR,
	                                                     DWORD)>(get_api(_hash, "kernel32.dll", lenSeed, lenSeed));

	return temp_GetModuleFileNameW(hModule,
	                               lpFilename,
	                               nSize);
}

HMODULE hash_GetModuleHandleA(LPCSTR lpModuleName)
{
	const auto _hash = MurmurHash2A("GetModuleHandleA", 17, 17);

	temp_GetModuleHandleA = static_cast<HMODULE(WINAPI*)(LPCSTR)>(get_api(_hash, "kernel32.dll", 17, 17));

	return temp_GetModuleHandleA(lpModuleName);
}

HMODULE hash_GetModuleHandleW(LPCWSTR lpModuleName)
{
	const auto _hash = MurmurHash2A("GetModuleHandleW", 17, 17);

	temp_GetModuleHandleW = static_cast<HMODULE(WINAPI*)(LPCWSTR)>(get_api(_hash, "kernel32.dll", 17, 17));

	return temp_GetModuleHandleW(lpModuleName);
}

FARPROC hash_GetProcAddress(HMODULE hModule,
                            LPCSTR lpProcName)
{
	const auto _hash = MurmurHash2A("GetProcAddress", 15, 15);

	temp_GetProcAddress = static_cast<FARPROC(WINAPI*)(HMODULE,
	                                                   LPCSTR)>(get_api(_hash, "kernel32.dll", 15, 15));

	return temp_GetProcAddress(hModule,
	                           lpProcName);
}

HANDLE hash_GetStdHandle(_In_ DWORD nStdHandle)
{
	const auto _hash = MurmurHash2A("GetStdHandle", 13, 13);

	temp_GetStdHandle = static_cast<HANDLE(WINAPI*)(_In_ DWORD)>(get_api(_hash, "kernel32.dll", 13, 13));

	return temp_GetStdHandle(nStdHandle);
}

BOOL hash_GetConsoleScreenBufferInfo(_In_ HANDLE hConsoleOutput,
                                     _Out_ PCONSOLE_SCREEN_BUFFER_INFO lpConsoleScreenBufferInfo)
{
	const auto _hash = MurmurHash2A("GetConsoleScreenBufferInfo", 27, 27);

	temp_GetConsoleScreenBufferInfo = static_cast<BOOL(WINAPI*)(_In_ HANDLE,
	                                                            _Out_ PCONSOLE_SCREEN_BUFFER_INFO)>(get_api(
		_hash, "kernel32.dll", 27, 27));

	return temp_GetConsoleScreenBufferInfo(hConsoleOutput,
	                                       lpConsoleScreenBufferInfo);
}

BOOL hash_SetConsoleTextAttribute(_In_ HANDLE hConsoleOutput,
                                  _In_ WORD wAttributes)
{
	const auto _hash = MurmurHash2A("SetConsoleTextAttribute", 24, 24);

	temp_SetConsoleTextAttribute = static_cast<BOOL(WINAPI*)(_In_ HANDLE,
	                                                         _In_ WORD)>(get_api(_hash, "kernel32.dll", 24, 24));

	return temp_SetConsoleTextAttribute(hConsoleOutput,
	                                    wAttributes);
}

DWORD hash_GetTickCount()
{
	const auto lenSeed = 13;
	const auto _hash = MurmurHash2A("GetTickCount", lenSeed, lenSeed);

	temp_GetTickCount = static_cast<DWORD(WINAPI*)()>(get_api(_hash, "kernel32.dll", lenSeed, lenSeed));

	return temp_GetTickCount();
}

BOOL hash_VerifyVersionInfoW(LPOSVERSIONINFOEXA lpVersionInformation,
                             DWORD dwTypeMask,
                             DWORDLONG dwlConditionMask)
{
	const auto lenSeed = 18;
	const auto _hash = MurmurHash2A("VerifyVersionInfoW", lenSeed, lenSeed);

	temp_VerifyVersionInfoW = static_cast<BOOL(WINAPI*)(LPOSVERSIONINFOEXA,
	                                                    DWORD,
	                                                    DWORDLONG)>(get_api(_hash, "kernel32.dll", lenSeed, lenSeed));

	return temp_VerifyVersionInfoW(lpVersionInformation,
	                               dwTypeMask,
	                               dwlConditionMask);
}

UINT hash_GetSystemWindowsDirectoryW(LPWSTR lpBuffer,
                                     UINT uSize)
{
	const auto lenSeed = 27;
	const auto _hash = MurmurHash2A("GetSystemWindowsDirectoryW", lenSeed, lenSeed);

	temp_GetSystemWindowsDirectoryW = static_cast<UINT(WINAPI*)(LPWSTR,
	                                                            UINT)>(get_api(
		_hash, "kernel32.dll", lenSeed, lenSeed));

	return temp_GetSystemWindowsDirectoryW(lpBuffer,
	                                       uSize);
}

UINT hash_GetWindowsDirectoryW(LPWSTR lpBuffer,
                               UINT uSize)
{
	const auto lenSeed = 21;
	const auto _hash = MurmurHash2A("GetWindowsDirectoryW", lenSeed, lenSeed);

	temp_GetWindowsDirectoryW = static_cast<UINT(WINAPI*)(LPWSTR,
	                                                      UINT)>(get_api(_hash, "kernel32.dll", lenSeed, lenSeed));

	return temp_GetWindowsDirectoryW(lpBuffer,
	                                 uSize);
}

UINT hash_GetSystemDirectoryW(LPWSTR lpBuffer,
                              UINT uSize)
{
	const auto lenSeed = 20;
	const auto _hash = MurmurHash2A("GetSystemDirectoryW", lenSeed, lenSeed);

	temp_GetSystemDirectoryW = static_cast<UINT(WINAPI*)(LPWSTR,
	                                                     UINT)>(get_api(_hash, "kernel32.dll", lenSeed, lenSeed));

	return temp_GetSystemDirectoryW(lpBuffer,
	                                uSize);
}

UINT hash_GetSystemDirectoryA(LPSTR lpBuffer,
                              UINT uSize)
{
	const auto lenSeed = 20;
	const auto _hash = MurmurHash2A("GetSystemDirectoryA", lenSeed, lenSeed);

	temp_GetSystemDirectoryA = static_cast<UINT(WINAPI*)(LPSTR,
	                                                     UINT)>(get_api(_hash, "kernel32.dll", lenSeed, lenSeed));

	return temp_GetSystemDirectoryA(lpBuffer,
	                                uSize);
}

void hash_GetSystemInfo(LPSYSTEM_INFO lpSystemInfo)
{
	const auto lenSeed = 14;
	const auto _hash = MurmurHash2A("GetSystemInfo", lenSeed, lenSeed);

	temp_GetSystemInfo = static_cast<void(WINAPI*)(LPSYSTEM_INFO)>(get_api(_hash, "kernel32.dll", lenSeed, lenSeed));

	return temp_GetSystemInfo(lpSystemInfo);
}

DWORD hash_ExpandEnvironmentStringsW(LPCWSTR lpSrc,
                                     LPWSTR lpDst,
                                     DWORD nSize)
{
	const auto lenSeed = 26;
	const auto _hash = MurmurHash2A("ExpandEnvironmentStringsW", lenSeed, lenSeed);

	temp_ExpandEnvironmentStringsW = static_cast<DWORD(WINAPI*)(LPCWSTR,
	                                                            LPWSTR,
	                                                            DWORD)>(get_api(
		_hash, "kernel32.dll", lenSeed, lenSeed));

	return temp_ExpandEnvironmentStringsW(lpSrc,
	                                      lpDst,
	                                      nSize);
}

BOOL hash_QueryPerformanceCounter(LARGE_INTEGER* lpPerformanceCount)
{
	const auto lenSeed = 24;
	const auto _hash = MurmurHash2A("QueryPerformanceCounter", lenSeed, lenSeed);

	temp_QueryPerformanceCounter = static_cast<BOOL(WINAPI*)(LARGE_INTEGER*)>(get_api(
		_hash, "kernel32.dll", lenSeed, lenSeed));

	return temp_QueryPerformanceCounter(lpPerformanceCount);
}

BOOL hash_IsProcessorFeaturePresent(DWORD ProcessorFeature)
{
	const auto lenSeed = 26;
	const auto _hash = MurmurHash2A("IsProcessorFeaturePresent", lenSeed, lenSeed);

	temp_IsProcessorFeaturePresent = static_cast<BOOL(WINAPI*)(DWORD)>(get_api(_hash, "kernel32.dll", lenSeed, lenSeed)
	);

	return temp_IsProcessorFeaturePresent(ProcessorFeature);
}

//TODO: needed fix
PVOID hash_AddVectoredExceptionHandler(ULONG First,
                                       PVECTORED_EXCEPTION_HANDLER Handler)
{
	const auto lenSeed = 28;
	const auto _hash = MurmurHash2A("AddVectoredExceptionHandler", lenSeed, lenSeed);

	temp_AddVectoredExceptionHandler = static_cast<PVOID(WINAPI*)(ULONG, PVECTORED_EXCEPTION_HANDLER)>(get_api(
		_hash, "kernel32.dll", lenSeed, lenSeed));

	return temp_AddVectoredExceptionHandler(First, Handler);
}

void hash_SetLastError(DWORD dwErrCode)
{
	const auto lenSeed = 13;
	const auto _hash = MurmurHash2A("SetLastError", lenSeed, lenSeed);

	temp_SetLastError = static_cast<void(WINAPI*)(DWORD)>(get_api(_hash, "kernel32.dll", lenSeed, lenSeed));

	return temp_SetLastError(dwErrCode);
}

_Post_equals_last_error_ DWORD hash_GetLastError()
{
	const auto lenSeed = 13;
	const auto _hash = MurmurHash2A("GetLastError", lenSeed, lenSeed);

	temp_GetLastError = static_cast<DWORD(WINAPI*)()>(get_api(_hash, "kernel32.dll", lenSeed, lenSeed));

	return temp_GetLastError();
}

void hash_OutputDebugStringW(LPCWSTR lpOutputString)
{
	const auto lenSeed = 19;
	const auto _hash = MurmurHash2A("OutputDebugStringW", lenSeed, lenSeed);

	temp_OutputDebugStringW = static_cast<void(WINAPI*)(LPCWSTR)>(get_api(_hash, "kernel32.dll", lenSeed, lenSeed));

	return temp_OutputDebugStringW(lpOutputString);
}

DWORD hash_FormatMessageW(DWORD dwFlags,
                          LPCVOID lpSource,
                          DWORD dwMessageId,
                          DWORD dwLanguageId,
                          LPWSTR lpBuffer,
                          DWORD nSize,
                          va_list* Arguments)
{
	const auto lenSeed = 15;
	const auto _hash = MurmurHash2A("FormatMessageW", lenSeed, lenSeed);

	temp_FormatMessageW = static_cast<DWORD(WINAPI*)(DWORD,
	                                                 LPCVOID,
	                                                 DWORD,
	                                                 DWORD,
	                                                 LPWSTR,
	                                                 DWORD,
	                                                 va_list*)>(get_api(_hash, "kernel32.dll", lenSeed, lenSeed));

	return temp_FormatMessageW(dwFlags,
	                           lpSource,
	                           dwMessageId,
	                           dwLanguageId,
	                           lpBuffer,
	                           nSize,
	                           Arguments);
}

HANDLE hash_CreateMutexW(LPSECURITY_ATTRIBUTES lpMutexAttributes,
                         BOOL bInitialOwner,
                         LPCWSTR lpName)
{
	const auto lenSeed = 13;
	const auto _hash = MurmurHash2A("CreateMutexW", lenSeed, lenSeed);

	temp_CreateMutexW = static_cast<HANDLE(WINAPI*)(LPSECURITY_ATTRIBUTES,
	                                                BOOL,
	                                                LPCWSTR)>(get_api(_hash, "kernel32.dll", lenSeed, lenSeed));

	return temp_CreateMutexW(lpMutexAttributes,
	                         bInitialOwner,
	                         lpName);
}

HANDLE hash_CreateEventW(LPSECURITY_ATTRIBUTES lpEventAttributes,
                         BOOL bManualReset,
                         BOOL bInitialState,
                         LPCWSTR lpName)
{
	const auto lenSeed = 13;
	const auto _hash = MurmurHash2A("CreateEventW", lenSeed, lenSeed);

	temp_CreateEventW = static_cast<HANDLE(WINAPI*)(LPSECURITY_ATTRIBUTES,
	                                                BOOL,
	                                                BOOL,
	                                                LPCWSTR)>(get_api(_hash, "kernel32.dll", lenSeed, lenSeed));

	return temp_CreateEventW(lpEventAttributes,
	                         bManualReset,
	                         bInitialState,
	                         lpName);
}

BOOL hash_SetEvent(HANDLE hEvent)
{
	const auto lenSeed = 9;
	const auto _hash = MurmurHash2A("SetEvent", lenSeed, lenSeed);

	temp_SetEvent = static_cast<BOOL(WINAPI*)(HANDLE)>(get_api(_hash, "kernel32.dll", lenSeed, lenSeed));

	return temp_SetEvent(hEvent);
}

DWORD hash_WaitForSingleObject(HANDLE hHandle,
                               DWORD dwMilliseconds)
{
	const auto lenSeed = 20;
	const auto _hash = MurmurHash2A("WaitForSingleObject", lenSeed, lenSeed);

	temp_WaitForSingleObject = static_cast<DWORD(WINAPI*)(HANDLE,
	                                                      DWORD)>(get_api(_hash, "kernel32.dll", lenSeed, lenSeed));

	return temp_WaitForSingleObject(hHandle,
	                                dwMilliseconds);
}

DWORD hash_QueueUserAPC(PAPCFUNC pfnAPC,
                        HANDLE hThread,
                        ULONG_PTR dwData)
{
	const auto lenSeed = 13;
	const auto _hash = MurmurHash2A("QueueUserAPC", lenSeed, lenSeed);

	temp_QueueUserAPC = static_cast<DWORD(WINAPI*)(PAPCFUNC,
	                                               HANDLE,
	                                               ULONG_PTR)>(get_api(_hash, "kernel32.dll", lenSeed, lenSeed));

	return temp_QueueUserAPC(pfnAPC,
	                         hThread,
	                         dwData);
}

HANDLE hash_CreateThread(LPSECURITY_ATTRIBUTES lpThreadAttributes,
                         SIZE_T dwStackSize,
                         LPTHREAD_START_ROUTINE lpStartAddress,
                         __drv_aliasesMem LPVOID lpParameter,
                         DWORD dwCreationFlags,
                         LPDWORD lpThreadId)
{
	const auto lenSeed = 13;
	const auto _hash = MurmurHash2A("CreateEventW", lenSeed, lenSeed);

	temp_CreateThread = static_cast<HANDLE(WINAPI*)(LPSECURITY_ATTRIBUTES,
	                                                SIZE_T,
	                                                LPTHREAD_START_ROUTINE,
	                                                __drv_aliasesMem LPVOID,
	                                                DWORD,
	                                                LPDWORD)>(get_api(_hash, "kernel32.dll", lenSeed, lenSeed));

	return temp_CreateThread(lpThreadAttributes,
	                         dwStackSize,
	                         lpStartAddress,
	                         lpParameter,
	                         dwCreationFlags,
	                         lpThreadId);
}

HANDLE hash_CreateWaitableTimerW(LPSECURITY_ATTRIBUTES lpTimerAttributes,
                                 BOOL bManualReset,
                                 LPCWSTR lpTimerName)
{
	const auto lenSeed = 21;
	const auto _hash = MurmurHash2A("CreateWaitableTimerW", lenSeed, lenSeed);

	temp_CreateWaitableTimerW = static_cast<HANDLE(WINAPI*)(LPSECURITY_ATTRIBUTES,
	                                                        BOOL,
	                                                        LPCWSTR)>(get_api(_hash, "kernel32.dll", lenSeed, lenSeed));

	return temp_CreateWaitableTimerW(lpTimerAttributes,
	                                 bManualReset,
	                                 lpTimerName);
}

BOOL hash_SetWaitableTimer(HANDLE hTimer,
                           const LARGE_INTEGER* lpDueTime,
                           LONG lPeriod,
                           PTIMERAPCROUTINE pfnCompletionRoutine,
                           LPVOID lpArgToCompletionRoutine,
                           BOOL fResume)
{
	const auto lenSeed = 17;
	const auto _hash = MurmurHash2A("SetWaitableTimer", lenSeed, lenSeed);

	temp_SetWaitableTimer = static_cast<BOOL(WINAPI*)(HANDLE,
	                                                  const LARGE_INTEGER*,
	                                                  LONG,
	                                                  PTIMERAPCROUTINE,
	                                                  LPVOID,
	                                                  BOOL)>(get_api(_hash, "kernel32.dll", lenSeed, lenSeed));

	return temp_SetWaitableTimer(hTimer,
	                             lpDueTime,
	                             lPeriod,
	                             pfnCompletionRoutine,
	                             lpArgToCompletionRoutine,
	                             fResume);
}

BOOL hash_CancelWaitableTimer(HANDLE hTimer)
{
	const auto lenSeed = 20;
	const auto _hash = MurmurHash2A("CancelWaitableTimer", lenSeed, lenSeed);

	temp_CancelWaitableTimer = static_cast<BOOL(WINAPI*)(HANDLE)>(get_api(_hash, "kernel32.dll", lenSeed, lenSeed));

	return temp_CancelWaitableTimer(hTimer);
}

BOOL hash_CreateTimerQueueTimer(PHANDLE phNewTimer,
                                HANDLE TimerQueue,
                                WAITORTIMERCALLBACK Callback,
                                PVOID DueTime,
                                DWORD Period,
                                DWORD Flags,
                                ULONG Parameter)
{
	const auto lenSeed = 22;
	const auto _hash = MurmurHash2A("CreateTimerQueueTimer", lenSeed, lenSeed);

	temp_CreateTimerQueueTimer = static_cast<BOOL(WINAPI*)(PHANDLE,
	                                                       HANDLE,
	                                                       WAITORTIMERCALLBACK,
	                                                       PVOID,
	                                                       DWORD,
	                                                       DWORD,
	                                                       ULONG)>(get_api(_hash, "kernel32.dll", lenSeed, lenSeed));

	return temp_CreateTimerQueueTimer(phNewTimer,
	                                  TimerQueue,
	                                  Callback,
	                                  DueTime,
	                                  Period,
	                                  Flags,
	                                  Parameter);
}

DWORD hash_SetFilePointer(HANDLE hFile,
                          LONG lDistanceToMove,
                          PLONG lpDistanceToMoveHigh,
                          DWORD dwMoveMethod)
{
	const auto lenSeed = 15;
	const auto _hash = MurmurHash2A("SetFilePointer", lenSeed, lenSeed);

	temp_SetFilePointer = static_cast<DWORD(WINAPI*)(HANDLE,
	                                                 LONG,
	                                                 PLONG,
	                                                 DWORD)>(get_api(_hash, "kernel32.dll", lenSeed, lenSeed));

	return temp_SetFilePointer(hFile,
	                           lDistanceToMove,
	                           lpDistanceToMoveHigh,
	                           dwMoveMethod);
}

BOOL hash_ReadFile(HANDLE hFile,
                   LPVOID lpBuffer,
                   DWORD nNumberOfBytesToRead,
                   LPDWORD lpNumberOfBytesRead,
                   LPOVERLAPPED lpOverlapped)
{
	const auto lenSeed = 9;
	const auto _hash = MurmurHash2A("ReadFile", lenSeed, lenSeed);

	temp_ReadFile = static_cast<BOOL(WINAPI*)(HANDLE,
	                                          LPVOID,
	                                          DWORD,
	                                          LPDWORD,
	                                          LPOVERLAPPED)>(get_api(_hash, "kernel32.dll", lenSeed, lenSeed));

	return temp_ReadFile(hFile,
	                     lpBuffer,
	                     nNumberOfBytesToRead,
	                     lpNumberOfBytesRead,
	                     lpOverlapped);
}

HANDLE hash_CreateFileW(LPCWSTR lpFileName,
                        DWORD dwDesiredAccess,
                        DWORD dwShareMode,
                        LPSECURITY_ATTRIBUTES lpSecurityAttributes,
                        DWORD dwCreationDisposition,
                        DWORD dwFlagsAndAttributes,
                        HANDLE hTemplateFile)
{
	const auto lenSeed = 12;
	const auto _hash = MurmurHash2A("CreateFileW", lenSeed, lenSeed);

	temp_CreateFileW = static_cast<HANDLE(WINAPI*)(LPCWSTR,
	                                               DWORD,
	                                               DWORD,
	                                               LPSECURITY_ATTRIBUTES,
	                                               DWORD,
	                                               DWORD,
	                                               HANDLE)>(get_api(_hash, "kernel32.dll", lenSeed, lenSeed));

	return temp_CreateFileW(lpFileName,
	                        dwDesiredAccess,
	                        dwShareMode,
	                        lpSecurityAttributes,
	                        dwCreationDisposition,
	                        dwFlagsAndAttributes,
	                        hTemplateFile);
}

DWORD hash_GetFullPathNameW(LPCWSTR lpFileName,
                            DWORD nBufferLength,
                            LPWSTR lpBuffer,
                            LPWSTR* lpFilePart)
{
	const auto lenSeed = 17;
	const auto _hash = MurmurHash2A("GetFullPathNameW", lenSeed, lenSeed);

	temp_GetFullPathNameW = static_cast<DWORD(WINAPI*)(LPCWSTR,
	                                                   DWORD,
	                                                   LPWSTR,
	                                                   LPWSTR*)>(get_api(_hash, "kernel32.dll", lenSeed, lenSeed));

	return temp_GetFullPathNameW(lpFileName,
	                             nBufferLength,
	                             lpBuffer,
	                             lpFilePart);
}

DWORD hash_GetFileAttributesW(LPCWSTR lpFileName)
{
	const auto lenSeed = 19;
	const auto _hash = MurmurHash2A("GetFileAttributesW", lenSeed, lenSeed);

	temp_GetFileAttributesW = static_cast<DWORD(WINAPI*)(LPCWSTR)>(get_api(_hash, "kernel32.dll", lenSeed, lenSeed));

	return temp_GetFileAttributesW(lpFileName);
}


void hash_GetSystemTimeAsFileTime(LPFILETIME lpSystemTimeAsFileTime)
{
	const auto lenSeed = 24;
	const auto _hash = MurmurHash2A("GetSystemTimeAsFileTime", lenSeed, lenSeed);

	temp_GetSystemTimeAsFileTime = static_cast<void(WINAPI*)(LPFILETIME)>(get_api(
		_hash, "kernel32.dll", lenSeed, lenSeed));

	return temp_GetSystemTimeAsFileTime(lpSystemTimeAsFileTime);
}

SIZE_T hash_VirtualQuery(LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength)
{
	const auto lenSeed = 13;
	const auto _hash = MurmurHash2A("VirtualQuery", lenSeed, lenSeed);

	temp_VirtualQuery = static_cast<SIZE_T(WINAPI*)(LPCVOID,
		PMEMORY_BASIC_INFORMATION,
		SIZE_T)>(get_api(_hash, "kernel32.dll", lenSeed, lenSeed));

	return temp_VirtualQuery(lpAddress,
		lpBuffer,
		dwLength);
}

BOOL hash_ReadProcessQMemory(HANDLE hProcess,
                             LPCVOID lpBaseAddress,
                             LPVOID lpBuffer,
                             SIZE_T nSize,
                             SIZE_T* lpNumberOfBytesRead)
{
	const auto lenSeed = 18;
	const auto _hash = MurmurHash2A("ReadProcessMemory", lenSeed, lenSeed);

	temp_ReadProcessMemory = static_cast<BOOL(WINAPI*)(HANDLE,
	                                                   LPCVOID,
	                                                   LPVOID,
	                                                   SIZE_T,
	                                                   SIZE_T*)>(get_api(_hash, "kernel32.dll", lenSeed, lenSeed));

	return temp_ReadProcessMemory(hProcess,
	                              lpBaseAddress,
	                              lpBuffer,
	                              nSize,
	                              lpNumberOfBytesRead);
}

/*DECLSPEC_ALLOCATOR*/
HLOCAL hash_LocalAlloc(UINT uFlags,
                       SIZE_T uBytes)
{
	const auto lenSeed = 11;
	const auto _hash = MurmurHash2A("LocalAlloc", lenSeed, lenSeed);

	temp_LocalAlloc = static_cast<HLOCAL(WINAPI*)(UINT,
	                                              SIZE_T)>(get_api(_hash, "kernel32.dll", lenSeed, lenSeed));

	return temp_LocalAlloc(uFlags,
	                       uBytes);
}

HLOCAL hash_LocalFree(_Frees_ptr_opt_ HLOCAL hMem)
{
	const auto lenSeed = 10;
	const auto _hash = MurmurHash2A("LocalFree", lenSeed, lenSeed);

	temp_LocalFree = static_cast<HLOCAL(WINAPI*)(_Frees_ptr_opt_ HLOCAL)>(get_api(
		_hash, "kernel32.dll", lenSeed, lenSeed));

	return temp_LocalFree(hMem);
}

BOOL hash_GlobalMemoryStatusEx(LPMEMORYSTATUSEX lpBuffer)
{
	const auto lenSeed = 21;
	const auto _hash = MurmurHash2A("GlobalMemoryStatusEx", lenSeed, lenSeed);

	temp_GlobalMemoryStatusEx = static_cast<BOOL(WINAPI*)(LPMEMORYSTATUSEX)>(get_api(
		_hash, "kernel32.dll", lenSeed, lenSeed));

	return temp_GlobalMemoryStatusEx(lpBuffer);
}

BOOL hash_WriteProcessMemory(HANDLE hProcess,
                             LPVOID lpBaseAddress,
                             LPCVOID lpBuffer,
                             SIZE_T nSize,
                             SIZE_T* lpNumberOfBytesWritten)
{
	const auto lenSeed = 19;
	const auto _hash = MurmurHash2A("WriteProcessMemory", lenSeed, lenSeed);

	temp_WriteProcessMemory = static_cast<BOOL(WINAPI*)(HANDLE,
	                                                    LPVOID,
	                                                    LPCVOID,
	                                                    SIZE_T,
	                                                    SIZE_T*)>(get_api(_hash, "kernel32.dll", lenSeed, lenSeed));

	return temp_WriteProcessMemory(hProcess,
	                               lpBaseAddress,
	                               lpBuffer,
	                               nSize,
	                               lpNumberOfBytesWritten);
}

SIZE_T hash_LocalSize(HLOCAL hMem)
{
	const auto lenSeed = 10;
	const auto _hash = MurmurHash2A("LocalSize", lenSeed, lenSeed);

	temp_LocalSize = static_cast<SIZE_T(WINAPI*)(HLOCAL)>(get_api(_hash, "kernel32.dll", lenSeed, lenSeed));

	return temp_LocalSize(hMem);
}


LPVOID hash_HeapAlloc(HANDLE hHeap,
                      DWORD dwFlags,
                      SIZE_T dwBytes)
{
	const auto lenSeed = 10;
	const auto _hash = MurmurHash2A("HeapAlloc", lenSeed, lenSeed);

	temp_HeapAlloc = static_cast<LPVOID(WINAPI*)(HANDLE,
	                                             DWORD,
	                                             SIZE_T)>(get_api(_hash, "kernel32.dll", lenSeed, lenSeed));

	return temp_HeapAlloc(hHeap,
	                      dwFlags,
	                      dwBytes);
}

HANDLE hash_GetProcessHeap()
{
	const auto lenSeed = 15;
	const auto _hash = MurmurHash2A("GetProcessHeap", lenSeed, lenSeed);

	temp_GetProcessHeap = static_cast<HANDLE(WINAPI*)()>(get_api(_hash, "kernel32.dll", lenSeed, lenSeed));

	return temp_GetProcessHeap();
}

BOOL hash_HeapFree(HANDLE hHeap,
                   DWORD dwFlags,
                   _Frees_ptr_opt_ LPVOID lpMem)
{
	const auto lenSeed = 9;
	const auto _hash = MurmurHash2A("HeapFree", lenSeed, lenSeed);

	temp_HeapFree = static_cast<BOOL(WINAPI*)(HANDLE,
	                                          DWORD,
	                                          _Frees_ptr_opt_ LPVOID)>(get_api(_hash, "kernel32.dll", lenSeed, lenSeed)
	);

	return temp_HeapFree(hHeap,
	                     dwFlags,
	                     lpMem);
}

BOOL hash_IsBadReadPtr(const VOID* lp,
                       UINT_PTR ucb)
{
	const auto lenSeed = 13;
	const auto _hash = MurmurHash2A("IsBadReadPtr", lenSeed, lenSeed);

	temp_IsBadReadPtr = static_cast<BOOL(WINAPI*)(const VOID*,
	                                              UINT_PTR)>(get_api(_hash, "kernel32.dll", lenSeed, lenSeed));

	return temp_IsBadReadPtr(lp,
	                         ucb);
}

HANDLE hash_GetCurrentProcess()
{
	const auto lenSeed = 18;
	const auto _hash = MurmurHash2A("GetCurrentProcess", lenSeed, lenSeed);

	temp_GetCurrentProcess = static_cast<HANDLE(WINAPI*)()>(get_api(_hash, "kernel32.dll", lenSeed, lenSeed));

	return temp_GetCurrentProcess();
}

BOOL hash_GetThreadContext(HANDLE hThread,
                           LPCONTEXT lpContext)
{
	const auto lenSeed = 17;
	const auto _hash = MurmurHash2A("GetThreadContext", lenSeed, lenSeed);

	temp_GetThreadContext = static_cast<BOOL(WINAPI*)(HANDLE,
	                                                  LPCONTEXT)>(get_api(_hash, "kernel32.dll", lenSeed, lenSeed));

	return temp_GetThreadContext(hThread,
	                             lpContext);
}

void hash_Sleep(DWORD dwMilliseconds)
{
	const auto lenSeed = 6;
	const auto _hash = MurmurHash2A("Sleep", lenSeed, lenSeed);

	temp_Sleep = static_cast<void(WINAPI*)(DWORD)>(get_api(_hash, "kernel32.dll", lenSeed, lenSeed));

	return temp_Sleep(dwMilliseconds);
}

DWORD hash_GetCurrentProcessId()
{
	const auto lenSeed = 20;
	const auto _hash = MurmurHash2A("GetCurrentProcessId", lenSeed, lenSeed);

	temp_GetCurrentProcessId = static_cast<DWORD(WINAPI*)()>(get_api(_hash, "kernel32.dll", lenSeed, lenSeed));

	return temp_GetCurrentProcessId();
}

HANDLE hash_OpenProcess(DWORD dwDesiredAccess,
                        BOOL bInheritHandle,
                        DWORD dwProcessId)
{
	const auto lenSeed = 12;
	const auto _hash = MurmurHash2A("OpenProcess", lenSeed, lenSeed);

	temp_OpenProcess = static_cast<HANDLE(WINAPI*)(DWORD,
	                                               BOOL,
	                                               DWORD)>(get_api(_hash, "kernel32.dll", lenSeed, lenSeed));

	return temp_OpenProcess(dwDesiredAccess,
	                        bInheritHandle,
	                        dwProcessId);
}

DWORD hash_GetEnvironmentVariableW(LPCWSTR lpName,
                                   LPWSTR lpBuffer,
                                   DWORD nSize)
{
	const auto lenSeed = 24;
	const auto _hash = MurmurHash2A("GetEnvironmentVariableW", lenSeed, lenSeed);

	temp_GetEnvironmentVariableW = static_cast<DWORD(WINAPI*)(LPCWSTR,
	                                                          LPWSTR,
	                                                          DWORD)>(get_api(_hash, "kernel32.dll", lenSeed, lenSeed));

	return temp_GetEnvironmentVariableW(lpName,
	                                    lpBuffer,
	                                    nSize);
}

HANDLE hash_CreateToolhelp32Snapshot(DWORD dwFlags,
                                     DWORD th32ProcessID)
{
	const auto lenSeed = 25;
	const auto _hash = MurmurHash2A("CreateToolhelp32Snapshot", lenSeed, lenSeed);

	temp_CreateToolhelp32Snapshot = static_cast<HANDLE(WINAPI*)(DWORD,
	                                                            DWORD)>(get_api(
		_hash, "kernel32.dll", lenSeed, lenSeed));

	return temp_CreateToolhelp32Snapshot(dwFlags,
	                                     th32ProcessID);
}

BOOL hash_Module32FirstW(HANDLE hSnapshot, LPMODULEENTRY32W lpme)
{
	const auto lenSeed = 15;
	const auto _hash = MurmurHash2A("Module32FirstW", lenSeed, lenSeed);

	temp_Module32FirstW = static_cast<BOOL(WINAPI*)(HANDLE, LPMODULEENTRY32W)>(get_api(
		_hash, "kernel32.dll", lenSeed, lenSeed));

	return temp_Module32FirstW(hSnapshot, lpme);
}

BOOL hash_Module32NextW(HANDLE hSnapshot,
                        LPMODULEENTRY32W lpme)
{
	const auto lenSeed = 14;
	const auto _hash = MurmurHash2A("Module32NextW", lenSeed, lenSeed);

	temp_Module32NextW = static_cast<BOOL(WINAPI*)(HANDLE,
	                                               LPMODULEENTRY32W)>(get_api(_hash, "kernel32.dll", lenSeed, lenSeed));

	return temp_Module32NextW(hSnapshot,
	                          lpme);
}

BOOL hash_SwitchToThread()
{
	const auto lenSeed = 15;
	const auto _hash = MurmurHash2A("SwitchToThread", lenSeed, lenSeed);

	temp_SwitchToThread = static_cast<BOOL(WINAPI*)()>(get_api(_hash, "kernel32.dll", lenSeed, lenSeed));

	return temp_SwitchToThread();
}

BOOL hash_IsWow64Process(HANDLE hProcess,
                         PBOOL Wow64Process)
{
	const auto lenSeed = 15;
	const auto _hash = MurmurHash2A("IsWow64Process", lenSeed, lenSeed);

	temp_IsWow64Process = static_cast<BOOL(WINAPI*)(HANDLE,
	                                                PBOOL)>(get_api(_hash, "kernel32.dll", lenSeed, lenSeed));

	return temp_IsWow64Process(hProcess,
	                           Wow64Process);
}

HANDLE hash_CreateRemoteThread(HANDLE hProcess,
                               LPSECURITY_ATTRIBUTES lpThreadAttributes,
                               SIZE_T dwStackSize,
                               LPTHREAD_START_ROUTINE lpStartAddress,
                               LPVOID lpParameter,
                               DWORD dwCreationFlags,
                               LPDWORD lpThreadId)
{
	const auto lenSeed = 19;
	const auto _hash = MurmurHash2A("CreateRemoteThread", lenSeed, lenSeed);

	temp_CreateRemoteThread = static_cast<HANDLE(WINAPI*)(HANDLE,
	                                                      LPSECURITY_ATTRIBUTES,
	                                                      SIZE_T,
	                                                      LPTHREAD_START_ROUTINE,
	                                                      LPVOID,
	                                                      DWORD,
	                                                      LPDWORD)>(get_api(_hash, "kernel32.dll", lenSeed, lenSeed));

	return temp_CreateRemoteThread(hProcess,
	                               lpThreadAttributes,
	                               dwStackSize,
	                               lpStartAddress,
	                               lpParameter,
	                               dwCreationFlags,
	                               lpThreadId);
}

BOOL hash_Thread32First(HANDLE hSnapshot,
                        LPTHREADENTRY32 lpte)
{
	const auto lenSeed = 14;
	const auto _hash = MurmurHash2A("Thread32First", lenSeed, lenSeed);

	temp_Thread32First = static_cast<BOOL(WINAPI*)(HANDLE,
	                                               LPTHREADENTRY32)>(get_api(_hash, "kernel32.dll", lenSeed, lenSeed));

	return temp_Thread32First(hSnapshot,
	                          lpte);
}

HANDLE hash_OpenThread(DWORD dwDesiredAccess,
                       BOOL bInheritHandle,
                       DWORD dwThreadId)
{
	const auto lenSeed = 11;
	const auto _hash = MurmurHash2A("OpenThread", lenSeed, lenSeed);

	temp_OpenThread = static_cast<HANDLE(WINAPI*)(DWORD,
	                                              BOOL,
	                                              DWORD)>(get_api(_hash, "kernel32.dll", lenSeed, lenSeed));

	return temp_OpenThread(dwDesiredAccess,
	                       bInheritHandle,
	                       dwThreadId);
}

BOOL hash_Thread32Next(HANDLE hSnapshot,
                       LPTHREADENTRY32 lpte)
{
	const auto lenSeed = 13;
	const auto _hash = MurmurHash2A("Thread32Next", lenSeed, lenSeed);

	temp_Thread32Next = static_cast<BOOL(WINAPI*)(HANDLE,
	                                              LPTHREADENTRY32)>(get_api(_hash, "kernel32.dll", lenSeed, lenSeed));

	return temp_Thread32Next(hSnapshot,
	                         lpte);
}

BOOL hash_Process32FirstW(HANDLE hSnapshot,
                          LPTHREADENTRY32 lpte)
{
	const auto lenSeed = 16;
	const auto _hash = MurmurHash2A("Process32FirstW", lenSeed, lenSeed);

	temp_Process32FirstW = static_cast<BOOL(WINAPI*)(HANDLE,
	                                                 LPTHREADENTRY32)>(get_api(_hash, "kernel32.dll", lenSeed, lenSeed)
	);

	return temp_Process32FirstW(hSnapshot,
	                            lpte);
}

BOOL hash_Process32NextW(HANDLE hSnapshot,
                         LPTHREADENTRY32 lpte)
{
	const auto lenSeed = 15;
	const auto _hash = MurmurHash2A("Process32NextW", lenSeed, lenSeed);

	temp_Process32NextW = static_cast<BOOL(WINAPI*)(HANDLE,
	                                                LPTHREADENTRY32)>(get_api(_hash, "kernel32.dll", lenSeed, lenSeed));

	return temp_Process32NextW(hSnapshot,
	                           lpte);
}

DWORD hash_GetCurrentThreadId()
{
	const auto lenSeed = 19;
	const auto _hash = MurmurHash2A("GetCurrentThreadId", lenSeed, lenSeed);

	temp_GetCurrentThreadId = static_cast<DWORD(WINAPI*)()>(get_api(_hash, "kernel32.dll", lenSeed, lenSeed));

	return temp_GetCurrentThreadId();
}

BOOL hash_TerminateProcess(HANDLE hProcess,
                           UINT uExitCode)
{
	const auto lenSeed = 17;
	const auto _hash = MurmurHash2A("TerminateProcess", lenSeed, lenSeed);

	temp_TerminateProcess = static_cast<BOOL(WINAPI*)(HANDLE,
	                                                  UINT)>(get_api(_hash, "kernel32.dll", lenSeed, lenSeed));

	return temp_TerminateProcess(hProcess,
	                             uExitCode);
}

BOOL hash_CloseHandle(HANDLE hObject)
{
	const auto lenSeed = 12;
	const auto _hash = MurmurHash2A("CloseHandle", lenSeed, lenSeed);

	temp_CloseHandle = static_cast<BOOL(WINAPI*)(HANDLE)>(get_api(_hash, "kernel32.dll", lenSeed, lenSeed));

	return temp_CloseHandle(hObject);
}

BOOL hash_DuplicateHandle(HANDLE hSourceProcessHandle,
                          HANDLE hSourceHandle,
                          HANDLE hTargetProcessHandle,
                          LPHANDLE lpTargetHandle,
                          DWORD dwDesiredAccess,
                          BOOL bInheritHandle,
                          DWORD dwOptions)
{
	const auto lenSeed = 16;
	const auto _hash = MurmurHash2A("DuplicateHandle", lenSeed, lenSeed);

	temp_DuplicateHandle = static_cast<BOOL(WINAPI*)(HANDLE,
	                                                 HANDLE,
	                                                 HANDLE,
	                                                 LPHANDLE,
	                                                 DWORD,
	                                                 BOOL,
	                                                 DWORD)>(get_api(_hash, "kernel32.dll", lenSeed, lenSeed));

	return temp_DuplicateHandle(hSourceProcessHandle,
	                            hSourceHandle,
	                            hTargetProcessHandle,
	                            lpTargetHandle,
	                            dwDesiredAccess,
	                            bInheritHandle,
	                            dwOptions);
}

BOOL hash_SetHandleInformation(HANDLE hObject,
                               DWORD dwMask,
                               DWORD dwFlags)
{
	const auto lenSeed = 21;
	const auto _hash = MurmurHash2A("SetHandleInformation", lenSeed, lenSeed);

	temp_SetHandleInformation = static_cast<BOOL(WINAPI*)(HANDLE,
	                                                      DWORD,
	                                                      DWORD)>(get_api(_hash, "kernel32.dll", lenSeed, lenSeed));

	return temp_SetHandleInformation(hObject,
	                                 dwMask,
	                                 dwFlags);
}

BOOL hash_DeviceIoControl(HANDLE hDevice,
                          DWORD dwIoControlCode,
                          LPVOID lpInBuffer,
                          DWORD nInBufferSize,
                          LPVOID lpOutBuffer,
                          DWORD nOutBufferSize,
                          LPDWORD lpBytesReturned,
                          LPOVERLAPPED lpOverlapped)
{
	const auto lenSeed = 16;
	const auto _hash = MurmurHash2A("DeviceIoControl", lenSeed, lenSeed);

	temp_DeviceIoControl = static_cast<BOOL(WINAPI*)(HANDLE,
	                                                 DWORD,
	                                                 LPVOID,
	                                                 DWORD,
	                                                 LPVOID,
	                                                 DWORD,
	                                                 LPDWORD,
	                                                 LPOVERLAPPED)>(get_api(_hash, "kernel32.dll", lenSeed, lenSeed));

	return temp_DeviceIoControl(hDevice,
	                            dwIoControlCode,
	                            lpInBuffer,
	                            nInBufferSize,
	                            lpOutBuffer,
	                            nOutBufferSize,
	                            lpBytesReturned,
	                            lpOverlapped);
}

int hash_lstrlenW(LPCWSTR lpString)
{
	const auto lenSeed = 9;
	const auto _hash = MurmurHash2A("lstrlenW", lenSeed, lenSeed);

	temp_lstrlenW = static_cast<int(WINAPI*)(LPCWSTR)>(get_api(_hash, "kernel32.dll", lenSeed, lenSeed));

	return temp_lstrlenW(lpString);
}


int hash_MultiByteToWideChar(UINT CodePage,
                             DWORD dwFlags,
                             _In_NLS_string_(cbMultiByte)LPCCH lpMultiByteStr,
                             int cbMultiByte,
                             LPWSTR lpWideCharStr,
                             int cchWideChar)
{
	const auto lenSeed = 20;
	const auto _hash = MurmurHash2A("MultiByteToWideChar", lenSeed, lenSeed);

	temp_MultiByteToWideChar = static_cast<int(WINAPI*)(UINT,
	                                                    DWORD,
	                                                    _In_NLS_string_(cbMultiByte)LPCCH,
	                                                    int,
	                                                    LPWSTR,
	                                                    int)>(get_api(_hash, "kernel32.dll", lenSeed, lenSeed));

	return temp_MultiByteToWideChar(CodePage,
	                                dwFlags,
	                                lpMultiByteStr,
	                                cbMultiByte,
	                                lpWideCharStr,
	                                cchWideChar);
}

HANDLE hash_CreateTimerQueue()
{
	const auto lenSeed = 17;
	const auto _hash = MurmurHash2A("CreateTimerQueue", lenSeed, lenSeed);

	temp_CreateTimerQueue = static_cast<HANDLE(WINAPI*)()>(get_api(_hash, "kernel32.dll", lenSeed, lenSeed));

	return temp_CreateTimerQueue();
}

BOOL hash_DeleteTimerQueueEx(HANDLE TimerQueue,
                             HANDLE CompletionEvent)
{
	const auto lenSeed = 19;
	const auto _hash = MurmurHash2A("DeleteTimerQueueEx", lenSeed, lenSeed);

	temp_DeleteTimerQueueEx = static_cast<BOOL(WINAPI*)(HANDLE,
	                                                    HANDLE)>(get_api(_hash, "kernel32.dll", lenSeed, lenSeed));

	return temp_DeleteTimerQueueEx(TimerQueue, CompletionEvent);
}

BOOL hash_CheckRemoteDebuggerPresent(HANDLE hProcess,
                                     PBOOL pbDebuggerPresent)
{
	const auto lenSeed = 27;
	const auto _hash = MurmurHash2A("CheckRemoteDebuggerPresent", lenSeed, lenSeed);

	temp_CheckRemoteDebuggerPresent = static_cast<BOOL(WINAPI*)(HANDLE,
	                                                            PBOOL)>(get_api(
		_hash, "kernel32.dll", lenSeed, lenSeed));

	return temp_CheckRemoteDebuggerPresent(hProcess,
	                                       pbDebuggerPresent);
}

LONG hash_UnhandledExceptionFilter(_EXCEPTION_POINTERS* ExceptionInfo)
{
	const auto lenSeed = 25;
	const auto _hash = MurmurHash2A("UnhandledExceptionFilter", lenSeed, lenSeed);

	temp_UnhandledExceptionFilter = static_cast<LONG(WINAPI*)(_EXCEPTION_POINTERS*)>(get_api(
		_hash, "kernel32.dll", lenSeed, lenSeed));

	return temp_UnhandledExceptionFilter(ExceptionInfo);
}

LPTOP_LEVEL_EXCEPTION_FILTER hash_SetUnhandledExceptionFilter(LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter)
{
	const auto lenSeed = 28;
	const auto _hash = MurmurHash2A("SetUnhandledExceptionFilter", lenSeed, lenSeed);

	temp_SetUnhandledExceptionFilter = static_cast<LPTOP_LEVEL_EXCEPTION_FILTER(WINAPI*)(LPTOP_LEVEL_EXCEPTION_FILTER)>(
		get_api(
			_hash, "kernel32.dll", lenSeed, lenSeed));

	return temp_SetUnhandledExceptionFilter(lpTopLevelExceptionFilter);
}

ULONG hash_RemoveVectoredExceptionHandler(PVOID Handle)
{
	const auto lenSeed = 31;
	const auto _hash = MurmurHash2A("RemoveVectoredExceptionHandler", lenSeed, lenSeed);

	temp_RemoveVectoredExceptionHandler = static_cast<ULONG(WINAPI*)(PVOID)>(get_api(
		_hash, "kernel32.dll", lenSeed, lenSeed));

	return temp_RemoveVectoredExceptionHandler(Handle);
}
//
//int hash_lstrcmpiW(LPCWSTR lpString1, LPCWSTR lpString2)
//{
//	const auto lenSeed = 10;
//	const auto _hash = MurmurHash2A("lstrcmpiW", lenSeed, lenSeed);
//
//	temp_lstrcmpiW = static_cast<int(WINAPI*)(LPCWSTR,
//		LPCWSTR)>(get_api(
//		_hash, "kernel32.dll", lenSeed, lenSeed));
//
//	return temp_lstrcmpiW(lpString1,
//		lpString2);
//}

//int hash_WideCharToMultiByte(UINT                               CodePage,
//	DWORD                              dwFlags,
//	_In_NLS_string_(cchWideChar)LPCWCH lpWideCharStr,
//	int                                cchWideChar,
//	LPSTR                              lpMultiByteStr,
//	int                                cbMultiByte,
//	LPCCH                              lpDefaultChar,
//	LPBOOL                             lpUsedDefaultChar)
//{
//	const auto lenSeed = 20;
//	const auto _hash = MurmurHash2A("WideCharToMultiByte", lenSeed, lenSeed);
//
//	temp_WideCharToMultiByte = static_cast<int(WINAPI*)(UINT                              ,
//		DWORD                              ,
//		_In_NLS_string_(cchWideChar)LPCWCH ,
//		int                                ,
//		LPSTR                              ,
//		int                                ,
//		LPCCH                              ,
//		LPBOOL                             )>(get_api(
//		_hash, "kernel32.dll", lenSeed, lenSeed));
//
//	return temp_WideCharToMultiByte(                               CodePage,
//		                              dwFlags,
//		 lpWideCharStr,
//		                                cchWideChar,
//		                              lpMultiByteStr,
//		                                cbMultiByte,
//		                              lpDefaultChar,
//		                             lpUsedDefaultChar);
//}
