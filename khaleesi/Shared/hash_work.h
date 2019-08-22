#pragma once

/*
Здесь размещаются прототипы функций, которые из хеша имени функции запустит реальныю функцию
*/

#include <windows.h>
#include <TlHelp32.h>
#include <winnt.h>

HANDLE                         hash_CreateFileA(__in LPCSTR file_name, __in DWORD access, __in DWORD share_mode,
                        __in LPSECURITY_ATTRIBUTES security, __in DWORD creation_disposition, __in DWORD flags,
                        __in HANDLE template_file);
BOOL                           hash_VirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
LPVOID                         hash_VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
BOOL                           hash_VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
LPVOID                         hash_VirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
BOOL                           hash_VirtualFreeEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
DWORD                          hash_QueryDosDeviceW(LPCWSTR lpDeviceName, LPWSTR lpTargetPath, DWORD ucchMax);
BOOL                           hash_GetDiskFreeSpaceExW(LPCWSTR lpDirectoryName, PULARGE_INTEGER lpFreeBytesAvailableToCaller,
                              PULARGE_INTEGER lpTotalNumberOfBytes, PULARGE_INTEGER lpTotalNumberOfFreeBytes);
HMODULE                        hash_LoadLibraryW(LPCWSTR lpLibFileName);
HMODULE hash_LoadLibraryA(LPCSTR lpLibFileName);
BOOL                           hash_GetModuleHandleExW(DWORD dwFlags, LPCWSTR lpModuleName, HMODULE* phModule);
DWORD                          hash_GetModuleFileNameW(HMODULE hModule, LPWSTR lpFilename, DWORD nSize);
HMODULE                        hash_GetModuleHandleA(LPCSTR lpModuleName);
HMODULE                        hash_GetModuleHandleW(LPCWSTR lpModuleName);
FARPROC                        hash_GetProcAddress(HMODULE hModule, LPCSTR lpProcName);
HANDLE                         hash_GetStdHandle(_In_ DWORD nStdHandle);
BOOL                           hash_GetConsoleScreenBufferInfo(_In_ HANDLE hConsoleOutput,
                                     _Out_ PCONSOLE_SCREEN_BUFFER_INFO lpConsoleScreenBufferInfo);
BOOL                           hash_SetConsoleTextAttribute(_In_ HANDLE hConsoleOutput, _In_ WORD wAttributes);
DWORD                          hash_GetTickCount();
BOOL                           hash_VerifyVersionInfoW(LPOSVERSIONINFOEXA lpVersionInformation, DWORD dwTypeMask, DWORDLONG dwlConditionMask);
UINT                           hash_GetSystemWindowsDirectoryW(LPWSTR lpBuffer, UINT uSize);
UINT                           hash_GetWindowsDirectoryW(LPWSTR lpBuffer, UINT uSize);
UINT                           hash_GetSystemDirectoryW(LPWSTR lpBuffer, UINT uSize);
UINT                           hash_GetSystemDirectoryA(LPSTR lpBuffer, UINT uSize);
void                           hash_GetSystemInfo(LPSYSTEM_INFO lpSystemInfo);
DWORD                          hash_ExpandEnvironmentStringsW(LPCWSTR lpSrc, LPWSTR lpDst, DWORD nSize);
BOOL                           hash_QueryPerformanceCounter(LARGE_INTEGER* lpPerformanceCount);
BOOL                           hash_IsProcessorFeaturePresent(DWORD ProcessorFeature);
PVOID                          hash_AddVectoredExceptionHandler(ULONG First, PVECTORED_EXCEPTION_HANDLER Handler);
void                           hash_SetLastError(DWORD dwErrCode);
_Post_equals_last_error_ DWORD hash_GetLastError();
void                           hash_OutputDebugStringW(LPCWSTR lpOutputString);
DWORD                          hash_FormatMessageW(DWORD dwFlags, LPCVOID lpSource, DWORD dwMessageId, DWORD dwLanguageId, LPWSTR lpBuffer,
                          DWORD nSize, va_list* Arguments);
HANDLE                         hash_CreateMutexW(LPSECURITY_ATTRIBUTES lpMutexAttributes, BOOL bInitialOwner, LPCWSTR lpName);
HANDLE                         hash_CreateEventW(LPSECURITY_ATTRIBUTES lpEventAttributes, BOOL bManualReset, BOOL bInitialState,
                         LPCWSTR lpName);
BOOL                           hash_SetEvent(HANDLE hEvent);
DWORD                          hash_WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds);
DWORD                          hash_QueueUserAPC(PAPCFUNC pfnAPC, HANDLE hThread, ULONG_PTR dwData);
HANDLE                         hash_CreateThread(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize,
                         LPTHREAD_START_ROUTINE lpStartAddress, __drv_aliasesMem LPVOID lpParameter,
                         DWORD dwCreationFlags, LPDWORD lpThreadId);
HANDLE                         hash_CreateWaitableTimerW(LPSECURITY_ATTRIBUTES lpTimerAttributes, BOOL bManualReset, LPCWSTR lpTimerName);
BOOL                           hash_SetWaitableTimer(HANDLE hTimer, const LARGE_INTEGER* lpDueTime, LONG lPeriod,
                           PTIMERAPCROUTINE pfnCompletionRoutine, LPVOID lpArgToCompletionRoutine, BOOL fResume);
BOOL                           hash_CancelWaitableTimer(HANDLE hTimer);
BOOL                           hash_CreateTimerQueueTimer(PHANDLE phNewTimer, HANDLE TimerQueue, WAITORTIMERCALLBACK Callback, PVOID DueTime,
                                DWORD Period, DWORD Flags, ULONG Parameter);
DWORD                          hash_SetFilePointer(HANDLE hFile, LONG lDistanceToMove, PLONG lpDistanceToMoveHigh, DWORD dwMoveMethod);
BOOL                           hash_ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead,
                   LPOVERLAPPED lpOverlapped);
HANDLE                         hash_CreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
                        LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition,
                        DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
DWORD                          hash_GetFullPathNameW(LPCWSTR lpFileName, DWORD nBufferLength, LPWSTR lpBuffer, LPWSTR* lpFilePart);
DWORD                          hash_GetFileAttributesW(LPCWSTR lpFileName);
void                           hash_GetSystemTimeAsFileTime(LPFILETIME lpSystemTimeAsFileTime);

SIZE_T hash_VirtualQuery(LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength);

BOOL                           hash_ReadProcessQMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize,
                             SIZE_T* lpNumberOfBytesRead);
HLOCAL                         hash_LocalAlloc(UINT uFlags, SIZE_T uBytes);
HLOCAL                         hash_LocalFree(_Frees_ptr_opt_ HLOCAL hMem);
BOOL                           hash_GlobalMemoryStatusEx(LPMEMORYSTATUSEX lpBuffer);
BOOL                           hash_WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize,
                             SIZE_T* lpNumberOfBytesWritten);
SIZE_T                         hash_LocalSize(HLOCAL hMem);
LPVOID                         hash_HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
HANDLE                         hash_GetProcessHeap();
BOOL                           hash_HeapFree(HANDLE hHeap, DWORD dwFlags, _Frees_ptr_opt_ LPVOID lpMem);
BOOL                           hash_IsBadReadPtr(const VOID* lp, UINT_PTR ucb);
HANDLE                         hash_GetCurrentProcess();
BOOL                           hash_GetThreadContext(HANDLE hThread, LPCONTEXT lpContext);
void                           hash_Sleep(DWORD dwMilliseconds);
DWORD                          hash_GetCurrentProcessId();
HANDLE                         hash_OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
DWORD                          hash_GetEnvironmentVariableW(LPCWSTR lpName, LPWSTR lpBuffer, DWORD nSize);
HMODULE                        hash_LoadLibraryA_static(__in LPCSTR file_name);
HANDLE                         hash_CreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID);
BOOL                           hash_Module32FirstW(HANDLE hSnapshot, LPMODULEENTRY32W lpme);
BOOL                           hash_Module32NextW(HANDLE hSnapshot, LPMODULEENTRY32W lpme);
BOOL                           hash_SwitchToThread();
BOOL                           hash_IsWow64Process(HANDLE hProcess, PBOOL Wow64Process);
HANDLE                         hash_CreateRemoteThread(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize,
                               LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags,
                               LPDWORD lpThreadId);
BOOL                           hash_Thread32First(HANDLE hSnapshot, LPTHREADENTRY32 lpte);
HANDLE                         hash_OpenThread(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwThreadId);
BOOL                           hash_Thread32Next(HANDLE hSnapshot, LPTHREADENTRY32 lpte);
BOOL hash_Process32FirstW(HANDLE hSnapshot, LPPROCESSENTRY32W lppe);
BOOL hash_Process32NextW(HANDLE hSnapshot, LPPROCESSENTRY32W lpte);
DWORD                          hash_GetCurrentThreadId();
BOOL                           hash_TerminateProcess(HANDLE hProcess, UINT uExitCode);
BOOL                           hash_CloseHandle(HANDLE hObject);
BOOL                           hash_DuplicateHandle(HANDLE hSourceProcessHandle, HANDLE hSourceHandle, HANDLE hTargetProcessHandle,
                          LPHANDLE lpTargetHandle, DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwOptions);
BOOL                           hash_SetHandleInformation(HANDLE hObject, DWORD dwMask, DWORD dwFlags);
BOOL                           hash_DeviceIoControl(HANDLE hDevice, DWORD dwIoControlCode, LPVOID lpInBuffer, DWORD nInBufferSize,
                          LPVOID lpOutBuffer, DWORD nOutBufferSize, LPDWORD lpBytesReturned, LPOVERLAPPED lpOverlapped);
int                            hash_lstrlenW(LPCWSTR lpString);
int                            hash_MultiByteToWideChar(UINT CodePage, DWORD dwFlags, _In_NLS_string_(cbMultiByte)LPCCH lpMultiByteStr,
                             int cbMultiByte, LPWSTR lpWideCharStr, int cchWideChar);
BOOL                           hash_DeleteTimerQueueEx(HANDLE TimerQueue, HANDLE CompletionEvent);
BOOL                           hash_CheckRemoteDebuggerPresent(HANDLE hProcess, PBOOL pbDebuggerPresent);
LONG                           hash_UnhandledExceptionFilter(_EXCEPTION_POINTERS* ExceptionInfo);
LPTOP_LEVEL_EXCEPTION_FILTER   hash_SetUnhandledExceptionFilter(LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter);
ULONG                          hash_RemoveVectoredExceptionHandler(PVOID Handle);
BOOL hash_QueryInformationJobObject(HANDLE hJob, JOBOBJECTINFOCLASS JobObjectInformationClass, LPVOID lpJobObjectInformation, DWORD cbJobObjectInformationLength, LPDWORD lpReturnLength);
UINT hash_GetWriteWatch(DWORD dwFlags, PVOID lpBaseAddress, SIZE_T dwRegionSize, PVOID *lpAddresses, ULONG_PTR *lpdwCount, LPDWORD lpdwGranularity);
UINT hash_GlobalGetAtomNameW(ATOM nAtom, LPWSTR lpBuffer, int nSize);
BOOL hash_GetBinaryTypeW(LPCWSTR lpApplicationName, LPDWORD lpBinaryType);
BOOL hash_HeapQueryInformation(HANDLE HeapHandle, HEAP_INFORMATION_CLASS HeapInformationClass, PVOID HeapInformation, SIZE_T HeapInformationLength, PSIZE_T ReturnLength);
UINT hash_ResetWriteWatch(LPVOID lpBaseAddress, SIZE_T dwRegionSize);
BOOL hash_IsDebuggerPresent();
HANDLE hash_CreateTimerQueue();
//int hash_WideCharToMultiByte(UINT CodePage, DWORD dwFlags, _In_NLS_string_(cchWideChar)LPCWCH lpWideCharStr, int cchWideChar, LPSTR lpMultiByteStr, int cbMultiByte, LPCCH lpDefaultChar, LPBOOL lpUsedDefaultChar);
//int hash_lstrcmpiW(LPCWSTR lpString1, LPCWSTR lpString2);