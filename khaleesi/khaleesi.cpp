// al-khaser.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"


int main()
{
	/* enable functions */
	BOOL	ENABLE_SCYLLAHIDE_DETECTOR = TRUE;
	BOOL	ENABLE_DEBUG_CHECKS = TRUE;
	BOOL	ENABLE_ANALYSIS_TOOLS_CHECK = FALSE;

	API::Init();
	//API::PrintAvailabilityReport();

	if (ENABLE_SCYLLAHIDE_DETECTOR) {
		/*ntdll*/
		ntdll_unhooking();
		/*kernel32 / kernelbase*/
		kernelbase_unhooking();

		// TitanHide detection
		if (TitanHideCheck()) {
			print_category(TEXT("[TitanHide] Your are under testsign or debug mode."));
		}  else {
			// if not find TitanHide
		}

	}

	if (ENABLE_DEBUG_CHECKS) PageExceptionInitialEnum();

	/* Debugger Detection */
	if (ENABLE_DEBUG_CHECKS) {
		print_category(TEXT("Debugger Detection"));
		//exec_check(&XAD, TEXT("Checking XAntiDebug "));
		exec_check(&IsDebuggerPresentAPI, TEXT("Checking IsDebuggerPresent API "));
		exec_check(&IsDebuggerPresentPEB, TEXT("Checking PEB.BeingDebugged "));
		exec_check(&CheckRemoteDebuggerPresentAPI, TEXT("Checking CheckRemoteDebuggerPresent API "));
		exec_check(&NtGlobalFlag, TEXT("Checking PEB.NtGlobalFlag "));
		exec_check(&HeapFlags, TEXT("Checking ProcessHeap.Flags "));
		exec_check(&HeapForceFlags, TEXT("Checking ProcessHeap.ForceFlags "));
		exec_check(&NtQueryInformationProcess_ProcessDebugPort, TEXT("Checking NtQueryInformationProcess with ProcessDebugPort "));
		exec_check(&NtQueryInformationProcess_ProcessDebugFlags, TEXT("Checking NtQueryInformationProcess with ProcessDebugFlags "));
		exec_check(&NtQueryInformationProcess_ProcessDebugObject, TEXT("Checking NtQueryInformationProcess with ProcessDebugObject "));
		exec_check(&WUDF_IsAnyDebuggerPresent, TEXT("Checking WudfIsAnyDebuggerPresent API "));
		exec_check(&WUDF_IsKernelDebuggerPresent, TEXT("Checking WudfIsKernelDebuggerPresent API "));
		exec_check(&WUDF_IsUserDebuggerPresent, TEXT("Checking WudfIsUserDebuggerPresent API "));
		exec_check(&NtSetInformationThread_ThreadHideFromDebugger, TEXT("Checking NtSetInformationThread with ThreadHideFromDebugger "));
		exec_check(&CloseHandle_InvalideHandle, TEXT("Checking CloseHandle with an invalide handle "));
		exec_check(&NtClose_InvalideHandle, TEXT("Checking NtClose with an invalide handle "));
		exec_check(&UnhandledExcepFilterTest, TEXT("Checking UnhandledExcepFilterTest "));
		exec_check(&OutputDebugStringAPI, TEXT("Checking OutputDebugString "));
		exec_check(&HardwareBreakpoints, TEXT("Checking Hardware Breakpoints "));
		//exec_check(&SoftwareBreakpoints, TEXT("Checking Software Breakpoints "));
		exec_check(&Interrupt_0x2d, TEXT("Checking Interupt 0x2d "));
		exec_check(&Interrupt_3, TEXT("Checking Interupt 1 "));
		exec_check(&MemoryBreakpoints_PageGuard, TEXT("Checking Memory Breakpoints PAGE GUARD "));
		exec_check(&IsParentExplorerExe, TEXT("Checking If Parent Process is explorer.exe "));
		exec_check(&CanOpenCsrss, TEXT("Checking SeDebugPrivilege "));
		exec_check(&NtQueryObject_ObjectTypeInformation, TEXT("Checking NtQueryObject with ObjectTypeInformation "));
		exec_check(&NtQueryObject_ObjectAllTypesInformation, TEXT("Checking NtQueryObject with ObjectAllTypesInformation "));
		exec_check(&NtYieldExecutionAPI, TEXT("Checking NtYieldExecution "));
		exec_check(&SetHandleInformation_ProtectedHandle, TEXT("Checking CloseHandle protected handle trick  "));
		exec_check(&NtQuerySystemInformation_SystemKernelDebuggerInformation, TEXT("Checking NtQuerySystemInformation with SystemKernelDebuggerInformation  "));
		exec_check(&SharedUserData_KernelDebugger, TEXT("Checking SharedUserData->KdDebuggerEnabled  "));
		exec_check(&ProcessJob, TEXT("Checking if process is in a job  "));
		exec_check(&VirtualAlloc_WriteWatch_BufferOnly, TEXT("Checking VirtualAlloc write watch (buffer only) "));
		exec_check(&VirtualAlloc_WriteWatch_APICalls, TEXT("Checking VirtualAlloc write watch (API calls) "));
		exec_check(&VirtualAlloc_WriteWatch_IsDebuggerPresent, TEXT("Checking VirtualAlloc write watch (IsDebuggerPresent) "));
		exec_check(&VirtualAlloc_WriteWatch_CodeWrite, TEXT("Checking VirtualAlloc write watch (code write) "));
		exec_check(&PageExceptionBreakpointCheck, TEXT("Checking for page exception breakpoints "));
		exec_check(&ModuleBoundsHookCheck, TEXT("Checking for API hooks outside module bounds "));
	}

	/* Malware analysis tools */
	if (ENABLE_ANALYSIS_TOOLS_CHECK) {
		print_category(TEXT("Analysis-tools"));
		analysis_tools_process();
	}

	print_category(TEXT("END"));

	getchar();

	return 0;
}

