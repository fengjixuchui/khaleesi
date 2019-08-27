#pragma once
#include <Windows.h>
#include <iostream>

#define CODEINTEGRITY_OPTION_TESTSIGN 0x00000002
#define CODEINTEGRITY_OPTION_DEBUGMODE_ENABLED 0x00000080

#define SystemCodeIntegrityInformation 0x67

//typedef struct _SYSTEM_CODEINTEGRITY_INFORMATION {
//	ULONG Length;
//	ULONG CodeIntegrityOptions;
//} SYSTEM_CODEINTEGRITY_INFORMATION;

typedef NTSTATUS(__stdcall* t_NtQuerySystemInformation)(
	IN ULONG,
	OUT PVOID,
	IN ULONG,
	OUT PULONG
	);


bool TitanHideCheck();
