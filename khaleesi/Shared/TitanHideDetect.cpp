#include "pch.h"
#include "TitanHideDetect.h"

bool TitanHideCheck()
{
	HMODULE ntdll = GetModuleHandleA("ntdll.dll");

	auto NtQuerySystemInformation = (t_NtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");

	SYSTEM_CODEINTEGRITY_INFORMATION cInfo;
	cInfo.Length = sizeof(cInfo);

	NtQuerySystemInformation(
		SystemCodeIntegrityInformation, // id получения информации о CodeIntegrity
		&cInfo,
		sizeof(cInfo),
		NULL
	);

	return (cInfo.CodeIntegrityOptions & CODEINTEGRITY_OPTION_TESTSIGN)
		|| (cInfo.CodeIntegrityOptions & CODEINTEGRITY_OPTION_DEBUGMODE_ENABLED);
}
