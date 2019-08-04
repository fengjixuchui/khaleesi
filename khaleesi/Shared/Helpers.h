#pragma once
#include <iostream>

inline void log()
{
}

template <typename First, typename ...Rest>
void log(First&& message, Rest&& ...rest)
{
	//std::cout << std::forward<First>(message);
	log(std::forward<Rest>(rest)...);
}

template <const hash_t::value_type ModuleHash>

inline PVOID _GetModuleHandle(void) noexcept
{
	const auto pPeb = (nt::PPEB)__readgsqword(0x60);

	if (pPeb)
	{
		for (auto pListEntry = pPeb->Ldr->InLoadOrderModuleList.Flink;
		     pListEntry != &pPeb->Ldr->InLoadOrderModuleList;
		     pListEntry = pListEntry->Flink)
		{
			auto pEntry = CONTAINING_RECORD(pListEntry, nt::LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

			if (ModuleHash == NULL || GetHash(pEntry->BaseDllName) == ModuleHash)
				return pEntry->DllBase;
		}
	}

	return nullptr;
}

template <const hash_t::value_type FunctionHash>
inline PVOID _GetProcAddress(const PVOID ModuleBaseAddress) noexcept
{
	PIMAGE_DOS_HEADER dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(ModuleBaseAddress);
	PIMAGE_NT_HEADERS32 nt32 = nullptr;
	PIMAGE_NT_HEADERS64 nt64 = nullptr;
	PIMAGE_EXPORT_DIRECTORY export_directory = nullptr;

	LPWORD ordinal_table = nullptr;
	LPDWORD name_table = nullptr;
	LPDWORD function_table = nullptr;

	if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
		return nullptr;

	nt32 = reinterpret_cast<PIMAGE_NT_HEADERS32>(static_cast<LPBYTE>(ModuleBaseAddress) + dos_header->e_lfanew);
	nt64 = reinterpret_cast<PIMAGE_NT_HEADERS64>(static_cast<LPBYTE>(ModuleBaseAddress) + dos_header->e_lfanew);

	if (nt32->Signature != IMAGE_NT_SIGNATURE)
		return nullptr;

	if (nt32->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		export_directory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(static_cast<LPBYTE>(ModuleBaseAddress) +
			nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	}
	else
	{
		export_directory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(static_cast<LPBYTE>(ModuleBaseAddress) +
			nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	}

	function_table = reinterpret_cast<LPDWORD>(static_cast<LPBYTE>(ModuleBaseAddress) + export_directory->
		AddressOfFunctions);
	name_table = reinterpret_cast<LPDWORD>(static_cast<LPBYTE>(ModuleBaseAddress) + export_directory->AddressOfNames);
	ordinal_table = reinterpret_cast<LPWORD>(static_cast<LPBYTE>(ModuleBaseAddress) + export_directory->
		AddressOfNameOrdinals);

	for (SIZE_T i = 0; i < export_directory->NumberOfNames; ++i)
	{
		const auto function_name = reinterpret_cast<PCCH>(ModuleBaseAddress) + static_cast<DWORD_PTR>(name_table[i]);
		if (GetHash(function_name) == FunctionHash)
			return reinterpret_cast<LPVOID>(static_cast<LPBYTE>(ModuleBaseAddress) + function_table[ordinal_table[i]]);
	}

	return nullptr;
}

template <hash_t::value_type ModuleHash>
NTSTATUS RemapNtModule(PVOID* BaseAddress) noexcept
{
	NTSTATUS status = STATUS_NOT_SUPPORTED;
	HANDLE sectionHandle = nullptr;
	SIZE_T viewSize = NULL;
	UNICODE_STRING usSectionName{};
	OBJECT_ATTRIBUTES objAttrib{};

	switch (ModuleHash)
	{
	case hashstr("kernel32.dll"):
		RtlInitUnicodeString(&usSectionName, xorstr_(L"\\KnownDlls\\kernel32.dll"));
		break;
	case hashstr("kernelbase.dll"):
		RtlInitUnicodeString(&usSectionName, xorstr_(L"\\KnownDlls\\kernelbase.dll"));
		break;
	case hashstr("ntdll.dll"):
		RtlInitUnicodeString(&usSectionName, xorstr_(L"\\KnownDlls\\ntdll.dll"));
		break;
	case hashstr("win32u.dll"):
		RtlInitUnicodeString(&usSectionName, xorstr_(L"\\KnownDlls\\win32u.dll"));
		break;
	default:
		return status;
	}

	InitializeObjectAttributes(&objAttrib, &usSectionName, OBJ_CASE_INSENSITIVE, NULL, NULL);

	status = NtFunctionCall(NtOpenSection)(&sectionHandle, SECTION_MAP_READ, &objAttrib);
	if (!NT_SUCCESS(status))
	{
		print("NtOpenSection failed: %llx", status);
		return status;
	}

	status = NtFunctionCall(NtMapViewOfSection)(sectionHandle, NtCurrentProcess(), BaseAddress, NULL, NULL, nullptr,
	                                            &viewSize, nt::SECTION_INHERIT::ViewShare, NULL, PAGE_READONLY);
	if (!NT_SUCCESS(status))
	{
		print("NtMapViewOfSection failed: %llx", status);
		return status;
	}

	if (sectionHandle)
	{
		status = NtClose(sectionHandle);
		if (!NT_SUCCESS(status))
		{
			print("NtClose failed: %llx", status);
			return status;
		}
	}

	return status;
}

using NtYieldExecution            = NTSTATUS(NTAPI*)();
using NtSetInformationThread      = NTSTATUS(NTAPI*)();
using NtSetInformationProcess     = NTSTATUS(NTAPI*)();
using NtQuerySystemInformation_t  = NTSTATUS(NTAPI*)();
using NtQueryInformationProcess_t = NTSTATUS(NTAPI*)();
using NtQueryObject_t             = NTSTATUS(NTAPI*)();
using NtCreateThreadEx            = NTSTATUS(NTAPI*)();
using NtSetDebugFilterState       = NTSTATUS(NTAPI*)();
using NtClose_t                   = NTSTATUS(NTAPI*)();
using NtQueryPerformanceCounter_t = NTSTATUS(NTAPI*)();
using NtGetContextThread_t        = NTSTATUS(NTAPI*)();
using NtSetContextThread_t        = NTSTATUS(NTAPI*)();
using NtQuerySystemTime_t         = NTSTATUS(NTAPI*)(OUT PLARGE_INTEGER SystemTime);
using GetTickCount_t              = DWORD(WINAPI*)();
using GetTickCount64_t            = ULONGLONG(WINAPI*)();
using OutputDebugStringA_t        = DWORD(WINAPI*)(LPCSTR lpOutputString);
using GetSystemTime_t             = void (WINAPI*)(LPSYSTEMTIME lpSystemTime);
using GetLocalTime_t              = void (WINAPI*)(LPSYSTEMTIME lpSystemTime);
