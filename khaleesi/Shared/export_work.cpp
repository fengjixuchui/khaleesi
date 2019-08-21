#include "pch.h"
#include "MurmurHash2A.h"
#include "hash_work.h"
#include "export_work.h"
#include "XorStr.h"
#include <comdef.h>

/*
Для запуска функции LoadLibraryA из хеша, её выносить в модуль hash_work нестал, т.к. это нужно в этом модуле
*/

static HMODULE (WINAPI* temp_LoadLibraryA)(__in LPCSTR file_name) = nullptr;

static HMODULE hash_LoadLibraryA(__in LPCSTR file_name)
{
	return temp_LoadLibraryA(file_name);
}

static LPVOID parse_export_table(HMODULE module, DWORD api_hash, int len, unsigned int seed)
{
	PIMAGE_DOS_HEADER img_dos_header;
	PIMAGE_NT_HEADERS img_nt_header;
	PIMAGE_EXPORT_DIRECTORY in_export;

	img_dos_header = (PIMAGE_DOS_HEADER)module;
	img_nt_header = (PIMAGE_NT_HEADERS)((DWORD_PTR)img_dos_header + img_dos_header->e_lfanew);
	in_export = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)img_dos_header + img_nt_header->OptionalHeader.DataDirectory[
		IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	PDWORD rva_name;
	PWORD rva_ordinal;

	rva_name = (PDWORD)((DWORD_PTR)img_dos_header + in_export->AddressOfNames);
	rva_ordinal = (PWORD)((DWORD_PTR)img_dos_header + in_export->AddressOfNameOrdinals);

	UINT ord = -1;
	char* api_name;
	unsigned int i;

	for (i = 0; i < in_export->NumberOfNames - 1; i++)
	{
		api_name = (PCHAR)((DWORD_PTR)img_dos_header + rva_name[i]);

		const int get_hash = MurmurHash2A(api_name, len, seed);

		if (api_hash == get_hash)
		{
			ord = static_cast<UINT>(rva_ordinal[i]);
			break;
		}
	}

	const auto func_addr = (PDWORD)((DWORD_PTR)img_dos_header + in_export->AddressOfFunctions);
	const auto func_find = (LPVOID)((DWORD_PTR)img_dos_header + func_addr[ord]);

	return func_find;
}
int STRCMP_(const char *p1, const char *p2)
{
	const unsigned char *s1 = (const unsigned char *)p1;
	const unsigned char *s2 = (const unsigned char *)p2;
	unsigned char c1, c2;
	do
	{
		c1 = (unsigned char)*s1++;
		c2 = (unsigned char)*s2++;
		if (c1 == '\0')
			return c1 - c2;
	} while (c1 == c2);
	return c1 - c2;
}
LPVOID get_api(DWORD api_hash, LPCSTR module, int len, unsigned int seed)
{
	HMODULE krnl32, hDll;
	LPVOID api_func;

#ifdef _WIN64
	const auto ModuleList = 0x18;
	const auto ModuleListFlink = 0x18;
	const auto KernelBaseAddr = 0x10;
	const INT_PTR peb = __readgsqword(0x60);
#else
	int ModuleList = 0x0C;
	int ModuleListFlink = 0x10;
	int KernelBaseAddr = 0x10;
	INT_PTR peb = __readfsdword(0x30);
#endif

	// Теперь получим адрес kernel32.dll

	const auto mdllist = *(INT_PTR*)(peb + ModuleList);
	const auto mlink = *(INT_PTR*)(mdllist + ModuleListFlink);
	auto krnbase = *(INT_PTR*)(mlink + KernelBaseAddr);

	auto mdl = (LDR_MODULE_*)mlink;
	do
	{
		mdl = (LDR_MODULE_*)mdl->e[0].Flink;

		if (mdl->base != nullptr)
		{
			const WCHAR* wc = mdl->dllname.Buffer;
			_bstr_t b(wc);
			const char* c = b;
			//if (!strcmp(c, "kernel32.dll") == 0)
			if (STRCMP_(c, ("KERNEL32.DLL")) == 0)
			{
				break;
			}
		}
	}
	while (mlink != (INT_PTR)mdl);

	krnl32 = static_cast<HMODULE>(mdl->base);

	//Получаем адрес функции LoadLibraryA
	const int api_hash_LoadLibraryA = MurmurHash2A("LoadLibraryA", 12, 10);
	temp_LoadLibraryA = static_cast<HMODULE(WINAPI*)(LPCSTR)>(parse_export_table(krnl32, api_hash_LoadLibraryA, 12, 10));
	hDll = hash_LoadLibraryA(module);

	api_func = static_cast<LPVOID>(parse_export_table(hDll, api_hash, len, seed));
	return api_func;
}
