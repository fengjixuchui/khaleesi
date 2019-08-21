#pragma once
#include <Windows.h>
#include <functional>
#include <vector>
#include "nt_defs.h"
#include "inttypes.h"

// so you create your all your defs and all that jazz
// and then jump to the bottom of this file and create
// "ezCall" (tm) defines to one line these bad boys
class TSyscall
{
	static void* pCodeLoc;
public:
	template<class T>
	static std::function<T> GetInvoke(const char* sFunction, T * pAddress = nullptr)
	{
		if (!pCodeLoc)
		{
			pCodeLoc = hash_VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE); // if you really want to be sneaky you can scan for a code cave
#ifdef _WIN64
			BYTE cb[] = { 0x4C, 0x8B, 0xD1, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3 };
			auto size = ARRAYSIZE(cb);
			memcpy(pCodeLoc, cb, size);
#endif
		}

		auto pStub = (DWORD*)hash_GetProcAddress(hash_GetModuleHandleW(L"ntdll.dll"), sFunction); // sneakier ways to do this too

#ifdef _WIN64
		memcpy((DWORD*)pCodeLoc + 1, pStub + 1, sizeof(DWORD));
		//printf("pStub = 0x%" PRIx64 "\n", (DWORD*)pStub);
#else
		memcpy(pCodeLoc, pStub, 15);
#endif
		return std::function<T>((T*)pCodeLoc);
	}

};

#define _sc(t, s) TSyscall::GetInvoke(s, (t)nullptr)

#include "syscall_defs.h"