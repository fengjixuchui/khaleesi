#pragma once
/*
Здесь размещаются основные функции мотора:
LPVOID get_api(DWORD api_hash, LPCSTR module) - Функция ищет хеш функции в нужном модуле и возвращает адрес скрытой функции
*/
#include <windows.h>

//typedef struct _UNICODE_STRING
//{
//	USHORT Length;
//	USHORT MaximumLength;
//	PWSTR Buffer;
//} UNICODE_STRING;
//
struct LDR_MODULE_
{
	LIST_ENTRY e[3];
	HMODULE base;
	void* entry;
	UINT size;
	UNICODE_STRING dllPath;
	UNICODE_STRING dllname;
};

LPVOID get_api(DWORD api_hash, LPCSTR module, int len, unsigned int seed);
