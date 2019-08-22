#include "pch.h"

#include "SetHandleInformation_API.h"


BOOL SetHandleInformation_ProtectedHandle()
{
	/* some vars */
	HANDLE hMutex;

	/* Create a mutex so we can get a handle */
	hMutex = hash_CreateMutexW(NULL, FALSE, _T("2349823489"));

	if (hMutex) {

		/* Protect our handle */
		hash_SetHandleInformation(hMutex, HANDLE_FLAG_PROTECT_FROM_CLOSE, HANDLE_FLAG_PROTECT_FROM_CLOSE);


		__try {
			/* Then, let's try close it */
			hash_CloseHandle(hMutex);
		}

		__except (EXCEPTION_EXECUTE_HANDLER) {
			return TRUE;
		}

	}
	return FALSE;
}
