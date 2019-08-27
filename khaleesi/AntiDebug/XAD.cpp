#include "pch.h"
#include "XAD.h"

BOOL XAD ()
{
	XAD_STATUS		status;
	XAntiDebug		antiDbg(hash_GetModuleHandleW(NULL), FLAG_FULLON);
	BOOL			result;
	status = antiDbg.XAD_Initialize();

	if (status != XAD_OK)
	{
		return true;
	}
	for (;;)
	{
		result = antiDbg.XAD_ExecuteDetect();
			
		return result;
	}

}
