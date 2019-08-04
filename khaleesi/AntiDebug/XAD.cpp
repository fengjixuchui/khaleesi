#include "pch.h"
#include "XAD.h"

BOOL XAD ()
{
	XAD_STATUS		status;
	XAntiDebug		antiDbg(GetModuleHandle(NULL), FLAG_FULLON);
	BOOL			result;
	status = antiDbg.XAD_Initialize();
	if (status != XAD_OK)
	{
		printf("initialize error. %d\n", status);
		return true;
	}
	for (;;)
	{
		result = antiDbg.XAD_ExecuteDetect();
		printf("result = %s\n", result ? "true" : "false");
			
		return result;
	}

}
