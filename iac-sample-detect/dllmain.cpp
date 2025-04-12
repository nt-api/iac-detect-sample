#include "pch.h"
#include "IgacAPI.h"
#include <iostream>

igacApi::IAC_DETECTION_RESULT sample_detect()
{
    return true; // detected
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		// register detection functions here
		igacApi::iac_register_detect("test", "test description", 0, sample_detect); // only log (severity 0)
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
	default: ;
    }
    return TRUE;
}

