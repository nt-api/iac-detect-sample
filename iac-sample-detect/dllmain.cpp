#include "pch.h"
#include <iostream>

bool sample_detect()
{
	std::cout << "Test" << '\n';
	return true; // return true if detected else return false
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
		// example: igacApi::iac_register_detect(fp);
		igacApi::iac_register_detect(sample_detect);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
	default: ;
    }
    return TRUE;
}

