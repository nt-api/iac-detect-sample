#ifndef IGACAPI_H
#define IGACAPI_H

#if defined(_WIN32) || defined(_WIN64)
#ifdef BUILD_IACAPI_DLL
#define IACAPI_API extern "C" __declspec(dllexport)
#else
#define IACAPI_API extern "C" __declspec(dllimport)
#endif
#else
#define IACAPI_API extern "C"
#endif

#include <algorithm>
#include <vector>
#include <functional>

namespace igacApi
{
	inline std::vector<std::function<bool()>>& get_detect_functions()
	{
		static std::vector<std::function<bool()>> detectFunctions;
		return detectFunctions;
	}

	// Register a detection function. All registered detects will be called by the perform function.
	inline void iac_register_detect(const std::function<bool()>& fn)
	{
		get_detect_functions().push_back(fn);
	}

	// Exported function that will be called by the AntiCheat. Do not touch unless you know what you are doing.
	IACAPI_API inline bool iac_perform()
	{
		return std::any_of(get_detect_functions().begin(), get_detect_functions().end(), [](const std::function<bool()>& fn) {
			return fn();
		});
	}
}

#endif //IGACAPI_H
