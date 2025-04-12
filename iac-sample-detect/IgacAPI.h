/**
 * @file igacapi.h
 * @brief API for the Integrity Guard Anti Cheat (IGAC)
 *
 * This API enables the integration of custom detection functions
 * into the IGAC as well as the utilization of YARA scans for file analysis.
 *
 * @version 1.0.0
 */

#ifndef IGACAPI_H
#define IGACAPI_H

#if defined(_WIN32) || defined(_WIN64)
#ifdef BUILD_IACAPI_DLL
#define IACAPI_API __declspec(dllexport)
#else
#define IACAPI_API __declspec(dllimport)
#endif
#else
#define IACAPI_API
#endif

#include <vector>
#include <string>

namespace igacApi
{
    /**
     * @typedef IAC_DETECTION_RESULT
     * @brief Alias for boolean type used for detection results
     *
	 * Detection functions should return this type instead of bool for readability.
     * 
     * true indicates the detection was positive (cheat detected)
     * false indicates the detection was negative (no cheat detected)
     */
    typedef bool IAC_DETECTION_RESULT;

    namespace detail // Functions in this namespace should not be used directly
    {
        /**
	     * @typedef IAC_DETECT
	     * @brief Function pointer type for detection functions
	     *
	     * Detection functions must return a boolean.
	     */
        typedef IAC_DETECTION_RESULT(*IAC_DETECT)();

        /**
         * @typedef IAC_SCAN_FILE_WITH_YARA_CALLBACK
         * @brief Function pointer type for YARA scan callbacks
         */
        typedef bool (*IAC_SCAN_FILE_WITH_YARA_CALLBACK)(const std::string&);

        /** Function pointer for YARA scanning */
        static IAC_SCAN_FILE_WITH_YARA_CALLBACK IAC_SCAN_FILE_WITH_YARA_PTR = nullptr;

        /**
         * @struct detection
         * @brief Structure for detection functions and associated metadata
         */
        struct detection {
            std::string name;
            std::string description;
            int severity;
            IAC_DETECT detect_func;
        };

        /**
         * @brief Returns the vector with registered detection functions
         * @return Reference to the static vector of detection functions
         */
        inline std::vector<detection>& get_detect_functions()
        {
            static std::vector<detection> detectFunctions;
            return detectFunctions;
        }
    }

    /**
     * @brief Registers a detection function to be called periodically by IGAC
     *
     * @param name Name of the detection
     * @param description Description of the detection
     * @param severity Severity level (0: just log, 1: perform kick, 2: perform ban (bans are always permanent))
     * @param fn Function pointer to the detection function
     */
    inline void iac_register_detect(const std::string& name, const std::string& description, const int severity, const detail::IAC_DETECT& fn)
    {
        detail::get_detect_functions().push_back({ .name = name, .description = description, .severity = severity, .detect_func = fn });
    }

    /**
     * @brief Performs a YARA scan on a file
     *
     * @param filePath Path to the file to be scanned
     * @return true if a match was found, false if not or if no YARA scanner is registered
     */
    inline bool iac_scan_file_with_yara(const std::string& filePath)
    {
        if (detail::IAC_SCAN_FILE_WITH_YARA_PTR)
        {
            return detail::IAC_SCAN_FILE_WITH_YARA_PTR(filePath);
        }
        return false;
    }

    /**
     * @brief Initializes the external IGAC API with the YARA scan callback
     *
     * This function is called by the IGAC framework to set up the YARA scanning functionality.
     *
     * @param callback Function pointer for the YARA scan
     */
    IACAPI_API inline void init_external_iac_api(const detail::IAC_SCAN_FILE_WITH_YARA_CALLBACK callback)
    {
        detail::IAC_SCAN_FILE_WITH_YARA_PTR = callback;
    }

    /**
     * @brief Returns all registered detection functions
     *
     * This function is used by the IGAC framework to obtain all registered detection functions.
     *
     * @return Reference to the vector with all registered detection functions
     */
    IACAPI_API inline std::vector<detail::detection>& iac_get_detects_external()
    {
        return detail::get_detect_functions();
    }

    /**
     * @brief Returns the API version
     *
     * @return Integer value of the API version (100 for v1.0.0)
     */
    IACAPI_API inline int iac_get_api_version()
    {
        return 100; // v1.0.0
    }
}

#endif //IGACAPI_H