#pragma once
#include <vector>
#include <string>

std::vector < std::tuple < uintptr_t, std::string, std::string > > g_imports =
{
{ 0x3000, "KERNEL32.DLL", "CreateThread" },
{ 0x3004, "KERNEL32.DLL", "AllocConsole" },
{ 0x3008, "KERNEL32.DLL", "IsDebuggerPresent" },
{ 0x300c, "ntdll.dll", "RtlInitializeSListHead" },
{ 0x3010, "KERNEL32.DLL", "GetSystemTimeAsFileTime" },
{ 0x3014, "KERNEL32.DLL", "GetCurrentThreadId" },
{ 0x3018, "KERNEL32.DLL", "GetCurrentProcessId" },
{ 0x301c, "KERNEL32.DLL", "QueryPerformanceCounter" },
{ 0x3020, "KERNEL32.DLL", "IsProcessorFeaturePresent" },
{ 0x3024, "KERNEL32.DLL", "TerminateProcess" },
{ 0x3028, "KERNEL32.DLL", "GetCurrentProcess" },
{ 0x302c, "KERNEL32.DLL", "SetUnhandledExceptionFilter" },
{ 0x3030, "KERNEL32.DLL", "UnhandledExceptionFilter" },
{ 0x3038, "MSVCP140.dll", "??5?$basic_istream@DU?$char_traits@D@std@@@std@@QAEAAV01@P6AAAV01@AAV01@@Z@Z" },
{ 0x303c, "MSVCP140.dll", "??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QAEAAV01@H@Z" },
{ 0x3040, "MSVCP140.dll", "??5?$basic_istream@DU?$char_traits@D@std@@@std@@QAEAAV01@AAH@Z" },
{ 0x3044, "MSVCP140.dll", "?flush@?$basic_ostream@DU?$char_traits@D@std@@@std@@QAEAAV12@XZ" },
{ 0x3048, "MSVCP140.dll", "?_Osfx@?$basic_ostream@DU?$char_traits@D@std@@@std@@QAEXXZ" },
{ 0x304c, "MSVCP140.dll", "?sputc@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QAEHD@Z" },
{ 0x3050, "MSVCP140.dll", "?put@?$basic_ostream@DU?$char_traits@D@std@@@std@@QAEAAV12@D@Z" },
{ 0x3054, "MSVCP140.dll", "?widen@?$basic_ios@DU?$char_traits@D@std@@@std@@QBEDD@Z" },
{ 0x3058, "MSVCP140.dll", "?setstate@?$basic_ios@DU?$char_traits@D@std@@@std@@QAEXH_N@Z" },
{ 0x305c, "MSVCP140.dll", "?uncaught_exceptions@std@@YAHXZ" },
{ 0x3060, "MSVCP140.dll", "?cout@std@@3V?$basic_ostream@DU?$char_traits@D@std@@@1@A" },
{ 0x3064, "MSVCP140.dll", "?cin@std@@3V?$basic_istream@DU?$char_traits@D@std@@@1@A" },
{ 0x3068, "MSVCP140.dll", "?sputn@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QAE_JPBD_J@Z" },
{ 0x3070, "VCRUNTIME140.dll", "_except_handler4_common" },
{ 0x3074, "VCRUNTIME140.dll", "__std_type_info_destroy_list" },
{ 0x3078, "VCRUNTIME140.dll", "__std_terminate" },
{ 0x307c, "VCRUNTIME140.dll", "__CxxFrameHandler" },
{ 0x3080, "VCRUNTIME140.dll", "memset" },
{ 0x3088, "ucrtbase.dll", "_cexit" },
{ 0x308c, "ucrtbase.dll", "_initterm" },
{ 0x3090, "ucrtbase.dll", "_execute_onexit_table" },
{ 0x3094, "ucrtbase.dll", "_initialize_onexit_table" },
{ 0x3098, "ucrtbase.dll", "_initialize_narrow_environment" },
{ 0x309c, "ucrtbase.dll", "_seh_filter_dll" },
{ 0x30a0, "ucrtbase.dll", "_initterm_e" },
{ 0x30a4, "ucrtbase.dll", "_configure_narrow_argv" },
{ 0x30ac, "ucrtbase.dll", "__acrt_iob_func" },
{ 0x30b0, "ucrtbase.dll", "__stdio_common_vfprintf" },
{ 0x30b4, "ucrtbase.dll", "freopen_s" },
};

// 0x7D
inline const char* entry_shellcode = "\x55\x8B\xEC\x83\xEC\x18\x53\x56\x57\x89\x75\xE8\x89\x45\xFC\x89\x5D\xF8\x89\x4D\xF4\x89\x55\xF0\x89\x7D\xEC\x0F\xB6\x05\x00\x00\x52\x02\x85\xC0\x74\x32\xC6\x05\x00\x00\x52\x02\x00\x33\xC0\x33\xDB\xB8\xD8\xAD\xE0\xDC\x35\x37\x13\x00\x00\x35\xEF\xBE\xAD\xDE\xBB\x15\xAA\xE0\xDC\x81\xF3\x37\x13\x00\x00\x81\xF3\xEF\xBE\xAD\xDE\x6A\x00\x6A\x01\x50\xFF\xD3\x8B\x45\xFC\x8B\x5D\xF8\x8B\x4D\xF4\x8B\x55\xF0\x8B\x7D\xEC\x8B\x75\xE8\xC9\x55\x8B\xEC\x6A\xFE\xE9\xDE\xAD\xBE\xEF\x90\x5F\x5E\x5B\x8B\xE5\x5D\xC3";
