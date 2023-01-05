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

inline const char* entry_shellcode = "\x55\x8B\xEC\x83\xEC\x20\x53\x56\x57\x89\x75\xE4\x89\x45\xF8\x89\x5D\xF4\x89\x4D\xF0\x89\x55\xEC\x89\x7D\xE8\xC7\x45\xE0\xD5\x65\x92\x75\xC7\x45\xFC\x74\x03\x37\x01\x6A\x00\x6A\x01\x68\x00\x00\x37\x01\xFF\x55\xFC\x8B\x45\xF8\x8B\x5D\xF4\x8B\x4D\xF0\x8B\x55\xEC\x8B\x7D\xE8\x8B\x75\xE4\xC9\x68\xA0\x02\x00\x00\xE9\xAE\xFF\xB4\x0E\x5B\x8B\xE5\x5D\xC3";
inline const char* restore_hook_shellcode = "\x55\x8B\xEC\x83\xEC\x20\x53\x56\x57\x89\x75\xE4\x89\x45\xF8\x89\x5D\xF4\x89\x4D\xF0\x89\x55\xEC\x89\x7D\xE8\xC7\x45\xE0\x00\x00\x30\x12\xC7\x45\xFC\x00\x00\x57\x01\x8B\x45\xFC\x8B\x0D\x00\x01\xEF\x00\x89\x08\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x8B\x45\xF8\x8B\x5D\xF4\x8B\x4D\xF0\x8B\x55\xEC\x8B\x7D\xE8\x8B\x75\xE4\xC9\x68\xE8\xAB\x9C\x75\xE9\x7E\x65\x3A\x74\x5B\x8B\xE5\x5D\xC3";
inline const char* restore_shellcode = "\x90\x90\x90";
inline const char* meme_shellcode = "\xC3\x6E\x6F\x20\x63\x72\x61\x63\x6B\x20\x6D\x65\x20\x70\x6C\x73\x72\x61\x74\x69\x6F\x20\x6D\x61\x6E\x29\x29\x29\x29";
inline const char* create_fake_thread_shellcode = "\x6A\x00\x6A\x00\x6A\x00\x68\x37\x13\x00\x00\x6A\x00\x6A\x00\xE8\xFC\xFE\xE8\x0D\x90\xC3";