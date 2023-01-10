#pragma once
#include <vector>
#include <string>

std::vector < std::tuple < uintptr_t, std::string, std::string > > g_imports =
{
{ 0x2000, "KERNEL32.DLL", "GetCurrentProcessId" },
{ 0x2004, "KERNEL32.DLL", "IsDebuggerPresent" },
{ 0x2008, "ntdll.dll", "RtlInitializeSListHead" },
{ 0x200c, "KERNEL32.DLL", "GetSystemTimeAsFileTime" },
{ 0x2010, "KERNEL32.DLL", "GetCurrentThreadId" },
{ 0x2014, "KERNEL32.DLL", "UnhandledExceptionFilter" },
{ 0x2018, "KERNEL32.DLL", "QueryPerformanceCounter" },
{ 0x201c, "KERNEL32.DLL", "IsProcessorFeaturePresent" },
{ 0x2020, "KERNEL32.DLL", "TerminateProcess" },
{ 0x2024, "KERNEL32.DLL", "GetCurrentProcess" },
{ 0x2028, "KERNEL32.DLL", "SetUnhandledExceptionFilter" },
{ 0x2030, "USER32.dll", "MessageBoxA" },
{ 0x2038, "VCRUNTIME140.dll", "memset" },
{ 0x203c, "VCRUNTIME140.dll", "_except_handler4_common" },
{ 0x2040, "VCRUNTIME140.dll", "__std_type_info_destroy_list" },
{ 0x2048, "ucrtbase.dll", "_seh_filter_dll" },
{ 0x204c, "ucrtbase.dll", "_initterm_e" },
{ 0x2050, "ucrtbase.dll", "_initterm" },
{ 0x2054, "ucrtbase.dll", "_initialize_narrow_environment" },
{ 0x2058, "ucrtbase.dll", "_initialize_onexit_table" },
{ 0x205c, "ucrtbase.dll", "_cexit" },
{ 0x2060, "ucrtbase.dll", "_configure_narrow_argv" },
{ 0x2064, "ucrtbase.dll", "_execute_onexit_table" },
};

// 0x7D
inline const char* entry_shellcode = "\x55\x8B\xEC\x83\xEC\x18\x53\x56\x57\x89\x75\xE8\x89\x45\xFC\x89\x5D\xF8\x89\x4D\xF4\x89\x55\xF0\x89\x7D\xEC\x0F\xB6\x05\x00\x00\x52\x02\x85\xC0\x74\x32\xC6\x05\x00\x00\x52\x02\x00\x33\xC0\x33\xDB\xB8\xD8\xAD\xE0\xDC\x35\x37\x13\x00\x00\x35\xEF\xBE\xAD\xDE\xBB\x15\xAA\xE0\xDC\x81\xF3\x37\x13\x00\x00\x81\xF3\xEF\xBE\xAD\xDE\x6A\x00\x6A\x01\x50\xFF\xD3\x8B\x45\xFC\x8B\x5D\xF8\x8B\x4D\xF4\x8B\x55\xF0\x8B\x7D\xEC\x8B\x75\xE8\xC9\x55\x8B\xEC\x6A\xFE\xE9\xDE\xAD\xBE\xEF\x90\x5F\x5E\x5B\x8B\xE5\x5D\xC3";
