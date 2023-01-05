#pragma once
#include <windows.h>
#include <string>
#include <iostream>
#include <process.h>
#include <thread>
#include <winternl.h>
#include <TlHelp32.h>
#include <fstream>
#include <vector>
#include <array>

#include <Zydis/Zydis.h>
#include <Zycore/Zycore.h>
#include <Zycore/Format.h>
#include <Zycore/API/Memory.h>
#include <Zycore/LibC.h>

#include "FileReader.hpp"

#pragma warning(disable : 4996) 
#define WIN32_LEAN_AND_MEAN 
#define _CRT_SECURE_NO_WARNINGS 
#define BYTES_TO_READ_FROM_FUNCTION 20

typedef INT(__stdcall* dllmain)(HMODULE, DWORD, LPVOID);

#define ERROR(Error, ...) { char Buffer[1024 * 16]; sprintf_s(Buffer, sizeof Buffer, Error, __VA_ARGS__); MessageBoxA(0, Buffer, "", MB_SYSTEMMODAL | MB_ICONERROR); ExitProcess(0); }

inline RemoteCode::FileReader file;
inline ByteArray binary;
inline ByteArray dos_binary;
inline bool debug_mode = false;
inline bool show_asm = false;

namespace game
{
    inline int process_id;
    inline HANDLE	process;

	bool attach(const char* name);
}

namespace mapper
{
    inline uintptr_t entry_address = 0;
    inline uintptr_t entry_block = 0;
    void process_mapping();
    void call_entry();
}
