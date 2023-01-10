#include "features.h"

namespace game
{
	bool attach(const char* name)
	{
		void* Toolhelp = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

		if (!Toolhelp)
			return false;

		PROCESSENTRY32 ProcessEntry{ sizeof PROCESSENTRY32 };

		if (!Process32First(Toolhelp, &ProcessEntry))
			return false;

		while (Process32Next(Toolhelp, &ProcessEntry))
		{
			if (strstr(name, ProcessEntry.szExeFile))
			{
				CloseHandle(Toolhelp);

				game::process_id = ProcessEntry.th32ProcessID;
				game::process = OpenProcess(PROCESS_ALL_ACCESS, false, ProcessEntry.th32ProcessID);

				PVOID dll = VirtualAllocEx(game::process, NULL, strlen(("VCRUNTIME140.dll")), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
				WriteProcessMemory(game::process, dll, ("VCRUNTIME140.dll"), strlen(("VCRUNTIME140.dll")), NULL);
				LPVOID loadlib = (LPVOID)GetProcAddress(GetModuleHandle(("kernel32.dll")), ("LoadLibraryA"));
				HANDLE remote = CreateRemoteThread(game::process, NULL, NULL, (LPTHREAD_START_ROUTINE)loadlib, dll, NULL, NULL);

				if (!game::process)
				{
					ERROR("Failed attach to proccess");
				}
				return true;
			}
		}

		CloseHandle(Toolhelp);
		return false;
	}

	void load_sys_dll(const char* module)
	{

	}
}
