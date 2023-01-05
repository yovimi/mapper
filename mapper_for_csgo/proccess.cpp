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
}