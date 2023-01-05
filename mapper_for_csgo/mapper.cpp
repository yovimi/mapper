#include "features.h"
#include "binary_info.h"

namespace mapper
{
	uintptr_t calculate_rva(uint32_t value2, std::vector < uintptr_t > blocks_data, bool counting_pe)
	{
		std::vector < uintptr_t > calculate_block = blocks_data;
		uintptr_t value1 = 0;
		uintptr_t address_block = 0;
		if (counting_pe) { value2 = value2 - 0x1000; }
		if (value2 > 0x1000)
		{
			int block = value2 / 0x1000;
			block = block + 1;

			if (block > calculate_block.size())
				return 0xdeadc0de;

			for (int i = 1; i <= block;)
			{
				if (i == block)
					address_block = calculate_block.back();
				calculate_block.pop_back();
				i = i + 1;
			}
			value2 = value2 - (0x1000 * (block - 1));
			value1 = address_block + value2;
		}
		else
		{
			address_block = calculate_block.back();
			value1 = address_block + value2;
		}

		return value1;
	}

	void call_entry()
	{
		// =-= :3
		uintptr_t hk_address = reinterpret_cast<uintptr_t>(GetProcAddress(GetModuleHandleA("kernelbase.dll"), "CreateRemoteThreadEx"));
		uintptr_t ret_addr = hk_address + 0x5;
		uintptr_t restore_hk_address = hk_address + 0x5;
		uintptr_t restore_ret_addr = restore_hk_address + 0x5;
		uintptr_t save_push = 0;
		LPVOID alloc = VirtualAllocEx(game::process, 0, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		LPVOID restore_alloc = VirtualAllocEx(game::process, 0, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		LPVOID meme_alloc = VirtualAllocEx(game::process, 0, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		LPVOID alloc_for_thread = VirtualAllocEx(game::process, 0, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		uintptr_t save_buffer = (uintptr_t)restore_alloc + 0x100;
		uintptr_t unhook_alloc = (uintptr_t)alloc + 0x32;

		// hook for restore create thread hook xDD (to call entry 1 time)
		ReadProcessMemory(game::process, (LPVOID)((uintptr_t)hk_address + 0x6), &save_push, 0x4, 0);
		WriteProcessMemory(game::process, (LPVOID)((uintptr_t)restore_alloc + 0x100), restore_shellcode, 0x3, 0);
		WriteProcessMemory(game::process, restore_alloc, restore_hook_shellcode, 0x61, 0);
		uintptr_t calc_restore_ret_addr = restore_ret_addr - ((uintptr_t)restore_alloc + 0x57) - 0x5;
		WriteProcessMemory(game::process, (LPVOID)((uintptr_t)restore_alloc + 0x57 + 0x1), &calc_restore_ret_addr, 0x4, 0);
		WriteProcessMemory(game::process, (LPVOID)((uintptr_t)restore_alloc + 0x25), &unhook_alloc, 0x4, 0);
		WriteProcessMemory(game::process, (LPVOID)((uintptr_t)restore_alloc + 0x2E), &save_buffer, 0x4, 0);
		WriteProcessMemory(game::process, (LPVOID)((uintptr_t)restore_alloc + 0x53), &save_push, 0x4, 0);
		uintptr_t restore_calc_address = (uintptr_t)restore_alloc - restore_hk_address - 0x5;
		WriteProcessMemory(game::process, (LPVOID)(restore_hk_address + 0x1), &restore_calc_address, 0x4, 0);
		WriteProcessMemory(game::process, (LPVOID)(restore_hk_address), "\xE9", 0x1, 0);

		// hook create thread lol
		printf("(entry) allocated at 0x%010" "llx" "\n", (ZyanU64)alloc);
		uintptr_t calc_address = (uintptr_t)alloc - hk_address - 0x5;
		WriteProcessMemory(game::process, alloc, entry_shellcode, 0x57, 0);
		WriteProcessMemory(game::process, (LPVOID)((uintptr_t)alloc + 0x2E), &entry_block, 0x4, 0);
		WriteProcessMemory(game::process, (LPVOID)((uintptr_t)alloc + 0x25), &entry_address, 0x4, 0);
		WriteProcessMemory(game::process, (LPVOID)((uintptr_t)alloc + 0x1E), &ret_addr, 0x4, 0);
		uintptr_t calc_ret_addr = ret_addr - ((uintptr_t)alloc + 0x4D) - 0x5;
		WriteProcessMemory(game::process, (LPVOID)((uintptr_t)alloc + 0x4D + 0x1), &calc_ret_addr, 0x4, 0);
		WriteProcessMemory(game::process, (LPVOID)(hk_address + 0x1), &calc_address, 0x4, 0);
		WriteProcessMemory(game::process, (LPVOID)(hk_address), "\xE9", 0x1, 0);

		// create meme and call ep (´｡• ω •｡`)
		printf("(entry) meme allocated at 0x%010" "llx" "\n", (ZyanU64)meme_alloc);
		printf("(entry) call thread allocated at 0x%010" "llx" "\n", (ZyanU64)alloc_for_thread);
		WriteProcessMemory(game::process, (LPVOID)(meme_alloc), meme_shellcode, 0x1D, 0);
		WriteProcessMemory(game::process, (LPVOID)(alloc_for_thread), create_fake_thread_shellcode, 0x16, 0);
		WriteProcessMemory(game::process, (LPVOID)((uintptr_t)alloc_for_thread + 0x7), &meme_alloc, 0x4, 0);
		uintptr_t create_thread_address = reinterpret_cast<uintptr_t>(GetProcAddress(GetModuleHandleA("KERNEL32.DLL"), "CreateThread"));
		uintptr_t calculate_lmao = create_thread_address - ((uintptr_t)alloc_for_thread + 0xF) - 0x5;
		WriteProcessMemory(game::process, (LPVOID)((uintptr_t)alloc_for_thread + 0xF + 0x1), &calculate_lmao, 0x4, 0);
		CreateRemoteThread(game::process, NULL, 0, (LPTHREAD_START_ROUTINE)(alloc_for_thread), 0, 0, NULL);
	}

	void fix_imports(IMAGE_NT_HEADERS* ntheaders, std::vector < uintptr_t > blocks_data)
	{
		DWORD currentElem = 0;
		DWORD lastElem = 0;
		uintptr_t calculateImportTable = calculate_rva((uint32_t)ntheaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, blocks_data, false);
		PIMAGE_IMPORT_DESCRIPTOR import_table = (PIMAGE_IMPORT_DESCRIPTOR)(calculateImportTable);
		for (int i = 0; import_table[i].FirstThunk != 0; i++)
		{
			DWORD* funcName = (DWORD*)(import_table[i].OriginalFirstThunk);
			funcName = reinterpret_cast<DWORD*>(calculate_rva((uint32_t)funcName, blocks_data, false));
			HMODULE mod = LoadLibraryA((LPCSTR)(import_table[i].Name));
			mod = reinterpret_cast<HMODULE>(calculate_rva((uint32_t)mod, blocks_data, false));
			DWORD* dw_FirstThunk = (DWORD*)(import_table[i].FirstThunk);
			dw_FirstThunk = reinterpret_cast<DWORD*>(calculate_rva((uint32_t)dw_FirstThunk, blocks_data, false));

			for (int b = 0; funcName[b] != 0; b++)
			{
				if (funcName[b] & IMAGE_ORDINAL_FLAG)
				{
					dw_FirstThunk[b] = (DWORD)GetProcAddress(mod, (LPCSTR)(funcName[b] & 0xFFFF));
				}
				else
				{
					uintptr_t calculateFuncName = funcName[b] + 2;
					calculateFuncName = calculate_rva((uint32_t)funcName, blocks_data, false);
					dw_FirstThunk[b] = (DWORD)GetProcAddress(mod, (LPCSTR)(calculateFuncName));
					currentElem = funcName[b];
					currentElem = calculate_rva((uint32_t)currentElem, blocks_data, false);
				}
			}
		}
	}

	void process_mapping()
	{
		//init
		time_t seconds;
		time(&seconds);
		srand((unsigned int)seconds);
		uintptr_t size_module = file.GetFileLength();
		HANDLE owned_process = GetCurrentProcess();
		dos_binary.insert(dos_binary.begin(), (uint8_t*)file, (uint8_t*)(file + file.GetFileLength()));
		PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)dos_binary.data();
		PIMAGE_NT_HEADERS nthead = (PIMAGE_NT_HEADERS)((DWORD)dos + dos->e_lfanew);

		//init zydis
		ZyanU8 SavedOriginalBuffers[0x1337][BYTES_TO_READ_FROM_FUNCTION];
		int nIteration = 0;
		ZydisDecoder decoder;
		ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZydisStackWidth::ZYDIS_STACK_WIDTH_32);
		ZydisFormatter formatter;
		ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

		//params
		bool succes = false;
		uintptr_t free_block = 0x10000000;
		uintptr_t blocks_size = 0x1000;
		uintptr_t region_size = 0x1000;
		uintptr_t buffer = 0;
		auto random_page = MEM_TOP_DOWN;
		std::vector < uintptr_t >  blocks{};
		bool rand_bool = false;

		while (succes != true)
		{
			// shit code, im sorry =)
			if (rand_bool == false)
				rand_bool = true;
			else
				rand_bool = false;

			// randomization
			if (rand_bool == true)
				random_page = 0;
			else
				random_page = MEM_TOP_DOWN;

back:       // allocate block
			auto alloc = VirtualAllocEx(game::process, reinterpret_cast<void*>(0), region_size, random_page | MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			if (alloc == 0x0)
				alloc = VirtualAllocEx(game::process, reinterpret_cast<void*>(0), region_size, MEM_LARGE_PAGES | MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			if (alloc == 0x0)
				goto back;

			printf("allocated at 0x%010" "llx" "\n", (ZyanU64)alloc);

			//save blocks
			blocks.push_back((uintptr_t)alloc);

			// calc
			binary.insert(
				binary.begin(),
				(uint8_t*)file + blocks_size,
				(uint8_t*)(file + blocks_size + 0x1000)
			);

			//write module memory
			WriteProcessMemory(game::process, (LPVOID)alloc, binary.data(), 0x1000, NULL);

			blocks_size = blocks_size + 0x1000;

			//complete
			if (blocks_size >= file.GetFileLength())
			{
				std::reverse(blocks.begin(), blocks.end());

				std::cout << "original entry 0x" << std::hex << nthead->OptionalHeader.AddressOfEntryPoint << std::endl;

				entry_address = calculate_rva(nthead->OptionalHeader.AddressOfEntryPoint, blocks, true);
				std::cout << "entry at 0x" << std::hex << entry_address << std::endl;

				// save begin blocks for ep
				std::vector < uintptr_t >  calculate_blocks{};
				calculate_blocks = blocks;
				entry_block = calculate_blocks.back();

				for (const auto& imp : g_imports)
				{
					HMODULE mod = LoadLibraryA(std::get< 1 >(imp).c_str());

					if (!mod)
						continue;

					uintptr_t imp_tab = calculate_rva(std::get< 0 >(imp), blocks, false);
					printf("import replace at 0x%010" "llx" "\n", (ZyanU64)imp_tab);
					uintptr_t calculate = reinterpret_cast<uintptr_t>(GetProcAddress(mod, std::get< 2 >(imp).c_str()));

					WriteProcessMemory(game::process, (LPVOID)imp_tab, &calculate, 0x4, 0);
				}

				uintptr_t calculate_block_size = 0;
				calculate_blocks = blocks;
				bool find_inst = false;

				for (int i = 0; i < file.GetFileLength() / 0x1000;)
				{
					if (calculate_blocks.size() == 0) { goto end_function;  }
					uintptr_t block_base_address = calculate_blocks.back();
					ZyanU8 pFirstBytesOfFunction[0x1000];
					std::size_t m_nReadBytes = ReadProcessMemory(
						game::process,
						(LPCVOID)block_base_address,
						pFirstBytesOfFunction,
						0x1000,
						NULL
					);
					ZyanU64 runtime_address = (uintptr_t)block_base_address;
					ZyanUSize offset = 0;
					const ZyanUSize length = BYTES_TO_READ_FROM_FUNCTION;
					ZydisDecodedInstruction instruction;
					while (ZydisDecoderDecodeBuffer(&decoder, pFirstBytesOfFunction + offset, length - offset, &instruction))
					{
                        char buffer[256];
						ZydisFormatterFormatInstruction(&formatter, &instruction, buffer, sizeof(buffer), runtime_address);

						if (instruction.mnemonic == ZydisMnemonic_::ZYDIS_MNEMONIC_JZ || instruction.mnemonic == ZydisMnemonic_::ZYDIS_MNEMONIC_JB 
							|| instruction.mnemonic == ZydisMnemonic_::ZYDIS_MNEMONIC_JNZ || instruction.mnemonic == ZydisMnemonic_::ZYDIS_MNEMONIC_JBE
							|| instruction.mnemonic == ZydisMnemonic_::ZYDIS_MNEMONIC_JLE || instruction.mnemonic == ZydisMnemonic_::ZYDIS_MNEMONIC_JNB
							|| instruction.opcode == 0x0F)
						{
							if (show_asm) { printf(buffer); printf("\n"); }
							if (instruction.length >= 0x6)
							{
								if (show_asm) { printf(buffer); printf("\n"); }
								uintptr_t delta_address = runtime_address + 0x2;
								ZyanU64 absolute_addr = 0;
								ZydisCalcAbsoluteAddress(&instruction, instruction.operands, runtime_address, &absolute_addr);
								if (absolute_addr >= 0x10000000 && absolute_addr <= file.GetFileLength() + 0x10000000)
								{
									if (debug_mode) printf("-> unknown memory 0x%010" "llx" "\n", runtime_address);
									uintptr_t new_call_address = 0;
									new_call_address = calculate_rva(absolute_addr - 0x10000000, blocks, false);
									if (new_call_address != 0xdeadc0de)
									{
										WriteProcessMemory
										(
											game::process,
											(LPVOID)delta_address,
											&new_call_address,
											0x4,
											NULL
										);
									}
									find_inst = true;
									goto next_stage;
								}
							}
							if (instruction.length == 0x5)
							{
								if (show_asm) { printf(buffer); printf("\n"); }
								uintptr_t delta_address = runtime_address + 0x1;
								ZyanU64 absolute_addr = 0;
								ZydisCalcAbsoluteAddress(&instruction, instruction.operands, runtime_address, &absolute_addr);
								if (absolute_addr >= 0x10000000 && absolute_addr <= file.GetFileLength() + 0x10000000)
								{
									if (debug_mode) printf("-> unknown memory 0x%010" "llx" "\n", runtime_address);
									uintptr_t new_call_address = 0;
									new_call_address = calculate_rva(absolute_addr - 0x10000000, blocks, false);
									if (new_call_address != 0xdeadc0de)
									{
										WriteProcessMemory
										(
											game::process,
											(LPVOID)delta_address,
											&new_call_address,
											0x4,
											NULL
										);
									}
									find_inst = true;
									goto next_stage;
								}
							}
						}

						if (instruction.operands->type == ZYDIS_OPERAND_TYPE_MEMORY) 
						{
							if (show_asm) { printf(buffer); printf("\n"); }
							if (instruction.length >= 0x6)
							{
								if (show_asm) { printf(buffer); printf("\n"); }
								uintptr_t absolute_addr = 0;
								uintptr_t delta_address = runtime_address + 0x2;
								ReadProcessMemory
								(
									game::process,
									(LPVOID)delta_address,
									&absolute_addr,
									0x4,
									NULL
								);
								if (absolute_addr >= 0x10000000 && absolute_addr <= file.GetFileLength() + 0x10000000)
								{
									if (debug_mode) printf("-> unknown memory 0x%010" "llx" "\n", runtime_address);
									uintptr_t new_call_address = 0;
									new_call_address = calculate_rva(absolute_addr - 0x10000000, blocks, false);
									if (new_call_address != 0xdeadc0de)
									{
										WriteProcessMemory
										(
											game::process,
											(LPVOID)delta_address,
											&new_call_address,
											0x4,
											NULL
										);
									}
									find_inst = true;
									goto next_stage;
								}
							}
							if (instruction.length == 0x5)
							{
								if (show_asm) { printf(buffer); printf("\n"); }
								uintptr_t absolute_addr = 0;
								uintptr_t delta_address = runtime_address + 0x1;
								ReadProcessMemory
								(
									game::process,
									(LPVOID)delta_address,
									&absolute_addr,
									0x4,
									NULL
								);
								if (absolute_addr >= 0x10000000 && absolute_addr <= file.GetFileLength() + 0x10000000)
								{
									if (debug_mode) printf("-> unknown memory 0x%010" "llx" "\n", runtime_address);
									uintptr_t new_call_address = 0;
									new_call_address = calculate_rva(absolute_addr - 0x10000000, blocks, false);
									if (new_call_address != 0xdeadc0de)
									{
										WriteProcessMemory
										(
											game::process,
											(LPVOID)delta_address,
											&new_call_address,
											0x4,
											NULL
										);
									}
									find_inst = true;
									goto next_stage;
								}
							}
						}
                                                                        
						if (instruction.mnemonic == ZydisMnemonic_::ZYDIS_MNEMONIC_CALL && instruction.operands->type != ZYDIS_OPERAND_TYPE_MEMORY && instruction.operands->type != ZYDIS_OPERAND_TYPE_REGISTER)  // 0xe9
						{
							if (show_asm) { printf(buffer); printf("\n"); }
							ZyanU64 absolute_addr = 0;
							ZydisCalcAbsoluteAddress(&instruction, instruction.operands, runtime_address, &absolute_addr);
							if (absolute_addr > block_base_address || absolute_addr < block_base_address)
							{
								if (runtime_address >= block_base_address + 0xfff - 0x4) { goto next_stage; }
								if (debug_mode) printf("-> call 0x%010" "llx" "\n", runtime_address);
								uintptr_t new_call_address = 0;
								if (absolute_addr > block_base_address) { new_call_address = calculate_rva(absolute_addr - block_base_address + calculate_block_size, blocks, false); }
								if (absolute_addr < block_base_address) { new_call_address = calculate_rva(block_base_address - absolute_addr + calculate_block_size, blocks, false); }
								uintptr_t calc_address = new_call_address - runtime_address - 0x5;
								uintptr_t delta_address = runtime_address + 0x1;
								if (new_call_address != 0xdeadc0de)
								{
									WriteProcessMemory
									(
										game::process,
										(LPVOID)delta_address,
										&calc_address,
										0x4,
										NULL
									);
								}
								find_inst = true;
							}
						}

						if (instruction.mnemonic == ZydisMnemonic_::ZYDIS_MNEMONIC_MOV && instruction.operands->type != ZYDIS_OPERAND_TYPE_MEMORY) 
						{
							if (show_asm) { printf(buffer); printf("\n"); }
							uintptr_t absolute_addr = 0;
							uintptr_t delta_address = runtime_address + 0x1;
							ReadProcessMemory
							(
								game::process,
								(LPVOID)delta_address,
								&absolute_addr,
								0x4,
								NULL
							);
							if (absolute_addr >= 0x10000000 && absolute_addr <= file.GetFileLength() + 0x10000000)
							{
								if (debug_mode) printf("-> mov 0x%010" "llx" "\n", runtime_address);
								uintptr_t new_call_address = 0;
								new_call_address = calculate_rva(absolute_addr - 0x10000000, blocks, false);
								if (new_call_address != 0xdeadc0de)
								{
									WriteProcessMemory
									(
										game::process,
										(LPVOID)delta_address,
										&new_call_address,
										0x4,
										NULL
									);
								}
								find_inst = true;
							}
						}

						if (instruction.mnemonic == ZydisMnemonic_::ZYDIS_MNEMONIC_PUSH || instruction.opcode == 0x68)
						{
							if (show_asm) { printf(buffer); printf("\n"); }
							uintptr_t absolute_addr = 0;
							uintptr_t delta_address = runtime_address + 0x1;
							ReadProcessMemory
							(
								game::process,
								(LPVOID)delta_address,
								&absolute_addr,
								0x4,
								NULL
							);
							if (absolute_addr >= 0x10000000 && absolute_addr <= file.GetFileLength() + 0x10000000)
							{
								if (debug_mode) printf("-> push 0x%010" "llx" "\n", runtime_address);
								uintptr_t new_call_address = 0;
								new_call_address = calculate_rva(absolute_addr - 0x10000000, blocks, true);
								if (new_call_address != 0xdeadc0de)
								{
									WriteProcessMemory
									(
										game::process,
										(LPVOID)delta_address,
										&new_call_address,
										0x4,
										NULL
									);
								}
								find_inst = true;
							}
						}

						if (instruction.opcode == 0xC7)  // mov [shit_addres], 1
						{
							if (show_asm) { printf(buffer); printf("\n"); }
							uintptr_t absolute_addr = 0;
							uintptr_t delta_address = runtime_address + 0x2;
							ReadProcessMemory
							(
								game::process,
								(LPVOID)delta_address,
								&absolute_addr,
								0x4,
								NULL
							);
							if (absolute_addr >= 0x10000000 && absolute_addr <= file.GetFileLength() + 0x10000000)
							{
								if (debug_mode) printf("-> shit mov 0x%010" "llx" "\n", runtime_address);
								uintptr_t new_call_address = 0;
								new_call_address = calculate_rva(absolute_addr - 0x10000000, blocks, false);
								if (new_call_address != 0xdeadc0de)
								{
									WriteProcessMemory
									(
										game::process,
										(LPVOID)delta_address,
										&new_call_address,
										0x4,
										NULL
									);
								}
								find_inst = true;
							}
						}

						if (instruction.operands->type == ZYDIS_OPERAND_TYPE_MEMORY && instruction.operands->type != ZYDIS_OPERAND_TYPE_REGISTER)
						{
							ZyanU64 absolute_addr = 0;
							ZydisCalcAbsoluteAddress(&instruction, instruction.operands, runtime_address, &absolute_addr);
							if (absolute_addr >= 0x10000000 && absolute_addr <= file.GetFileLength() + 0x10000000)
							{
								if (instruction.mnemonic == ZydisMnemonic_::ZYDIS_MNEMONIC_CALL || instruction.mnemonic == ZydisMnemonic_::ZYDIS_MNEMONIC_INC || 
									instruction.mnemonic == ZydisMnemonic_::ZYDIS_MNEMONIC_MOV || instruction.mnemonic == ZydisMnemonic_::ZYDIS_MNEMONIC_CMP || 
									instruction.mnemonic == ZydisMnemonic_::ZYDIS_MNEMONIC_AND || instruction.mnemonic == ZydisMnemonic_::ZYDIS_MNEMONIC_JMP
									|| instruction.mnemonic == ZydisMnemonic_::ZYDIS_MNEMONIC_POP || instruction.mnemonic == ZydisMnemonic_::ZYDIS_MNEMONIC_OR)
								{
									if (instruction.opcode == 0xA1 || instruction.opcode == 0xA3 || instruction.opcode == 0xA2)  // if opcode size == 0x1
									{
										if (debug_mode) printf("-> memory 0x%010" "llx" "\n", runtime_address);
										if (runtime_address >= block_base_address + 0xfff - 0x5) { goto next_stage; }
										if (absolute_addr == 0xcccccccccccccccc) { goto next_stage; }
										if (absolute_addr < 0x10000000) { goto next_stage; }
										if (absolute_addr > block_base_address || absolute_addr < block_base_address)
										{
											if (runtime_address >= block_base_address + 0xfff - 0x5) { goto next_stage; }
											if (absolute_addr == 0xcccccccccccccccc) { goto next_stage; }
											if (absolute_addr < 0x10000000) { goto next_stage; }
											uintptr_t new_call_address = 0;
											new_call_address = calculate_rva(absolute_addr - 0x10000000, blocks, false);
											uintptr_t delta_address = runtime_address + 0x1;
											if (new_call_address != 0xdeadc0de)
											{
												WriteProcessMemory
												(
													game::process,
													(LPVOID)delta_address,
													&new_call_address,
													0x4,
													NULL
												);
											}
											find_inst = true;
										}
									}
									else  // if opcode size == 0x2
									{
										if (debug_mode) printf("-> memory 0x%010" "llx" "\n", runtime_address);
										if (runtime_address >= block_base_address + 0xfff - 0x5) { goto next_stage; }
										if (absolute_addr == 0xcccccccccccccccc) { goto next_stage; }
										if (absolute_addr < 0x10000000) { goto next_stage; }
										if (absolute_addr > block_base_address || absolute_addr < block_base_address)
										{
											if (runtime_address >= block_base_address + 0xfff - 0x5) { goto next_stage; }
											if (absolute_addr == 0xcccccccccccccccc) { goto next_stage; }
											if (absolute_addr < 0x10000000) { goto next_stage; }
											uintptr_t new_call_address = 0;
											new_call_address = calculate_rva(absolute_addr - 0x10000000, blocks, false);
											uintptr_t delta_address = runtime_address + 0x2;
											if (new_call_address != 0xdeadc0de)
											{
												WriteProcessMemory
												(
													game::process,
													(LPVOID)delta_address,
													&new_call_address,
													0x4,
													NULL
												);
											}
											find_inst = true;
										}
									}
								}
							}
						}

						if (instruction.mnemonic == ZydisMnemonic_::ZYDIS_MNEMONIC_CALL || instruction.mnemonic == ZydisMnemonic_::ZYDIS_MNEMONIC_INC  ||
							instruction.mnemonic == ZydisMnemonic_::ZYDIS_MNEMONIC_MOV  || instruction.mnemonic == ZydisMnemonic_::ZYDIS_MNEMONIC_CMP  ||
							instruction.mnemonic == ZydisMnemonic_::ZYDIS_MNEMONIC_AND  || instruction.mnemonic == ZydisMnemonic_::ZYDIS_MNEMONIC_JMP  || 
							instruction.mnemonic == ZydisMnemonic_::ZYDIS_MNEMONIC_POP  && instruction.operands->type == ZYDIS_OPERAND_TYPE_MEMORY)
						{
							if (instruction.opcode == 0xA1 || instruction.opcode == 0xA3 || instruction.opcode == 0xA2)  // if opcode size == 0x1
							{
								uintptr_t absolute_addr = 0;
								uintptr_t delta_address = runtime_address + 0x1;
								ReadProcessMemory
								(
									game::process,
									(LPVOID)delta_address,
									&absolute_addr,
									0x4,
									NULL
								);
								if (debug_mode) printf("-> not memory 0x%010" "llx" "\n", runtime_address);
								if (runtime_address >= block_base_address + 0xfff - 0x5) { goto next_stage; }
								if (absolute_addr == 0xcccccccccccccccc) { goto next_stage; }
								if (absolute_addr < 0x10000000) { goto next_stage; }
								if (absolute_addr > block_base_address || absolute_addr < block_base_address)
								{
									if (runtime_address >= block_base_address + 0xfff - 0x5) { goto next_stage; }
									if (absolute_addr == 0xcccccccccccccccc) { goto next_stage; }
									if (absolute_addr < 0x10000000) { goto next_stage; }
									uintptr_t new_call_address = 0;
									new_call_address = calculate_rva(absolute_addr - 0x10000000, blocks, false);
									uintptr_t delta_address = runtime_address + 0x1;
									if (new_call_address != 0xdeadc0de)
									{
										WriteProcessMemory
										(
											game::process,
											(LPVOID)delta_address,
											&new_call_address,
											0x4,
											NULL
										);
									}
									find_inst = true;
								}
							}
							else  // if opcode size == 0x2
							{
								uintptr_t absolute_addr = 0;
								uintptr_t delta_address = runtime_address + 0x2;
								ReadProcessMemory
								(
									game::process,
									(LPVOID)delta_address,
									&absolute_addr,
									0x4,
									NULL
								);
								if (debug_mode) printf("-> not memory 0x%010" "llx" "\n", runtime_address);
								if (runtime_address >= block_base_address + 0xfff - 0x5) { goto next_stage; }
								if (absolute_addr == 0xcccccccccccccccc) { goto next_stage; }
								if (absolute_addr < 0x10000000) { goto next_stage; }
								if (absolute_addr > block_base_address || absolute_addr < block_base_address)
								{
									if (runtime_address >= block_base_address + 0xfff - 0x5) { goto next_stage; }
									if (absolute_addr == 0xcccccccccccccccc) { goto next_stage; }
									if (absolute_addr < 0x10000000) { goto next_stage; }
									uintptr_t new_call_address = 0;
									new_call_address = calculate_rva(absolute_addr - 0x10000000, blocks, false);
									uintptr_t delta_address = runtime_address + 0x2;
									if (new_call_address != 0xdeadc0de)
									{
										WriteProcessMemory
										(
											game::process,
											(LPVOID)delta_address,
											&new_call_address,
											0x4,
											NULL
										);
									}
									find_inst = true;
								}
							}
						}

						if (find_inst)
						{
next_stage:					offset += instruction.length;
							runtime_address += instruction.length;
							find_inst = false;
						}
						else
						{
  					        offset = offset + 0x1;
							runtime_address = runtime_address + 0x1;
						}
						if (runtime_address - (uintptr_t)block_base_address >= 0x1000)
							goto delete_block;
					}
				
delete_block:       // delete block
					calculate_blocks.pop_back();
					calculate_block_size = calculate_block_size + 0x1000;
					i++;
				}

				succes = true;
			}
		}

end_function:   printf("mapped!\n");

	}
}