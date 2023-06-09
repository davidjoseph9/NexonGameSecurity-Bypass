#include "../Patch/PatchManager.h"
#include "../Patch/Patch.h"
#include "BlackCall.h"

#include <string>
#include <chrono>
#include <filesystem>
#include <sstream>
#include <iostream>
#include <fstream>

#include <Windows.h>

#include <Psapi.h>
#include <TlHelp32.h>


#define ASM_BUFF_SIZE 2048
#define FILENAME_BUFF_SIZE 2048

using namespace Patch;

namespace BlackCall {
	unsigned int MAX_IPC_FILE_WAITTIME = 60; // secs to wait for IPC file created by BlackCipher64 process
	unsigned int MAX_NTDLLCOPY_WAITTIME = 30; // secs to wait for ntdll copy module to load

	LPCWSTR BLACKCIPHER64 = L"BlackCipher64.aes";
	LPCWSTR BLACKCALL64 = L"BlackCall64.aes";
	LPCWSTR MAPLESTORY_MODULE = L"maplestory.exe";
	LPCWSTR NTDLL_MODULE = L"ntdll.dll";

	PatchManager patchManager = PatchManager();
	char asmBuffer[ASM_BUFF_SIZE];

	string ipcDir;
	string ipcFileContent;

	HMODULE hMapleStory = NULL;
	HMODULE hNtdll = NULL;

	unsigned int* blackCipherPid = NULL;


	unsigned __int64 bcAPIOverwriteRoutineOffset = 0x9FE883;
	unsigned __int64 bcAPIOverwriteRoutineRetOffset = 0x9FE894;

	unsigned __int64 bcMemoryCheck1Offset = 0x141BE7;
	unsigned __int64 bcMemoryCheck1RetOffset = 0x141BF4;

	unsigned __int64 bcMemoryCheck2Offset = 0x136810;
	unsigned __int64 bcMemoryCheck2RetOffset = 0x13681D;

	unsigned __int64 bcMemoryCheck3Offset = 0x136A44;
	unsigned __int64 bcMemoryCheck3CallOffset = 0x137000;
	unsigned __int64 bcMemoryCheck3RetOffset = 0x136A51;

	unsigned __int64 bcMemoryCheck4Offset = 0xB7CB58;
	unsigned __int64 bcMemoryCheck4RetOffset = 0xB7CB69;

	unsigned __int64 bcDebuggerCheck1Offset = 0x22C6D4;
	unsigned __int64 bcDebuggerCheck2Offset = 0x22D08C;
	unsigned __int64 bcDebuggerCheck3Offset = 0x233C00;

	unsigned __int64 blackCipherCopyAddr = NULL;
	unsigned __int64 blackCallCopyAddr = NULL;
	unsigned __int64 bcNtdllCopyAddr = NULL;

	MODULEENTRY32W bcNtdllModuleEntry;
	MODULEENTRY32W blackCallModuleEntry;
	MODULEENTRY32W blackCipherModuleEntry;

	std::string asmReturnFalse = Patch::unindent(R"(
        xor rax, rax
		ret
	)");

	std::string bcNtReadVirtualMemoryAsm = Patch::unindent(R"(
		push rbx
        push rcx
        push rdx

        push rsi
        push rdi

        push r8
        push r9
        push r10
        push r11
        push r12
        push r13
        push r14
        push r15
        
        sub rsp, 0x30
        mov rax, 0x%llX
        call rax
        add rsp, 0x30
		
        pop r15
        pop r14
        pop r13
        pop r12
        pop r11
        pop r10
        pop r9
        pop r8
		
		pop rdi
        pop rsi

        pop rdx
        pop rcx
        pop rbx

        cmp rax, -1
        mov rdx, rax
        jne NtReadVirtualMemory
        ret

	    NtReadVirtualMemory:
        mov rdx, rax
        mov r10, rcx
        mov eax, 0x0000003F
        syscall
		ret
	)");
	unsigned __int64 WINAPI BCNtReadVirtualMemoryFilter(HANDLE hProcess, LPCVOID lpBaseAddress) {//, SIZE_T numberOfBytesToRead, SIZE_T* lpNumberOfBytesRead) {
		DWORD targetPid = GetProcessId(hProcess);

		wprintf(L"[BCXXXX/NTDLL.NtReadVirtualMemory] pid = 0x%X, lpBaseAddress = 0x%llX\n", 
			targetPid, (unsigned __int64)lpBaseAddress);

		if (targetPid == GetCurrentProcessId()) {
			if ((unsigned __int64)lpBaseAddress == (unsigned __int64)hMapleStory) {
				printf("[BCXXXX/NTDLL.NtReadVirtualMemory] Denying access to maplestory.exe\n");
				SetLastError(STATUS_ACCESS_DENIED);
				return -1;
			}
			else if (lpBaseAddress >= blackCallModuleEntry.modBaseAddr &&
					lpBaseAddress <= blackCallModuleEntry.modBaseAddr + blackCallModuleEntry.modBaseSize) {

				unsigned __int64 copyOffset = (unsigned __int64)lpBaseAddress - (unsigned __int64)blackCallModuleEntry.modBaseAddr;
				wprintf(L"[BCXXXX/NTDLL.NtReadVirtualMemory] Reading from %s, replacing original address 0x%llX with copy address 0x%llX\n",
					blackCallModuleEntry.szModule, (unsigned __int64)lpBaseAddress, blackCallCopyAddr + copyOffset);

				return blackCallCopyAddr + copyOffset;
			}
			else if ((unsigned __int64)lpBaseAddress == (unsigned __int64)bcNtdllCopyAddr) {
				printf("[BCXXXX/NTDLL.NtReadVirtualMemory] Denying access to BCXXXX.tmp ntdll copy\n");
				SetLastError(STATUS_ACCESS_DENIED);
				return -1;
			}
		}
		else if (targetPid == *blackCipherPid) {
			if (lpBaseAddress >= blackCipherModuleEntry.modBaseAddr &&
				lpBaseAddress <= blackCipherModuleEntry.modBaseAddr + blackCipherModuleEntry.modBaseSize) {

				unsigned __int64 copyOffset = (unsigned __int64)lpBaseAddress - (unsigned __int64)blackCipherModuleEntry.modBaseAddr;
				wprintf(L"[BCXXXX/NTDLL.NtReadVirtualMemory] Reading from %s, replacing original address 0x%llX with copy address 0x%llX\n", 
					blackCipherModuleEntry.szModule, (unsigned __int64)lpBaseAddress, blackCipherCopyAddr + copyOffset);

				return blackCipherCopyAddr + copyOffset;
			}
		}
		return (unsigned __int64)lpBaseAddress;
	}

	bool InstallBCNtReadVirtualMemoryHook(PatchManager& patchManager) {
		Patch::PatchManager::Patch patch;

		patch.name = "BCXXX/BlackCall64/ntdll.NtReadVirtualMemory hook";
		patch.address = (unsigned __int64)GetProcAddress((HMODULE)bcNtdllModuleEntry.modBaseAddr, "NtReadVirtualMemory");
		if (patch.address == NULL) {
			printf("Failed to get proc address of NtReadVirtualMemory\n");
			return false;
		}
		patch.address += 0x8;
		sprintf_s(asmBuffer, bcNtReadVirtualMemoryAsm.c_str(), &BCNtReadVirtualMemoryFilter);

		patch.patchType = PatchManager::PatchType::HOOK;
		patch.hookType = PatchManager::HookType::JUMP;
		
		patch.assembly = std::string(asmBuffer);
		patch.hookRegister = "rax";
		patch.nopCount = 0;

		return patchManager.InstallPatch(true, patch);
	}


	std::string APIRestoreRoutine1Asm = Patch::unindent(R"(
        mov rax, 0x7FF000000000
		cmp r14, rax
		jg Exit
		mov [r14], r12

		Exit:
        movzx r10, word ptr [r11]
        mov r15, rbp
        add r15, 0x00000000
        mov rax, 0x%llX
		jmp rax
	)");

	void InstallAPIRestoreRoutinePatch(PatchManager& patchManager) {
		/*
		 * Install patch to bypass routine that periodically 
		 * restores the memory of the ntdll.dll copy
		 */
		Patch::PatchManager::Patch patch;

		patch.name = "BC API Restore Routine";
		patch.address = (unsigned __int64)blackCallModuleEntry.modBaseAddr + bcAPIOverwriteRoutineOffset;
		sprintf_s(asmBuffer, APIRestoreRoutine1Asm.c_str(), 
			(unsigned __int64)blackCallModuleEntry.modBaseAddr + bcAPIOverwriteRoutineRetOffset);
		patch.patchType = PatchManager::PatchType::HOOK;
		patch.hookType = PatchManager::HookType::JUMP;
		
		patch.assembly = std::string(asmBuffer);
		patch.hookRegister = "rax";
		patch.nopCount = 0;

		patchManager.InstallPatch(true, patch);
	}

	std::string bcMemoryCheck1Asm = Patch::unindent(R"(
        mov rax, [rsp+0x20]
        mov rax, [rax]

        mov r8, 0x%llX
		cmp rax, r8
		jl Exit
		add r8, 0x%llX
		cmp rax, r8
		jg Exit
        mov r8, 0x%llX
		sub rax, r8
		mov r8, 0x%llX
		add rax, r8
        mov r8, [rsp+0x20]
        mov [r8], rax

		Exit:
		mov eax,[rax]
		mov ecx,[rsp]
        mov r8, 0x%llX
		jmp r8
	)");

	bool InstallBCMemoryCheck1Hook(PatchManager& patchManager) {
		/*
		 * Install patch to bypass memory integrity check that
		 * checks the integrity of the ntdll.dll copy
		 */
		Patch::PatchManager::Patch patch;

		patch.name = "BC Memory Integrity check 1";
		patch.address = (unsigned __int64)blackCallModuleEntry.modBaseAddr + bcMemoryCheck1Offset;
		sprintf_s(
			asmBuffer,
			bcMemoryCheck1Asm.c_str(),
			(unsigned __int64)bcNtdllModuleEntry.modBaseAddr,
			bcNtdllModuleEntry.modBaseSize,
			(unsigned __int64)bcNtdllModuleEntry.modBaseAddr,
			bcNtdllCopyAddr,
			(unsigned __int64)blackCallModuleEntry.modBaseAddr + bcMemoryCheck1RetOffset
		);
		patch.patchType = PatchManager::PatchType::HOOK;
		patch.hookType = PatchManager::HookType::JUMP;

		patch.assembly = std::string(asmBuffer);
		patch.hookRegister = "r8";
		patch.nopCount = 0;

		return patchManager.InstallPatch(true, patch);
	}

	std::string bcMemoryCheck2Asm = Patch::unindent(R"(
        mov r10, 0x%llX
        cmp rcx, r10
        jl Exit
        add r10, 0x%llX
        cmp rcx, r10
        jg Exit
        mov r10, 0x%llX
        sub rcx, r10
		mov r10, 0x%llX
        add rcx, r10

		Exit:
        sub rsp, 0x18
        mov r8d, edx
        mov r9, rcx
        test rcx, rcx
        mov r10, 0x%llX
		jmp r10
	)");

	bool InstallBCMemoryCheck2Hook(PatchManager& patchManager) {
		/*
		 * Install patch to bypass memory integrity check that 
		 * checks the integrity of the ntdll.dll copy
		 */
		Patch::PatchManager::Patch patch;

		patch.name = "BC Memory Integrity check 2";
		patch.address = (unsigned __int64)blackCallModuleEntry.modBaseAddr + bcMemoryCheck2Offset;

		sprintf_s(asmBuffer, bcMemoryCheck2Asm.c_str(),
			(unsigned __int64)bcNtdllModuleEntry.modBaseAddr,
			bcNtdllModuleEntry.modBaseSize,
			(unsigned __int64)bcNtdllModuleEntry.modBaseAddr,
			bcNtdllCopyAddr,
			(unsigned __int64)blackCallModuleEntry.modBaseAddr + bcMemoryCheck2RetOffset);

		patch.patchType = PatchManager::PatchType::HOOK;
		patch.hookType = PatchManager::HookType::JUMP;

		patch.name = "Memory Integrity check 2";
		patch.assembly = std::string(asmBuffer);
		patch.hookRegister = "r10";
		patch.nopCount = 0;

		return patchManager.InstallPatch(true, patch);
	}

	std::string bcMemoryCheck3Asm = Patch::unindent(R"(
        mov r10, 0x%llX
        cmp rdi, r10
        jl Exit
        add r10, 0x%llX
        cmp rdi, r10
        jg Exit
        mov r10, 0x%llX
        sub rdi, r10
		mov r10, 0x%llX
        add rdi, r10

		Exit:
        movzx ecx, byte ptr [rdi]
        lea rdx, [rsp+0x20]
        call 0x%llX
        mov r10, 0x%llX
		jmp r10
	)");

	bool InstallBCMemoryCheck3Hook(PatchManager& patchManager) {
		/*
		 * Install patch to bypass memory integrity check that reads
		 * the memory of a subset of methods in the BlackCall64.aes module
		 * checks the integrity check responsible for checking the
		 * integrity of the ntdll.dll copy
		 */
		Patch::PatchManager::Patch patch;

		patch.name = "BC Memory Integrity check 3";
		patch.address = (unsigned __int64)blackCallModuleEntry.modBaseAddr + bcMemoryCheck3Offset;
		sprintf_s(asmBuffer, bcMemoryCheck3Asm.c_str(),
			blackCallModuleEntry.modBaseAddr,
			blackCallModuleEntry.modBaseSize,
			blackCallModuleEntry.modBaseAddr,
			blackCallCopyAddr,
			(unsigned __int64)blackCallModuleEntry.modBaseAddr + bcMemoryCheck3CallOffset,
			(unsigned __int64)blackCallModuleEntry.modBaseAddr + bcMemoryCheck3RetOffset);

		patch.patchType = PatchManager::PatchType::HOOK;
		patch.hookType = PatchManager::HookType::JUMP;
;
		patch.assembly = std::string(asmBuffer);
		patch.hookRegister = "r10";
		patch.nopCount = 0;

		return patchManager.InstallPatch(true, patch);
	}

	std::string bcMemoryCheck4Asm = Patch::unindent(R"(
        mov rcx, 0x%llX
		cmp r8, rcx
		jl Exit
		add rcx, 0x%llX
		cmp r8, rcx
		jg Exit
        mov rcx, 0x%llX
		sub r8, rcx
		mov rcx, 0x%llX
		add r8, rcx

		Exit:
        mov r8d,[r8]
		add r13, 0x000000A9
        mov r12, 0x00000000
        mov rcx, 0x%llX
	    jmp rcx
	)");

	bool InstallBCMemoryCheck4Hook(PatchManager& patchManager) {
		/*
		 * Install patch to bypass memory integrity check that reads 
		 * the memory of a subset of methods in the BlackCall64.aes module
		 * checks the integrity check responsible for checking the
		 * integrity of the ntdll.dll copy
		 */
		Patch::PatchManager::Patch patch;

		patch.name = "BC Memory Integrity check 4";
		patch.address = (unsigned __int64)blackCallModuleEntry.modBaseAddr + bcMemoryCheck4Offset;
		sprintf_s(asmBuffer, bcMemoryCheck4Asm.c_str(),
			blackCallModuleEntry.modBaseAddr,
			blackCallModuleEntry.modBaseSize,
			blackCallModuleEntry.modBaseAddr,
			blackCallCopyAddr,
			(unsigned __int64)blackCallModuleEntry.modBaseAddr + bcMemoryCheck4RetOffset);

		patch.patchType = PatchManager::PatchType::HOOK;
		patch.hookType = PatchManager::HookType::JUMP;
		
		patch.assembly = std::string(asmBuffer);
		patch.hookRegister = "rcx";
		patch.nopCount = 0;

		return patchManager.InstallPatch(true, patch);
	}

	void LoadMapleStoryModules() {
		/*
		 * Load modules loaded in the MapleStory.exe process and add them to a list
		 * The list will later be used for the Module32FirstW and Module32NextW hook
		 * to iterate over a static list of modules.
		 * Create a copy of the BlackCall64.aes module if it's available,
		 * along with the ntdll.dll copy (BCXXXX.tmp) so they can be used in the memory
		 * integrity check bypass patches.
		 */
		HANDLE hModuleSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0);

		MODULEENTRY32W moduleEntry;
		moduleEntry.dwSize = sizeof(MODULEENTRY32W);

		if (Module32FirstW(hModuleSnapshot, &moduleEntry)) {
			// BlackCall64.aes and BCXXXX.tmp (ntdll) are never first
			do {
				if (blackCallCopyAddr == NULL && lstrcmpW(moduleEntry.szModule, BLACKCALL64) == 0) {
					memcpy((void*)&blackCallModuleEntry, (void*)&moduleEntry, sizeof(MODULEENTRY32W));
					blackCallCopyAddr = Patch::CopyModule((unsigned __int64)blackCallModuleEntry.modBaseAddr, (unsigned __int64)blackCallModuleEntry.modBaseSize);
					if (blackCallCopyAddr == NULL) {
						wprintf(L"Failed to copy the %s module\n", BLACKCALL64);
						break;
					}
					wprintf(L"Successfully created copy of %s 0x%llX\n", BLACKCALL64, blackCallCopyAddr);
				}
				else if (bcNtdllCopyAddr == NULL && endsWithW(moduleEntry.szModule, L".tmp")) {
					unsigned __int64 procAddress = (unsigned __int64)GetProcAddress(moduleEntry.hModule, "NtReadVirtualMemory");
					if (procAddress != NULL) {
						memcpy((void*)&bcNtdllModuleEntry, (void*)&moduleEntry, sizeof(MODULEENTRY32W));
						bcNtdllCopyAddr = Patch::CopyModule((unsigned __int64)bcNtdllModuleEntry.modBaseAddr, (unsigned __int64)bcNtdllModuleEntry.modBaseSize);
						if (bcNtdllCopyAddr == NULL) {
							printf("Failed to copy the BCXXXX.tmp (ntdll.dll copy)");
							break;
						}
					}
				}
			} while (Module32NextW(hModuleSnapshot, &moduleEntry));
		}
	}

	bool LoadBlackCipherModules() {
		/*
		 * Load modules loaded in the BlackCipher64.aes process and add them to a list
		 * The list will later be used for the Module32FirstW and Module32NextW hook
		 * to iterate over a static list of modules.
		 * Create a copy of the BlackCipher64.aes module if it's available so it can
		 * can later be used in the NtReadVirtualMemory hook to bypass the security modules
		 * integrity checks
		 */
		HANDLE hModuleSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, *blackCipherPid);

		MODULEENTRY32W moduleEntry;
		moduleEntry.dwSize = sizeof(MODULEENTRY32W);

		if (!Module32FirstW(hModuleSnapshot, &moduleEntry)) {
			return false;
		}

		if (lstrcmpW(moduleEntry.szModule, BLACKCIPHER64) == 0) {
			memcpy((void*)&blackCipherModuleEntry, (void*)&moduleEntry, sizeof(MODULEENTRY32W));
		}
		else {
			do {
				if (lstrcmpW(moduleEntry.szModule, BLACKCIPHER64) == 0) {
					memcpy((void*)&blackCipherModuleEntry, (void*)&moduleEntry, sizeof(MODULEENTRY32W));
					break;
				}
			} while (Module32NextW(hModuleSnapshot, &moduleEntry));
		}

		return true;
	}

	bool GenerateIPCFile() {
		/*
		 * Generate a file used to provide data required for the bypass to the BlackCipher64.aes process
		 * Includes the address of the BlackCall64.aes module copy 
		 */
		DWORD processId = GetCurrentProcessId();

		char lockedFileName[128];
		sprintf_s(lockedFileName, "%s/NGSBypass%X-2.lock", ipcDir.c_str(), processId);
		std::remove(lockedFileName); // delete file if exists
		printf("Generating IPC file %s\n", lockedFileName);
		char content[128];
		std::filesystem::path path{ lockedFileName };
		std::ofstream ofs(path);
		sprintf_s(content, "blackCall64Copy=0x%llX\n", blackCallCopyAddr);
		ofs << content;
		ofs.close();

		char unlockedFileName[128];
		sprintf_s(unlockedFileName, "%s/NGSBypass%X-2", ipcDir.c_str(), processId);
		std::remove(unlockedFileName); // delete file if exists

		if (std::rename(lockedFileName, unlockedFileName)) {
			printf("Error renaming IPC file\n");
			return false;
		}
		printf("IPC file %s renamed to %s\n", lockedFileName, unlockedFileName);

		return true;
	}

	void ReadIPCFile(char* fileName) {
		/*
		 * Read the data file generated by the BlackCipher64.aes process
		 * Contains the address to the BlackCipher64.aes module copy and the BlackCipher64.aes pid
		 */
		printf("Reading IPC file %s\n", fileName);
		string content = ReadTextFile(fileName);
		printf(content.c_str());
		vector<string> lines = Split(content.c_str(), '\n');
		for (auto line : lines) {
			vector<string> keyValuePair = Split(line.c_str(), '=');
			if (keyValuePair.size() == 2) {
				if (keyValuePair[0].compare("blackCipher64Copy") == 0) {
					std::stringstream ss;
					ss << std::hex << (const char*)keyValuePair[1].c_str() + 2;
					ss >> blackCipherCopyAddr;
					printf("BlackCipher64 0x%llX\n", blackCipherCopyAddr);
				}
				else if (keyValuePair[0].compare("pid") == 0) {
					std::stringstream ss;
					ss << std::hex << (const char*)keyValuePair[1].c_str() + 2;
		   			ss >> *blackCipherPid;
					printf("BlackCipher PID 0x%X\n", *blackCipherPid);
				}
			}

		}
	}

	bool WaitForIPCFile() {
		/*
		 * Wait until the IPC file generated by the BlackCipher64.aes module becomes available
		 * then read it or wait until the time elapsed exceeds the allotted time
		 */
		DWORD processId = GetCurrentProcessId();

		char fileName[64];
		sprintf_s(fileName, "%s/NGSBypass%X-1", ipcDir.c_str(), processId);

		std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();
		bool timedout = false;
		while (!timedout) {
			timedout = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - start).count() > MAX_IPC_FILE_WAITTIME;
			try {
				ifstream f(fileName);
				if (!f.good()) continue;
				f.close();
				ReadIPCFile(fileName);
				timedout = false;
				break;
			}
			catch (const std::filesystem::filesystem_error& err) {
				printf("%s\n", err.what());
				return false;
			}
			Sleep(50);
		}

		if (timedout) {
			printf("Timed out while waiting for the IPC file %s\n", fileName);
			return false;
		}

		std::filesystem::remove(fileName);

		return true;
	}

	bool InstallPatches(unsigned int* bcPid) {
		/*
		 * Install patches related to the BlackCall64.aes module
		 */
		blackCipherPid = bcPid;
		patchManager.Setup();

		hMapleStory = GetModuleHandleW(MAPLESTORY_MODULE);
		if (hMapleStory == NULL) {
			wprintf(L"Failed to get handle of the module %s\n", MAPLESTORY_MODULE);
			return false;
		}

		hNtdll = GetModuleHandleW(NTDLL_MODULE);
		if (hNtdll == NULL) {
			wprintf(L"Failed to get handle of the module %s\n", NTDLL_MODULE);
			return false;
		}

		ipcDir = getenv("appdata") + string("/NGSBypass");
		if (!std::filesystem::exists(ipcDir))
		{
			if (!filesystem::create_directory(ipcDir))
			{
				printf("Failed to create IPC dir %s\n", ipcDir.c_str());
				return false;
			}
		}

		if (!WaitForIPCFile()) {
			printf("Wait for IPC file failed\n");
			return false;
		}

		unsigned int counter = 0;
		do {
			LoadMapleStoryModules();
			Sleep(100);
		} while ((blackCallCopyAddr == NULL || bcNtdllCopyAddr == NULL) && counter++ < MAX_NTDLLCOPY_WAITTIME * 10);

		if (blackCallCopyAddr == NULL || bcNtdllCopyAddr == NULL) {
			wprintf(L"Failed retrieving handle of BlackCall64's ntdll copy (BCXXXX.tmp)");
			return false;
		}

		LoadBlackCipherModules();

		GenerateIPCFile();

		unsigned int threadId = GetCurrentThreadId();
		SuspendProcessThreads(threadId);

		InstallAPIRestoreRoutinePatch(patchManager);

		bool success = InstallBCMemoryCheck1Hook(patchManager) &&
			InstallBCMemoryCheck2Hook(patchManager) &&
			InstallBCMemoryCheck3Hook(patchManager) &&
			InstallBCMemoryCheck4Hook(patchManager);

		if (!success) {
			printf("Failed to install BlackCall64 memory integrity check patches\n");
			return false;
		}

		if (!InstallBCNtReadVirtualMemoryHook(patchManager)) {
			return false;
		}

		//InstallDebuggerCheckPatches(patchManager);

		ResumeProcessThreads(threadId);

		return true;
	}
}
