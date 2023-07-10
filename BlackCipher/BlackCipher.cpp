#include "../Patch/Patch.h"
#include "../Patch/PatchManager.h"
#include "../BlackCipher/BlackCipher.h"
#include "../MapleStory/MapleStory.h"

#include <vector>
#include <string>
#include <map>
#include <list>
#include <fstream>
#include <iostream>
#include <sstream>
#include <chrono>
#include <filesystem>

#include <TlHelp32.h>
#include <Psapi.h>

using namespace Patch;


namespace BlackCipher {
	LPCWSTR MAPLESTORY = L"maplestory.exe";
	LPCWSTR BLACKCIPHER64 = L"BlackCipher64.aes";
	LPCWSTR BLACKCALL64 = L"BlackCall64.aes";

	LPCWSTR USER32_DLL = L"USER32.DLL";
	LPCWSTR KERNELBASE_DLL = L"KERNELBASE.DLL";
	LPCWSTR NTDLL_DLL = L"ntdll.dll";
	LPCWSTR KERNEL32_DLL = L"KERNEL32.DLL";

	unsigned int MAX_IPC_FILE_WAITTIME = 60; // secs to wait for IPC file created by BlackCipher64 process
	unsigned int MAX_NTDLLCOPY_WAITTIME = 60; // secs to wait for ntdll copy module to load

	PatchManager patchManager = Patch::PatchManager();

	char asmBuffer[2048];

	HMODULE hNtdll = NULL;
	HMODULE hNtdllCopy = NULL; // BCXXXX.tmp
	HMODULE hKernelbase = NULL;
	HMODULE hKernel32 = NULL;

	string ipcDir;
	char ipcFileName[255];

	unsigned __int64 bcNtdllCopyAddress = NULL;
	unsigned __int64 blackCipherCopyAddr = NULL;

	// List of modules to filter for static list of modules created at the start
	// used in the Module32FirstW and Module32NextW hooks
	std::list<std::wstring> moduleExclusionList = { L"keystone.dll", L"MapleNGSBypass.dll",  L"vehdebug-x86_64.dll" }; // maplestory also excluded

	PROCESSENTRY32W processEntry{ 0 };

	std::list<MODULEENTRY32W> blackcipherModuleList;
	std::list<MODULEENTRY32W>::iterator blackcipherIterator;
	std::list<MODULEENTRY32W> maplestoryModuleList;
	std::list<MODULEENTRY32W>::iterator maplestoryIterator;

	MODULEENTRY32W blackCipherModuleEntry{ 0 };
	MODULEENTRY32W blackCallModuleEntry{ 0 };
	MODULEENTRY32W maplestoryModuleEntry{ 0 };
	MODULEENTRY32W bcNtdllModuleEntry{ 0 };

	unsigned __int64 rtlCaptureContextPtr = 0x006FF648;

	unsigned __int64 bcAPIRestoreRoutineAddress = 0x00D0C9F4;
	unsigned __int64 bcAPIRestoreRoutineRetAddress = 0x00D0CA01;

	unsigned __int64 bcMemoryCheck1Address = 0x0045B9D9;
	unsigned __int64 bcMemoryCheck1RetAddress = 0x0045B9EB;

	unsigned __int64 bcMemoryCheck2Address = 0x009C2CD7;
	unsigned __int64 bcMemoryCheck2RetAddress = 0x009C2CE3;

	unsigned __int64 bcMemoryCheck3Address = 0x004F8CC7;
	unsigned __int64 bcMemoryCheck3RetAddress = 0x004F8CD4;

	unsigned __int64 bcMemoryCheck4Address = 0x00A36408;
	unsigned __int64 bcMemoryCheck4RetAddress = 0x00A3641C;

	unsigned __int64 bcMemoryCheck5Address = 0x004F3D0B;
	unsigned __int64 bcMemoryCheck5RetAddress = 0x004F3D17;

	unsigned __int64 bcMemoryCheck6Address = 0x00ADC7A0;
	unsigned __int64 bcMemoryCheck6RetAddress = 0x00ADC7AB;
	
	unsigned __int64 blackCallCopyAddr = NULL;

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
	unsigned __int64 WINAPI BCNtReadVirtualMemoryFilter(HANDLE hProcess, unsigned __int64 lpBaseAddress) {//, SIZE_T numberOfBytesToRead, SIZE_T* lpNumberOfBytesRead) {
		DWORD targetProcessId = GetProcessId(hProcess);
		wprintf(L"[BCXXXX/NTDLL.NtReadVirtualMemory] pid = %X, lpBaseAddress = '%llX'\n", (unsigned int)targetProcessId, (unsigned __int64)lpBaseAddress);
		
		if (targetProcessId == GetCurrentProcessId()) {
			if (lpBaseAddress >= (unsigned __int64)blackCipherModuleEntry.modBaseAddr &&
				lpBaseAddress <= (unsigned __int64)blackCipherModuleEntry.modBaseAddr + blackCipherModuleEntry.modBaseSize) {
				unsigned __int64 copyOffset = (unsigned __int64)lpBaseAddress - (unsigned __int64)blackCipherModuleEntry.modBaseAddr;
				wprintf(L"Reading from %s, replacing original 0x%llX with copy 0x%llX\n",
					blackCipherModuleEntry.szModule, (unsigned __int64)lpBaseAddress, blackCipherCopyAddr + copyOffset);
				return blackCipherCopyAddr + copyOffset;
			}
		}
		else if (targetProcessId == processEntry.th32ParentProcessID) {
			if (lpBaseAddress >= (unsigned __int64)blackCallModuleEntry.modBaseAddr &&
				lpBaseAddress <= (unsigned __int64)blackCallModuleEntry.modBaseAddr + blackCallModuleEntry.modBaseSize) {
				unsigned __int64 copyOffset = (unsigned __int64)lpBaseAddress - (unsigned __int64)blackCallModuleEntry.modBaseAddr;
				wprintf(L"Reading from %s, replacing original address 0x%llX with copy address 0x%llX\n",
					blackCallModuleEntry.szModule, (unsigned __int64)lpBaseAddress, blackCallCopyAddr + copyOffset);
				return blackCallCopyAddr + copyOffset;
			}
			else if (lpBaseAddress == (unsigned __int64)maplestoryModuleEntry.modBaseAddr) {
				printf("[BCXXXX/NTDLL.NtReadVirtualMemory] Denying access to maplestory.exe module\n");
				SetLastError(STATUS_ACCESS_DENIED);
				return -1;
			}
		}
		return (unsigned __int64)lpBaseAddress;
	}

	bool InstallBCNtReadVirtualMemoryHook(PatchManager& patchManager) {
		Patch::PatchManager::Patch patch;

		patch.address = (unsigned __int64)GetProcAddress((HMODULE)bcNtdllModuleEntry.modBaseAddr, "NtReadVirtualMemory");
		if (patch.address == NULL) {
			printf("Failed to get proc address of NtReadVirtualMemory");
			return false;
		}
		patch.address += 0x8;

		sprintf_s(asmBuffer, bcNtReadVirtualMemoryAsm.c_str(), &BCNtReadVirtualMemoryFilter);

		patch.patchType = PatchManager::PatchType::HOOK;
		patch.hookType = PatchManager::HookType::JUMP;
		patch.name = "BCXXXX.tmp/ntdll.NtReadVirtualMemory hook";
		patch.assembly = std::string(asmBuffer);
		patch.hookRegister = "rax";
		patch.nopCount = 0;

		patchManager.InstallPatch(true, patch);

		return true;
	}

	std::string bcNtOpenProcessAsm = Patch::unindent(R"(
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
        
        sub rsp, 0x20
        
        mov rcx, [r9]
        mov rax, 0x%llX
        call rax

        add rsp, 0x20
		
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

        test rax, rax
        jne NtOpenProcess
		xor rax, rax
        ret

	    NtOpenProcess:
        mov r10, rcx
        mov eax, 0x00000026
        syscall
		ret
	)");
	bool WINAPI NtOpenProcessHook(DWORD pid) {
		wprintf(L"[BCXXXX/NTDLL.NtOpenProcess] pid = %X\n", pid);
		if (pid == 0 || pid == processEntry.th32ProcessID || pid == processEntry.th32ParentProcessID) {
			printf("Allow access to NtOpenProcess for MapleStory or BlackCipher process 0x%X\n", pid);
			return true;
		}
		else {
			printf("Denying access to NtOpenProcess for the process 0x%X\n", pid);
			SetLastError(ERROR_ACCESS_DENIED);
			return false;
		}
	}

	bool InstallBCNtOpenProcessHook(PatchManager& patchManager) {
		Patch::PatchManager::Patch patch1;

		patch1.address = (unsigned __int64)GetProcAddress(hNtdll, "NtOpenProcess");
		if (patch1.address == NULL) {
			printf("Failed to get proc address of NtReadVirtualMemory");
			return false;
		}
		patch1.address += 0x8;

		sprintf_s(asmBuffer, bcNtOpenProcessAsm.c_str(), &NtOpenProcessHook);

		patch1.patchType = PatchManager::PatchType::HOOK;
		patch1.hookType = PatchManager::HookType::JUMP;
		patch1.name = "ntdll.NtOpenProcess hook";
		patch1.assembly = std::string(asmBuffer);
		patch1.hookRegister = "rax";
		patch1.nopCount = 0;

		patchManager.InstallPatch(true, patch1);

		Patch::PatchManager::Patch patch2;

		patch2.address = (unsigned __int64)GetProcAddress((HMODULE)bcNtdllModuleEntry.modBaseAddr, "NtOpenProcess");
		if (patch2.address == NULL) {
			printf("Failed to get proc address of NtOpenProcess");
			return false;
		}
		patch2.address += 0x8;

		sprintf_s(asmBuffer, bcNtOpenProcessAsm.c_str(), &NtOpenProcessHook);

		patch2.patchType = PatchManager::PatchType::HOOK;
		patch2.hookType = PatchManager::HookType::JUMP;
		patch2.name = "BCXXX/BlackCipher64/ntdll.NtOpenProcess hook";
		patch2.assembly = std::string(asmBuffer);
		patch2.hookRegister = "rax";
		patch2.nopCount = 0;

		patchManager.InstallPatch(true, patch2);
		return true;
	}
	
	std::string bcNtQuerySystemInformationAsm = Patch::unindent(R"(
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
        
        sub rsp, 0x20
        
        mov rax, 0x%llX
        call rax

        add rsp, 0x20
		
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

		xor rax, rax
        ret
	)");
	NTSTATUS WINAPI NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass,
			PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength) {
		wprintf(L"[BCXXXX/NTDLL.NtQuerySystemInformation] SystemInformationClass = 0x%X\n", SystemInformationClass);
		memset(SystemInformation, 0, SystemInformationLength);

		if (ReturnLength != NULL)
			*ReturnLength = 0;

		return STATUS_ACCESS_DENIED;
	}

	bool InstallBCNtQuerySystemInformationHook(PatchManager& patchManager) {
		Patch::PatchManager::Patch patch;

		patch.address = (unsigned __int64)GetProcAddress((HMODULE)bcNtdllModuleEntry.modBaseAddr, "NtQuerySystemInformation");
		if (patch.address == NULL) {
			printf("Failed to get procedure address of NtQuerySystemInformation");
			return false;
		}
		patch.address += 0x8;
		sprintf_s(asmBuffer, bcNtQuerySystemInformationAsm.c_str(), &NtQuerySystemInformation, STATUS_ACCESS_DENIED);
		patch.patchType = PatchManager::PatchType::HOOK;
		patch.hookType = PatchManager::HookType::JUMP;
		patch.name = "BCXXX.tmp/ntdll.NtQuerySystemInformation hook";
		patch.assembly = std::string(asmBuffer);
		patch.hookRegister = "rax";
		patch.nopCount = 0;

		patchManager.InstallPatch(true, patch);
		return true;
	}

	std::string APIRestoreRoutineAsm = Patch::unindent(R"(
        mov r9, 0x7FF000000000
		cmp r11, r9
		jg Exit
		mov [r11], rax

		Exit:
        mov r9, rbp
        add r9, 0x00000051
        mov rdx, 0x%llX
		jmp rdx
	)");

	bool InstallAPIRestoreRoutinePatch(PatchManager& patchManager) {
		/*
		 * Install patch to bypass routine that periodically
		 * restores the memory of the ntdll.dll copy
		 */
		Patch::PatchManager::Patch patch;

		patch.name = "BC API Restore Routine";

		patch.address = bcAPIRestoreRoutineAddress;
		sprintf_s(asmBuffer, APIRestoreRoutineAsm.c_str(), bcAPIRestoreRoutineRetAddress);

		patch.patchType = PatchManager::PatchType::HOOK;
		patch.hookType = PatchManager::HookType::JUMP;
		
		patch.assembly = std::string(asmBuffer);
		patch.hookRegister = "rdx";
		patch.nopCount = 0;

		return patchManager.InstallPatch(true, patch);
	}

	std::string bcMemoryCheck1Asm = Patch::unindent(R"(
        mov rax, 0x%llX
		cmp r9, rax
		jl Exit
		add rax, 0x%llX
		cmp r9, rax
		jg Exit
        mov rax, 0x%llX
		sub r9, rax
		add r9, 0x%llX

		Exit:
        mov r9,[r9]
		mov [rsp+0x30],r8
        lea r8,[rsp+0x30]
        mov [rsp+0x38],rbx
        mov rax, 0x%llX
		jmp rax
	)");

	bool InstallAPIMemoryCheck1Patch(PatchManager& patchManager) {
		/*
		 * Install patch to bypass memory integrity check that
		 * checks the integrity of the ntdll.dll copy
		 */
		Patch::PatchManager::Patch patch;

		patch.name = "BC API Memory Check 1";
		patch.address = bcMemoryCheck1Address;
		sprintf_s(asmBuffer, bcMemoryCheck1Asm.c_str(), bcNtdllModuleEntry.modBaseAddr,
			bcNtdllModuleEntry.modBaseSize, bcNtdllModuleEntry.modBaseAddr,
			bcNtdllCopyAddress, bcMemoryCheck1RetAddress);

		patch.patchType = PatchManager::PatchType::HOOK;
		patch.hookType = PatchManager::HookType::JUMP;
		
		patch.assembly = std::string(asmBuffer);
		patch.hookRegister = "rax";
		patch.nopCount = 0;

		return patchManager.InstallPatch(true, patch);
	}

	std::string APIMemoryCheck2Asm = Patch::unindent(R"(
        add r10, rbp
		mov r10, [r10]
        mov rsi, [rsi]

        mov rdi, 0x%llX
        cmp rsi, rdi
        jl Exit
        add rdi, 0x%llX
        cmp rsi, rdi
        jg Exit
        mov rdi, 0x%llX
        sub rsi, rdi
        add rsi, 0x%llX

        Exit:
		cmp [rsi], r10
        mov rdi, 0x%llX
		jmp rdi
	)");

	bool InstallAPIMemoryCheck2Patch(PatchManager& patchManager) {
		/*
		 * Install patch to bypass memory integrity check that
		 * checks the integrity of the ntdll.dll copy
		 */
		Patch::PatchManager::Patch patch;

		patch.name = "BC API Memory Check 2";

		patch.address = bcMemoryCheck2Address;
		sprintf_s(asmBuffer, APIMemoryCheck2Asm.c_str(), bcNtdllModuleEntry.modBaseAddr,
			bcNtdllModuleEntry.modBaseSize, bcNtdllModuleEntry.modBaseAddr, bcNtdllCopyAddress, 
			bcMemoryCheck2RetAddress);

		patch.patchType = PatchManager::PatchType::HOOK;
		patch.hookType = PatchManager::HookType::JUMP;
		
		patch.assembly = std::string(asmBuffer);
		patch.hookRegister = "rdi";
		patch.nopCount = 0;

		return patchManager.InstallPatch(true, patch);
	}

	std::string APIMemoryCheck3Asm = Patch::unindent(R"(
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
        add rax, 0x%llX
        mov r8, [rsp+0x20] 
        mov [r8], rax

		Exit:
        mov eax, [rax]
		mov ecx, [rsp]
        mov r8, 0x%llX
		jmp r8
	)");

	bool InstallAPIMemoryCheck3Patch(PatchManager& patchManager) {
		/*
		 * Install patch to bypass memory integrity check that
		 * checks the integrity of the ntdll.dll copy
		 */
		Patch::PatchManager::Patch patch;
		
		patch.name = "BC API Memory Check 3";

		patch.address = bcMemoryCheck3Address;
		sprintf_s(asmBuffer, APIMemoryCheck3Asm.c_str(), bcNtdllModuleEntry.modBaseAddr, 
			bcNtdllModuleEntry.modBaseSize, bcNtdllModuleEntry.modBaseAddr, bcNtdllCopyAddress, 
			bcMemoryCheck3RetAddress);

		patch.patchType = PatchManager::PatchType::HOOK;
		patch.hookType = PatchManager::HookType::JUMP;
		
		patch.assembly = std::string(asmBuffer);
		patch.hookRegister = "r8";
		patch.nopCount = 0;

		return patchManager.InstallPatch(true, patch);
	}


	std::string APIMemoryCheck4Asm = Patch::unindent(R"(
        mov r8, 0x%llX
        cmp r12, r8
        jl Exit
        add r8, 0x%llX
        cmp r12, r8
        jg Exit
        mov r8, 0x%llX
        sub r12, r8
        add r12, 0x%llX

		Exit:
        mov r12b, [r12]
        and rsi, 0x00000010
        sub r15w, 0x2665
        add r15, rbp
        mov r8, 0x%llX
		jmp r8
	)");
	bool InstallAPIMemoryCheck4Patch(PatchManager& patchManager) {
		/*
		 * Install patch to bypass memory integrity check that reads
		 * the memory of a subset of methods in the BlackCipher64.aes module
		 * checks the integrity check responsible for checking the
		 * integrity of the ntdll.dll copy
		 */
		Patch::PatchManager::Patch patch;

		patch.name = "BC API Memory Check 4";

		patch.address = bcMemoryCheck4Address;
		sprintf_s(asmBuffer, APIMemoryCheck4Asm.c_str(), blackCipherModuleEntry.modBaseAddr, 
			blackCipherModuleEntry.modBaseSize, blackCipherModuleEntry.modBaseAddr, 
			blackCipherCopyAddr, bcMemoryCheck4RetAddress);

		patch.patchType = PatchManager::PatchType::HOOK;
		patch.hookType = PatchManager::HookType::JUMP;
		
		patch.assembly = std::string(asmBuffer);
		patch.hookRegister = "r8";
		patch.nopCount = 0;

		return patchManager.InstallPatch(true, patch);
	}

	std::string bcMemoryCheck5Asm = Patch::unindent(R"(
        mov rax, 0x%llX
		cmp rdi, rax
		jl Exit
		add rax, 0x%llX
		cmp rdi, rax
		jg Exit
        mov rax, 0x%llX
		sub rdi, rax
		add rdi, 0x%llX

		Exit:
        mov r14d, r9d
        mov rdi, r8
        mov r15d, edx
        mov rsi, rcx
        mov rax, 0x%llX
		jmp rax
	)");

	bool InstallAPIMemoryCheck5Patch(PatchManager& patchManager) {
		/*
		 * Install patch to bypass memory integrity check that reads
		 * the memory of a subset of methods in the BlackCipher64.aes module
		 * checks the integrity check responsible for checking the
		 * integrity of the ntdll.dll copy
		 */
		Patch::PatchManager::Patch patch;

		patch.name = "BC API Memory Check 5";

		patch.address = bcMemoryCheck5Address;
		sprintf_s(asmBuffer, bcMemoryCheck5Asm.c_str(), blackCipherModuleEntry.modBaseAddr,
			blackCipherModuleEntry.modBaseSize, blackCipherModuleEntry.modBaseAddr,
			blackCipherCopyAddr, bcMemoryCheck5RetAddress);

		patch.patchType = PatchManager::PatchType::HOOK;
		patch.hookType = PatchManager::HookType::JUMP;

		patch.assembly = std::string(asmBuffer);
		patch.hookRegister = "rax";
		patch.nopCount = 0;

		return patchManager.InstallPatch(true, patch);
	}

	std::string APIMemoryCheck6Asm = Patch::unindent(R"(
        mov r11, 0x%llX
        cmp rcx, r11
        jl Exit
        add r11, 0x%llX
        cmp rcx, r11
        jg Exit
        mov r11, 0x%llX
        sub rcx, r11
        add rcx, 0x%llX

		Exit:
        mov ecx, [rcx]
		mov r11, 0x00000001
		mov [rdi], ecx
        mov r11, 0x%llX
		jmp r11
	)");

	bool InstallAPIMemoryCheck6Patch(PatchManager& patchManager) {
		/*
		 * Install patch to bypass memory integrity check that reads
		 * the memory of a subset of methods in the BlackCipher64.aes module
		 * checks the integrity check responsible for checking the
		 * integrity of the ntdll.dll copy
		 */
		Patch::PatchManager::Patch patch;

		patch.name = "BC API Memory Check 6";

		patch.address = bcMemoryCheck6Address;
		sprintf_s(asmBuffer, APIMemoryCheck6Asm.c_str(), blackCipherModuleEntry.modBaseAddr,
			blackCipherModuleEntry.modBaseSize, blackCipherModuleEntry.modBaseAddr, 
			blackCipherCopyAddr, bcMemoryCheck6RetAddress);

		patch.patchType = PatchManager::PatchType::HOOK;
		patch.hookType = PatchManager::HookType::JUMP;
		
		patch.assembly = std::string(asmBuffer);
		patch.hookRegister = "r11";
		patch.nopCount = 0;

		return patchManager.InstallPatch(true, patch);
	}

	std::string KernelBaseIsDebuggerPresentAsm = Patch::unindent(R"(
        xor rax, rax
		ret
	)");

	bool InstallIsDebuggerPresentPatch(PatchManager& patchManager) {
		Patch::PatchManager::Patch patch;

		patch.address = (unsigned __int64)GetProcAddress(hKernelbase, "IsDebuggerPresent");
		if (patch.address == NULL) {
			printf("Failed to get procedure address for KERNELBASE.IsDebuggerPresent");
			return false;
		}

		patch.patchType = PatchManager::PatchType::WRITE;
		patch.name = "KERNELBASE.IsDebuggerPresent - always false";
		patch.assembly = KernelBaseIsDebuggerPresentAsm;

		return patchManager.InstallPatch(true, patch);
	}

	std::string Kernel32Module32FirstWSnapshotAsm = Patch::unindent(R"(
        push rbx
        push rdx
        push r8
        push r12
        push r13
        push r14
        push r15
		
        push rcx
        push rsi
        push rdi
		
        sub rsp, 8

        mov rcx, rdi
        mov r12, 0x%llX
        call r12

        add rsp, 8
        
        pop rdi
        pop rsi
        pop rcx

        pop r15
        pop r14
        pop r13
        pop r12
        pop r8
        pop rdx
        pop rbx

        ret
	)");
	BOOL WINAPI Module32FirstWFilter(MODULEENTRY32W& lpme) {
		/*
		 * KERNEL32.Module32FirstW API hook method
		 * Return the MODULEENTRY32W from the static list we created at the start
		 */
		if (lpme.th32ProcessID == processEntry.th32ProcessID) {
			blackcipherIterator = blackcipherModuleList.begin();
			memcpy(&lpme, &blackcipherIterator._Ptr->_Myval, sizeof(MODULEENTRY32W));
			//wprintf(L"[KERNEL32.Module32FirstW] BC pid = %X, name = '%s' \n%s\n", lpme.th32ProcessID, lpme.szModule, lpme.szExePath);
		}
		else if (lpme.th32ProcessID == processEntry.th32ParentProcessID) {
			maplestoryIterator = maplestoryModuleList.begin();
			memcpy(&lpme, &maplestoryIterator._Ptr->_Myval, sizeof(MODULEENTRY32W));
			//wprintf(L"[KERNEL32.Module32FirstW] Maple pid = %X, name = '%s' \n%s\n", lpme.th32ProcessID, lpme.szModule, lpme.szExePath);
		}
		return true;
	}

	bool InstallModule32FirstWPatch(PatchManager& patchManager) {
		/*
		 * Install the patch to the KERNEL32.Module32FirstW API
		 */
		Patch::PatchManager::Patch patch;

		patch.name = "KERNELBASE.Module32FirstW hook";
		patch.address = (unsigned __int64)GetProcAddress(hKernel32, "Module32FirstW") + 0x128;
		if (patch.address == NULL) {
			printf("GetProcAddress 'Module32FirstW' failed");
			return false;
		}
		sprintf_s(asmBuffer, Kernel32Module32FirstWSnapshotAsm.c_str(), &Module32FirstWFilter);

		patch.patchType = PatchManager::PatchType::HOOK;
		patch.hookType = PatchManager::HookType::JUMP;
		
		patch.assembly = std::string(asmBuffer);
		patch.hookRegister = "r12";
		patch.nopCount = 0;

		return patchManager.InstallPatch(true, patch);
	}

	std::string Kernel32Module32NextWSnapshotAsm = Patch::unindent(R"(
        mov eax, edi
        mov rbx, [rsp+0x60]
        add rsp, 0x50
        pop rdi

		push rbx
        push rdx
        push r8
        push r9
        push r12
        push r13
        push r14
        push r15
		
        push rcx
        push rsi
        push rdi
		

		mov rcx, rdi
        sub rsp, 0x8

        mov r12, 0x%llX
        call r12

        add rsp, 0x8
        
        pop rdi
        pop rsi
        pop rcx

        pop r15
        pop r14
        pop r13
        pop r12
        pop r9
        pop r8
        pop rdx
        pop rbx

		ret
	)");
	BOOL WINAPI Module32NextWHook(MODULEENTRY32W me) {
		/*
		 * KERNEL32.Module32NextW API hook method
		 * Iterate over list of modules from initial filtered snapshot
		 * Return false once all of the modules have been iterated through
		 */
		if (me.th32ProcessID == processEntry.th32ProcessID) {
			blackcipherIterator++;
			if (blackcipherIterator == blackcipherModuleList.end()) {
				SetLastError(ERROR_NO_MORE_FILES);
				return false;
			}
			memcpy(&me, &blackcipherIterator._Ptr->_Myval, sizeof(MODULEENTRY32W));
			//wprintf(L"[KERNEL32.Module32NextW] BC pid = %X, name = '%s' \n%s\n", me.th32ProcessID, me.szModule, me.szExePath);
		}
		else if (me.th32ProcessID == processEntry.th32ParentProcessID) {
			maplestoryIterator++;
			if (maplestoryIterator == maplestoryModuleList.end()) {
				SetLastError(ERROR_NO_MORE_FILES);
				return false;
			}
			memcpy(&me, &maplestoryIterator._Ptr->_Myval, sizeof(MODULEENTRY32W));
			//wprintf(L"[KERNEL32.Module32NextW] Maple pid = %X, name = '%s' \n%s\n", me.th32ProcessID, me.szModule, me.szExePath);
		}
		// else { // this should never happen, we filter other processes using NtOpenProcess hook }
		return true;
	}

	bool InstallModule32NextWPatch(PatchManager& patchManager) {
		/* 
		 * Install the patch to the KERNEL32.Module32NextW API
		 */
		Patch::PatchManager::Patch patch;

		patch.name = "KERNELBASE.Module32NextW hook";

		patch.address = (unsigned __int64)GetProcAddress(hKernel32, "Module32NextW") + 0x129;
		if (patch.address == NULL) {
			printf("GetProcAddress 'Module32NextW' failed");
			return false;
		}

		sprintf_s(asmBuffer, Kernel32Module32NextWSnapshotAsm.c_str(), &Module32NextWHook);

		patch.patchType = PatchManager::PatchType::HOOK;
		patch.hookType = PatchManager::HookType::JUMP;
		
		patch.assembly = std::string(asmBuffer);
		patch.hookRegister = "r12";
		patch.nopCount = 0;

		return patchManager.InstallPatch(true, patch);
	}

	bool LoadBlackCipherModules() {
		/*
		 * Load modules loaded in the BlackCipher64.aes process and add them to a list
		 * The list will later be used for the Module32FirstW and Module32NextW hook
		 * to iterate over a static list of modules.
		 * Create a copy of the BlackCipher64.aes module if it's available,
		 * along with the ntdll.dll copy (BCXXXX.tmp) so they can be used in the memory
		 * integrity check bypass patches.
		 */
		HANDLE hModuleSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0);
		MODULEENTRY32W moduleEntry;

		moduleEntry.dwSize = sizeof(MODULEENTRY32W);

		if (Module32FirstW(hModuleSnapshot, &moduleEntry)) {
			if (blackCipherModuleEntry.hModule == NULL && lstrcmpW(moduleEntry.szModule, BLACKCIPHER64) == 0) {
				memcpy((void*)&blackCipherModuleEntry, (void*)&moduleEntry, sizeof(MODULEENTRY32W));
				blackCipherCopyAddr = Patch::CopyModule((unsigned __int64)moduleEntry.modBaseAddr, (unsigned __int64)moduleEntry.modBaseSize);
				if (blackCipherCopyAddr == NULL) {
					wprintf(L"Failed to create a copy of the %s module\n", BLACKCIPHER64);
					return false;
				}
				blackcipherModuleList.push_back(moduleEntry);
			}
			do {
				if (blackCipherModuleEntry.hModule == NULL && lstrcmpW(moduleEntry.szModule, BLACKCIPHER64) == 0) {
					memcpy((void*)&blackCipherModuleEntry, (void*)&moduleEntry, sizeof(MODULEENTRY32W));
					blackCipherCopyAddr = Patch::CopyModule((unsigned __int64)moduleEntry.modBaseAddr, (unsigned __int64)moduleEntry.modBaseSize);
					if (blackCipherCopyAddr == NULL) {
						wprintf(L"Failed to create a copy of the %s module\n", BLACKCIPHER64);
						return false;
					}
					blackcipherModuleList.push_back(moduleEntry);
				}
				else if (bcNtdllModuleEntry.hModule == NULL && endsWithW(moduleEntry.szModule, L".tmp")) {
					unsigned __int64 procAddress = (unsigned __int64)GetProcAddress(moduleEntry.hModule, "NtReadVirtualMemory");
					if (procAddress != NULL) {
						memcpy((void*)&bcNtdllModuleEntry, (void*)&moduleEntry, sizeof(MODULEENTRY32W));
						bcNtdllCopyAddress = Patch::CopyModule((unsigned __int64)bcNtdllModuleEntry.modBaseAddr, (unsigned __int64)bcNtdllModuleEntry.modBaseSize);
						if (bcNtdllCopyAddress == NULL) {
							printf("Failed to copy the BCXXXX.tmp (ntdll.dll copy)");
							return false;
						}
					}
					// blackcipherModuleList.push_back(bcNtdllModuleEntry);
				}
				else {
					bool bFilter = false;
					for (auto const& moduleToFilter : moduleExclusionList) {
						if (lstrcmpW(moduleToFilter.c_str(), moduleEntry.szModule) == 0) {
							bFilter = true;
						}
					}
					if (!bFilter) {
						blackcipherModuleList.push_back(moduleEntry);
					}
				}
			} while (Module32NextW(hModuleSnapshot, &moduleEntry));
		}
		else {
			return false;
		}
		CloseHandle(hModuleSnapshot);
		return true;
	}


	bool InstallEnumWindowsPatch(PatchManager& patchManager) {
		/*
		 * Patch USER32.EnumWindows API
		 * Don't iterate through list of top-level Windows on the screen
		 * return false
		 */
		Patch::PatchManager::Patch patch;

		HMODULE hUser32 = GetModuleHandleW(USER32_DLL);
		if (hUser32 == NULL) {
			wprintf(L"Could not get handle of the module %s", USER32_DLL);
			return false;
		}
		patch.name = "USER32.EnumWindows return false";
		patch.address = (unsigned __int64)GetProcAddress(hUser32, "EnumWindows");
		if (patch.address == NULL) {
			printf("GetProcAddress 'USER32.EnumWindows' failed");
			return false;
		}
		sprintf_s(asmBuffer, asmReturnFalse.c_str());
		patch.patchType = Patch::PatchManager::PatchType::WRITE;

		patch.assembly = std::string(asmBuffer);
		return patchManager.InstallPatch(true, patch);
	}


	bool LoadMapleStoryModules() {
		/*
		 * Load modules loaded in the MapleStory.exe process and add them to a list
		 * The list will later be used for the Module32FirstW and Module32NextW hook
		 * to iterate over a static list of modules.
		 */
		HANDLE hModuleSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, processEntry.th32ParentProcessID);
		MODULEENTRY32W moduleEntry;

		moduleEntry.dwSize = sizeof(MODULEENTRY32W);

		if (!Module32FirstW(hModuleSnapshot, &moduleEntry)) {
			return false;
		}

		if (maplestoryModuleEntry.hModule == NULL && lstrcmpW(moduleEntry.szModule, MAPLESTORY) == 0) {
			memcpy((void*)&maplestoryModuleEntry, (void*)&moduleEntry, sizeof(MODULEENTRY32W));
			//maplestoryModuleList.push_back(maplestoryModuleEntry);
		}

		do {
			if (maplestoryModuleEntry.hModule == NULL && lstrcmpW(moduleEntry.szModule, MAPLESTORY) == 0) {
				memcpy((void*)&maplestoryModuleEntry, (void*)&moduleEntry, sizeof(MODULEENTRY32W));
				//maplestoryModuleList.push_back(maplestoryModuleEntry);
			}
			else if (blackCallModuleEntry.hModule == NULL && lstrcmpW(moduleEntry.szModule, BLACKCALL64) == 0) {
				memcpy((void*)&blackCallModuleEntry, (void*)&moduleEntry, sizeof(MODULEENTRY32W));
				maplestoryModuleList.push_back(blackCallModuleEntry);
			}
			else {
				bool bFilter = false;
				for (auto const& moduleToFilter : moduleExclusionList) {
					if (lstrcmpW(moduleToFilter.c_str(), moduleEntry.szModule) == 0) {
						bFilter = true;
					}
				}
				if (!bFilter) {
					maplestoryModuleList.push_back(moduleEntry);
				}
			}
		} while (Module32NextW(hModuleSnapshot, &moduleEntry));

		CloseHandle(hModuleSnapshot);
		return true;
	}

	bool GenerateIPCFile() {
		/*
		 * Generate a file used to provide data required for the bypass to the MapleStory.exe process
		 * Includes the address of the BlackCipher64.aes module copy abd the pid of the current process
		 */
		sprintf_s(ipcFileName, "%s/NGSBypass%X-1.lock", ipcDir.c_str(), processEntry.th32ParentProcessID);
		printf("Generating IPC file %s\n", ipcFileName);
		std::filesystem::path path{ ipcFileName };
		std::filesystem::remove(path); // delete file if exist
		std::ofstream ofs(path);

		char content[64];
		sprintf_s(content, "blackCipher64Copy=0x%llX\n", blackCipherCopyAddr);
		ofs << content;
		sprintf_s(content, "pid=0x%X\n", GetCurrentProcessId());
		ofs << content;
		ofs.close();

		printf(content);

		char newFileName[64];
		sprintf_s(newFileName, "%s/NGSBypass%X-1", ipcDir.c_str(), processEntry.th32ParentProcessID);
		if (std::rename(ipcFileName, newFileName)) {
			printf("Error renaming the IPC file to %s\n", newFileName);
			return false;
		}

		printf("Successfully renamed the IPC file %s\n", newFileName);
		return true;
	}

	void ReadIPCFile(char* fileName) {
		/*
		 * Read the data file generated by the MapleStory.exe process
		 * Contains the address to the BlackCall64.aes module copy and the BlackCall64.aes pid
		 */
		printf("Reading IPC file\n");
		string content = ReadTextFile(fileName);
		vector<string> lines = Split(content.c_str(), '\n');
		for (auto line : lines) {
			vector<string> keyValuePair = Split(line.c_str(), '=');
			if (keyValuePair.size() == 2) {
				if (keyValuePair[0].compare("blackCall64Copy") == 0) {
					std::stringstream ss;
					ss << std::hex << (const char*)keyValuePair[1].c_str() + 2;
					ss >> blackCallCopyAddr;
					printf("BlackCall64 Copy 0x%llX\n", blackCallCopyAddr);
				}
			}

		}
	}

	bool WaitForIPCFile() {
		/*
		 * Wait until the IPC file generated by the MapleStory.exe module becomes available
		 * then read it or wait until the time elapsed exceeds the allotted time
		 */
		char fileName[64];
		sprintf_s(fileName, "%s/NGSBypass%X-2", ipcDir.c_str(), processEntry.th32ParentProcessID);
		printf("Waiting for IPC file %s\n", fileName);

		std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();
		bool timedout = false;
		while (!timedout) {
			timedout = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - start).count() > MAX_IPC_FILE_WAITTIME;

			try {
				ifstream f(fileName);
				if (!f.good()) continue;
				f.close();
				ReadIPCFile(fileName);
				break;
			}
			catch (const std::filesystem::filesystem_error& err) {
				printf("IPCFile filesystem error: %s\n", err.what());
				return false;
			}

			Sleep(50);
		}

		if (timedout) {
			printf("Waiting for IPC file timedout\n");
			return false;
		}
		std::filesystem::remove(fileName);
		return true;
	}

	bool InstallPatches() {
		/*
		 * Install patches related to the BlackCipher64.aes module
		 */
		patchManager.Setup();

		hNtdll = GetModuleHandleW(NTDLL_DLL);
		if (hNtdll == NULL) {
			wprintf(L"Could not get handle of the module %s\n", NTDLL_DLL);
			return false;
		}

		hKernelbase = GetModuleHandleW(KERNELBASE_DLL);
		if (hKernelbase == NULL) {
			wprintf(L"Could not get handle of the module %s\n", KERNELBASE_DLL);
			return false;
		}

		hKernel32 = GetModuleHandleW(KERNEL32_DLL);
		if (hKernel32 == NULL) {
			wprintf(L"Could not get handle of the module %s", KERNEL32_DLL);
			return false;
		}

		HANDLE hProcessSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		processEntry.dwSize = sizeof(PROCESSENTRY32W);
		if (Process32FirstW(hProcessSnapShot, &processEntry)) {
			const unsigned int currentProcessId = GetCurrentProcessId();
			do {
				if (processEntry.th32ProcessID == currentProcessId) {
					printf("Current process %X: Parent %X\n", processEntry.th32ProcessID, processEntry.th32ParentProcessID);
					break;
				}
			} while (Process32NextW(hProcessSnapShot, &processEntry));
		}
		else {
			wprintf(L"[Process32NextW] Failed to get information on the process %s\n", BLACKCIPHER64);
			return false;
		}

		CloseHandle(hProcessSnapShot);

		unsigned int counter = 0;
		do {
			LoadBlackCipherModules();
			Sleep(100);
		} while (bcNtdllCopyAddress == NULL && counter++ < MAX_NTDLLCOPY_WAITTIME * 10);

		if (bcNtdllCopyAddress == NULL) {
			wprintf(L"Failed retrieving the address of BlackCipher's ntdll copy (BCXXXX.tmp)");
			return false;
		}

		if (!LoadMapleStoryModules()) {
			wprintf(L"Failed to list modules of the %s process", MAPLESTORY);
			return false;
		}

		// Create NGSBypass directory in APPDATA if it doesn't exist
		ipcDir = getenv("appdata") + string("/NGSBypass");
		std::filesystem::path path{ ipcDir };
		if (!std::filesystem::exists(ipcDir))
		{
			if (!filesystem::create_directory(ipcDir))
			{
				cout << "Failed to create IPC dir " << ipcDir.c_str() << endl;
				return false;
			}
		}

		if (!GenerateIPCFile()) {
			cout << "Failed to generate IPC file\n" << endl;
			return false;
		}

		if (!WaitForIPCFile()) {
			cout << "Failed to read IPC file from the process " << MAPLESTORY << endl;
			return false;
		}

		DWORD currentProcessId = GetCurrentProcessId();

		SuspendProcessThreads(currentProcessId);

		InstallModule32FirstWPatch(patchManager);
		InstallModule32NextWPatch(patchManager);
		InstallEnumWindowsPatch(patchManager);

		bool success = InstallAPIRestoreRoutinePatch(patchManager) &&
			InstallAPIMemoryCheck1Patch(patchManager) &&
			InstallAPIMemoryCheck2Patch(patchManager) &&
			InstallAPIMemoryCheck3Patch(patchManager) &&
			InstallAPIMemoryCheck4Patch(patchManager) &&
			InstallAPIMemoryCheck5Patch(patchManager) &&
			InstallAPIMemoryCheck6Patch(patchManager);

		if (!success) {
			wprintf(L"Failed to install patches to bypass %s API memory integrity checks\n", BLACKCIPHER64);
			return false;
		}

		success = InstallBCNtReadVirtualMemoryHook(patchManager) &&
			InstallBCNtOpenProcessHook(patchManager) &&
			InstallBCNtQuerySystemInformationHook(patchManager);
			//InstallBCNtQueryVirtualMemoryHook(patchManager); not required and implementation removed

		if (!success) {
			wprintf(L"Failed install %s copy / BCXXXX.tmp patches\n", NTDLL_DLL);
			return false;
		}

		InstallIsDebuggerPresentPatch(patchManager);

		ResumeProcessThreads(currentProcessId);

		return true;
	}

	void Main() {
		if (!InstallPatches()) {
			wprintf(L"Failed to install %s patches\n", BLACKCIPHER64);
			wprintf(L"Terminating the process in 5 seconds...\n");
			Sleep(5000);
			TerminateProcess(GetCurrentProcess(), 1);
		}
	}

}
