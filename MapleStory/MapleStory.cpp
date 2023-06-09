#include "../Patch/Patch.h"
#include "../Patch/PatchManager.h"
#include "../MapleStory/MapleStory.h"
#include "../BlackCall/BlackCall.h"

#include <windows.h>
#include <random>
#include <chrono>

#define BUFF_SIZE 2048

using namespace Patch;

HMODULE hKernelbase = NULL;

unsigned __int64 maplestoryBaseAddress = 0;

const unsigned __int64 maplestoryCRCHookAddress = 0x147E53D37;
const unsigned __int64 maplestoryCRCBypassAddress = 0x147E4D2EC;
const unsigned __int64 maplestoryCRCBypassReturnAddress = 0x148067112;
const unsigned __int64 maplestoryCRCRegionSize = 0xE0D3000;

const unsigned __int64 threadIdCheck1PatchAddress = 0x140DDBDAE;
const unsigned __int64 threadIdCheck1JmpAddress = 0x140DDBF6E;

const unsigned __int64 threadIdCheck2PatchAddress = 0x140DDBF9E;
const unsigned __int64 threadIdCheck2JmpAddress = 0x140DDC15E;

const unsigned __int64 debuggerCheck1Address = 0x14484E64C;

namespace MapleStory {
	LPCWSTR MAPLESTORY_PROCESS = L"MapleStory.exe";
	LPCWSTR MAPLESTORY_MODULE = L"maplestory.exe";
	LPCWSTR MACHINE_ID_LIB_DLL = L"MachineIdLib.dll";
	LPCWSTR CRASH_REPORTER_DLL = L"CrashReporter_64.dll";
	LPCWSTR NEXON_ANALYTICS_DLL = L"NexonAnalytics64.dll";
	LPCWSTR KERNELBASE_DLL = L"KERNELBASE.dll";

	PatchManager patchManager = PatchManager();
	unsigned char* maplestoryCopyBase;
	char asmBuffer[BUFF_SIZE];

	unsigned __int64 machineId = 0;
	
	std::string asmReturnFalse = Patch::unindent(R"(
        xor rax, rax
		ret
	)");
	std::string asmAbsoluteJumpAsm = R"(mov rax, 0x%llX; jmp rax)";
	std::string asmRelativeJump = R"(jmp 0x%llX)";

	std::string crcCodeCaveAsm = Patch::unindent(R"(
        mov rdx, 0x%llX
		sub rsi, rdx
        add rsi, 0x%llX
		repe movsb
        xor rdx, rdx
		mov rsi, 0x%llX
		jmp rsi
	)");
	

	void InstallCrcBypass(PatchManager& patchManager) {
		HMODULE hModule = GetModuleHandleW(MAPLESTORY_MODULE);
		if (hModule == NULL) {
			wprintf(L"Failed to get a handle of the module %s\n", MAPLESTORY_MODULE);
			return;
		}
		maplestoryBaseAddress = (unsigned __int64)hModule;
		const unsigned __int64 bytesRead = 0;
		// create copy of memory region checked by CRC validation
		maplestoryCopyBase = (unsigned char*)VirtualAlloc(NULL, maplestoryCRCRegionSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (maplestoryCopyBase == NULL) {
			printf("Failed to allocate buffer for CRC memory region copy\n");
			return;
		}
		memcpy(maplestoryCopyBase, (void*)(maplestoryBaseAddress + 0x1000), maplestoryCRCRegionSize);
		patchManager.gameCopyAddress = (unsigned __int64)maplestoryCopyBase;

		Patch::PatchManager::Patch patch1;

		patch1.name = "CRC Bypass";
		sprintf(asmBuffer, crcCodeCaveAsm.c_str(), maplestoryBaseAddress + 0x1000, maplestoryCopyBase, maplestoryCRCBypassReturnAddress);
		patch1.assembly = std::string(asmBuffer);
		patch1.patchType = Patch::PatchManager::PatchType::WRITE;
		patch1.address = maplestoryCRCBypassAddress;
		patch1.nopCount = 2;

		patchManager.InstallPatch(true, patch1);

		Patch::PatchManager::Patch patch2;

		patch2.name = "CRC Hook";
		sprintf(asmBuffer, asmRelativeJump.c_str(), maplestoryCRCBypassAddress);
		patch2.assembly = std::string(asmBuffer);
		patch2.patchType = Patch::PatchManager::PatchType::WRITE;
		patch2.address = maplestoryCRCHookAddress;

		patchManager.InstallPatch(true, patch2);
	}

	std::string getMachineIdHookAsm = R"(mov rax, 0x%llX; jmp rax)";

	const unsigned __int64 MIDLib_GetMachineIdHook() {
		/*
		 * Original: Gather information from the system and generate an ID
		 * Patch:	 Generate random 8 byte value to be used as ID
		 */
		printf("[MIDLib_GetMachineIdHook] Using randomly generated machine ID\n");
		if (machineId == 0) {
			unsigned seed = std::chrono::system_clock::now().time_since_epoch().count();
			std::independent_bits_engine<std::mt19937, 64, std::uint_fast64_t> generator(seed);
			machineId = generator();
		}
		printf("[MIDLib_GetMachineIdHook] MachineID = 0x%llX\n", machineId);
		return machineId;
	}

	void InstallGetMachineIdHook(PatchManager& patchManager) {
		HMODULE hMachineIdLib = GetModuleHandleW(MACHINE_ID_LIB_DLL);
		if (hMachineIdLib == NULL) {
			wprintf(L"Cannot get handle of the module %s", MACHINE_ID_LIB_DLL);
			return;
		}

		const unsigned __int64 getMachineIdAddress = (unsigned __int64)GetProcAddress(hMachineIdLib, "MIDLib_GetMachineId");
		if (getMachineIdAddress == NULL) {
			printf("Failed to patch machine ID, cannot retrieve the address for the procedure MIDLib_GetMachineId");
		}

		Patch::PatchManager::Patch patch;
		patch.name = "MachineIdLib.MIDLib_GetMachineId Hook";
		sprintf(asmBuffer, asmAbsoluteJumpAsm.c_str(), &MIDLib_GetMachineIdHook);
		patch.assembly = std::string(asmBuffer);
		patch.patchType = Patch::PatchManager::PatchType::WRITE;
		patch.address = getMachineIdAddress;

		patchManager.InstallPatch(true, patch);
	}


	bool InstallCrashReporterPatch(PatchManager& patchManager) {
		HMODULE hCrashReporter = GetModuleHandleW(CRASH_REPORTER_DLL);
		if (hCrashReporter == NULL) {
			wprintf(L"Cannot get handle of the module %s", CRASH_REPORTER_DLL);
			return false;
		}
		Patch::PatchManager::Patch patch;
		patch.address = (unsigned __int64)GetProcAddress(hCrashReporter, "CrashReporter_Init");
		if (patch.address == NULL) {
			printf("Failed to get CrashReporter_64.ScreenShot_ShootA procedure address");
		}
		patch.name = "CrashReporter_64.CrashReporter_Init Hook";
		patch.assembly = std::string(asmReturnFalse);
		patch.patchType = Patch::PatchManager::PatchType::WRITE;

		return patchManager.InstallPatch(true, patch);
	}

	bool InstallNexonAnalyticsLogsPatch(PatchManager& patchManager) {
		HMODULE hNexonAnalytics = GetModuleHandleW(NEXON_ANALYTICS_DLL);
		if (hNexonAnalytics == NULL) {
			wprintf(L"Cannot a handle for the module %s", NEXON_ANALYTICS_DLL);
			return false;
		}

		Patch::PatchManager::Patch patch;

		patch.name = "NexonAnalytics.enqueueLog";
		patch.address = (unsigned __int64)GetProcAddress(hNexonAnalytics, "enqueueLog");
		
		patch.assembly = asmReturnFalse;
		patch.patchType = PatchManager::PatchType::WRITE;
		
		patch.targetAddress = (unsigned __int64)&hNexonAnalytics;

		return patchManager.InstallPatch(true, patch);
	}

	bool InstallThreadIdCheckPatch(PatchManager& patchManager) {
		Patch::PatchManager::Patch patch;
		
		patch.name = "ThreadID check 1 bypass";
		sprintf(asmBuffer, asmRelativeJump.c_str(), threadIdCheck1JmpAddress);
		patch.assembly = std::string(asmBuffer);
		patch.patchType = Patch::PatchManager::PatchType::WRITE;
		patch.address = threadIdCheck1PatchAddress;

		if (!patchManager.InstallPatch(true, patch))
			return false;

		Patch::PatchManager::Patch patch2;

		patch2.name = "ThreadID check 2 bypass";
		sprintf(asmBuffer, asmRelativeJump.c_str(), threadIdCheck2JmpAddress);
		patch2.assembly = std::string(asmBuffer);
		patch2.patchType = Patch::PatchManager::PatchType::WRITE;
		patch2.address = threadIdCheck2PatchAddress;

		return patchManager.InstallPatch(true, patch2);
	}

	bool InstallIsDebuggerPresentPatch(PatchManager& patchManager) {
		Patch::PatchManager::Patch patch;

		patch.address = (unsigned __int64)GetProcAddress(hKernelbase, "IsDebuggerPresent");
		if (patch.address == NULL) {
			printf("Failed to get procedure address for KERNELBASE.IsDebuggerPresent");
			return false;
		}

		patch.patchType = PatchManager::PatchType::WRITE;
		patch.name = "KERNELBASE.IsDebuggerPresent - always false";
		patch.assembly = asmReturnFalse;

		return patchManager.InstallPatch(true, patch);
	}

	void InstallPatches()
	{
		if (!BlackCall::InstallHooks()) {
			wprintf(L"Failed to install %s hooks\n", MAPLESTORY_PROCESS);
			printf("Terminating the process in 5 seconds...\n");
			Sleep(5000);
			TerminateProcess(GetCurrentProcess(), 1);
			return;
		}

		patchManager.Setup();

		hKernelbase = GetModuleHandleW(KERNELBASE_DLL);
		if (hKernelbase == NULL) {
			wprintf(L"Could not get handle of the module %s", KERNELBASE_DLL);
			return;
		}

		InstallCrcBypass(patchManager);
		InstallIsDebuggerPresentPatch(patchManager);
		InstallNexonAnalyticsLogsPatch(patchManager);
		InstallGetMachineIdHook(patchManager);
		InstallCrashReporterPatch(patchManager);
		InstallThreadIdCheckPatch(patchManager);
	}
}