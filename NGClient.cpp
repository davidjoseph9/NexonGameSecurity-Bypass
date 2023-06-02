#include "pch.h"
#include "Patch.h"
#include "PatchManager.h"
#include "BlackCall.h"
#include <TlHelp32.h>

using namespace Patch;

namespace NGClient {
	LPCWSTR NGCLIENT64_MODULE = L"NGClient64.aes";
	LPCWSTR MAPLESTORY_MODULE = L"maplestory.exe";
	unsigned int MAX_WAIT_FOR_NGCLIENT = 10; // maximum time to wait for NGClient64.aes module to become avialable in seconds

	PatchManager patchManager = PatchManager();

	// NGClient64.aes
	unsigned __int64 ngClientBaseAddress = NULL;
	unsigned __int64 ngClientCreateProcessWPtrOffset = 0xEF2E8;
	unsigned __int64 ngClientCopyFileWPtrOffset = 0xEF238;
	//unsigned __int64 ngClientLoadLibraryWPtrOffset = 0xEF1E0;
	unsigned __int64 ngClientLoadLibraryExWPtrOffset = 0xEF3B0;

	HMODULE hNGClientMod = NULL;
	// maplestory.exe
	unsigned __int64 mapleStoryBaseAddress = NULL;
	unsigned __int64 mapleStoryCreateProcessWPtrOffset = 0x4E61578;
	
	//PROCESSENTRY32W blackCipherProcessEntry;

	//PatchManager* lpPatchManager;

	bool __stdcall CreateProcessWHook(
		LPCWSTR lpApplicationName,
		LPWSTR lpCommandLine,
		LPSECURITY_ATTRIBUTES lpProcessAttributes,
		LPSECURITY_ATTRIBUTES lpThreadAttributes,
		BOOL                  bInheritHandles,
		DWORD                 dwCreationFlags,
		LPVOID                lpEnvironment,
		LPCWSTR               lpCurrentDirectory,
		LPSTARTUPINFOW        lpStartupInfo,
		LPPROCESS_INFORMATION lpProcessInformation
	) {
		wprintf(L"NGClient64 CreateProcessW %s %X", lpCommandLine, dwCreationFlags);
		return CreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes,
			bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory,
			lpStartupInfo, lpProcessInformation);
	}

	bool installCreateProcessWHook(PatchManager& patchManager) {
		Patch::PatchManager::Patch patch;
		patch.patchType = PatchManager::PatchType::HOOK;
		patch.hookType = PatchManager::HookType::PTR;
		patch.name = "NGClient64.aes ntdll.CreateProcessW ptr hook";
		patch.address = ngClientBaseAddress + ngClientCreateProcessWPtrOffset;
		patch.targetAddress = (unsigned __int64)&CreateProcessWHook;
		if (!patchManager.InstallPatch(true, patch))
			return false;

		patch.patchType = PatchManager::PatchType::HOOK;
		patch.hookType = PatchManager::HookType::PTR;
		patch.name = "MapleStory ntdll.CreateProcessW ptr hook";
		patch.address = mapleStoryBaseAddress + mapleStoryCreateProcessWPtrOffset;
		patch.targetAddress = (unsigned __int64)&CreateProcessWHook;
		if (!patchManager.InstallPatch(true, patch))
			return false;

		return true;
	}

	bool __stdcall CopyFileWHook(LPCWSTR lpExistingFileName, LPCWSTR lpNewFileName, BOOL bFailIfExists) {
		wprintf(L"CopyFileW(src=%s, dest=%s, ...ommitted)\n", lpExistingFileName, lpNewFileName);
		if (endsWithW(wstring(lpExistingFileName), wstring(L"Ntdll.dll"))) {

			printf("Allow access for Ntdll.dll copy\n");
			//SetLastError(ERROR_ACCESS_DENIED);
			//return false;
		}
		//printf("WAITING FOR 30000");
		//Sleep(60000);
		printf("CONTINUE");
		return CopyFileW(lpExistingFileName, lpNewFileName, bFailIfExists);
	}

	void installCopyFileWHook(PatchManager& patchManager) {
		Patch::PatchManager::Patch patch;

		patch.patchType = PatchManager::PatchType::HOOK;
		patch.hookType = PatchManager::HookType::PTR;
		patch.name = "NGClient64.CopyFileW ptr hook";
		patch.address = ngClientBaseAddress + ngClientCopyFileWPtrOffset;
		patch.targetAddress = (unsigned __int64)&CopyFileWHook;
		patchManager.InstallPatch(true, patch);
	}

	HMODULE LoadLibraryExWHook(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags) {
		wprintf(L"%s.LoadLibraryExW(%s)\n", NGCLIENT64_MODULE, lpLibFileName);
		return LoadLibraryExW(lpLibFileName, hFile, dwFlags);
	}


	void installLoadLibraryExHook(PatchManager& patchManager) {
		Patch::PatchManager::Patch patch;

		patch.patchType = PatchManager::PatchType::HOOK;
		patch.hookType = PatchManager::HookType::PTR;
		patch.name = "NGClient64.LoadLibraryEx ptr hook";
		patch.address = ngClientBaseAddress + ngClientLoadLibraryExWPtrOffset;
		patch.targetAddress = (unsigned __int64)&LoadLibraryExWHook;
		patchManager.InstallPatch(true, patch);
	}

	bool InstallHooks() {
		wprintf(L"Installing %s hooks\n", NGCLIENT64_MODULE);

		patchManager.Setup();

		unsigned int counter = 0;
		hNGClientMod = GetModuleHandleW(NGCLIENT64_MODULE);
		if (hNGClientMod == NULL) {
			do {
				Sleep(50);
				hNGClientMod = GetModuleHandleW(NGCLIENT64_MODULE);
			} while (hNGClientMod == NULL && counter++ < MAX_WAIT_FOR_NGCLIENT * 20);
		}

		ngClientBaseAddress = (unsigned __int64)GetModuleHandleW(NGCLIENT64_MODULE);
		if (ngClientBaseAddress == NULL) {
			printf("Failed to get module handle of the module '%s'", NGCLIENT64_MODULE);
			return false;
		}

		mapleStoryBaseAddress = (unsigned __int64)GetModuleHandleW(MAPLESTORY_MODULE);
		if (mapleStoryBaseAddress == NULL) {
			printf("Failed to get module handle of the module '%s'", MAPLESTORY_MODULE);
			return false;
		}

		if (!installCreateProcessWHook(patchManager)) {
			return false;
		}

		installCopyFileWHook(patchManager);
		installLoadLibraryExHook(patchManager);
		return true;
	}
}