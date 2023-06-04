#include "pch.h"
#include "PatchManager.h"
#include "BlackCipher.h"
#include "MapleStory.h"
#include "Patch.h"

#include <iostream>

using namespace std;

std::string BLACKCIPHER_PROCESS_NAME = "BlackCipher64.aes";
std::string MAPLESTORY_PROCESS_NAME = "maplestory.exe";
const char* CONSOLE_TITLE = "Debug Console - %s";

char buff[64];

void SetupConsole(std::string moduleName) {
	if (!AllocConsole()) {
		MessageBoxA(NULL, "Cannot allocate a console", "Error", MB_OK);
		return;
	}

	freopen("CONOUT$", "wt", stdout);
	
	sprintf(buff, CONSOLE_TITLE, moduleName.c_str());
	SetConsoleTitleA(buff);
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_RED);
}

bool APIENTRY DllMain(HMODULE hModule, DWORD  dwReason, LPVOID lpReserved) {
	if (dwReason == DLL_PROCESS_ATTACH) {
		char moduleFilePath[MAX_PATH];
		GetModuleFileNameA(GetModuleHandle(NULL), moduleFilePath, MAX_PATH);

		if (Patch::endsWith(moduleFilePath, BLACKCIPHER_PROCESS_NAME)) {
			SetupConsole(BLACKCIPHER_PROCESS_NAME);
			CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)&BlackCipher::InstallPatches, NULL, 0, NULL);
		}
		else if (Patch::endsWith(moduleFilePath, MAPLESTORY_PROCESS_NAME)) {
			SetupConsole(MAPLESTORY_PROCESS_NAME);
			CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)&MapleStory::InstallPatches, NULL, 0, NULL);
		}
		DisableThreadLibraryCalls(hModule);
	}
	return TRUE;
}
