#pragma once

#include "pch.h"

#include <Windows.h>
#include <string>
#include <map>

#define PATCH_PAGE_SIZE	0x640000

using namespace std;

namespace Patch {
	class PatchManager
	{
	private:
		struct PatchMemory {
			unsigned char* start;
			unsigned char* next;
			unsigned int size;
		};
	public:
		enum PatchType {
			HOOK = 0,
			WRITE = 1
		};

		enum DisableAction {
			TOGGLE = 0,
			REVERT = 1
		};

		enum HookType {
			JUMP = 0,
			PTR = 1
			// CALL = 1
		};

		struct Patch {
			bool enabled = false;
			PatchType patchType = WRITE;
			DisableAction disableAction = TOGGLE;
			HookType hookType;
			string hookRegister;
			string name;
			string assembly;
			string writeBytes;
			unsigned __int64 codeCaveAddress = 0;
			unsigned __int64 address = 0;
			unsigned __int64 targetAddress = 0;
			unsigned char* originalMemory = 0;
			unsigned __int64 originalMemorySize = 0;
			unsigned int nopCount = 0;
		};
		unsigned __int64 gameCopyAddress = NULL;

		map<string, Patch*> patchMap;
		PatchMemory patchMemory;
		PatchManager();
		~PatchManager();
		string GetLastError();
		bool Setup();
		bool TogglePatch(bool enable, string patchName);
		bool InstallPatch(bool enable, Patch& patch);
		unsigned char* GetJumpPatchBytes(unsigned __int64 targetAddress, char* jumpRegister, SIZE_T* asmSize);
	};
}
