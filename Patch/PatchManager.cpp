#include "Patch.h"
#include "PatchManager.h"

#include <Windows.h>
#include <keystone/keystone.h>

#include <strsafe.h>
#include <intrin.h>
#include <inttypes.h>

#include <string>
#include <algorithm>
#include <vector>
#include <map>

#pragma warning(disable: 4733)
#pragma comment(lib, "ntdll")

#define DEFAULT_HOOK_REGISTER "r10"
#define ASM_BUFFER_SIZE 2048

using namespace std;

namespace Patch {
	char asmCode[ASM_BUFFER_SIZE];
	char logBuff[ASM_BUFFER_SIZE];

	ks_engine* ks;
	string lastError = "";

	PatchManager::PatchManager() {
		this->patchMemory.next = NULL;
		this->patchMemory.start = NULL;
		this->patchMemory.size = NULL;
	}

	PatchManager::~PatchManager() {
		ks_close(ks);
	}

	string PatchManager::GetLastError() {
		return lastError;
	}

	bool PatchManager::Setup() {
		ks_err err = ks_open(KS_ARCH_X86, KS_MODE_64, &ks);
		if (err != KS_ERR_OK) {
			printf("ERROR: failed on ks_open(), quit\n");
			return false;
		}

		this->patchMemory.start = (unsigned char*)VirtualAlloc(NULL, PATCH_PAGE_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		this->patchMemory.next = this->patchMemory.start;
		this->patchMemory.size = PATCH_PAGE_SIZE;

		return true;
	}

	bool PatchManager::TogglePatch(bool enable, string patchName) {
		printf("Toggle the patch %s\n", patchName.c_str());
		if (!this->patchMap.count(patchName)) {
			printf("The patch %s cannot be found", patchName.c_str());
			//lastError = std::string(logBuff);
			return false;
		}
		

		return true;
	}

	bool PatchManager::InstallPatch(bool enable, Patch& patch) {
		printf("Installing the patch '%s'\n", patch.name.c_str());

		patch.enabled = enable;
		unsigned char* writeBytes = NULL;
		SIZE_T writeSize = 0;
		size_t asmSize;

		if (enable) {
			if (patch.assembly.empty()) return false;
			unsigned __int64 asmRelativeAddress;
			if (patch.patchType == PatchType::HOOK) {
				asmRelativeAddress = (unsigned __int64)this->patchMemory.next;
			}
			else {
				asmRelativeAddress = patch.address;
			}
			size_t count;
			unsigned char* encode;

			if (ks_asm(ks, patch.assembly.c_str(), asmRelativeAddress, &encode, &asmSize, &count) != KS_ERR_OK) {
				printf("ERROR: ks_asm() failed & count = %d, error = %d\n", (int)count, ks_errno(ks));
				return false;
			}
			else {
#ifdef DEBUG
				size_t i;
				for (i = 0; i < asmSize; i++) {
					printf("%02x ", encode[i]);
				} 
				printf("\n");
#endif
			}

			if (patch.patchType == PatchType::HOOK)
			{
				printf("Writing code cave (%d) to 0x%llx\n", (unsigned int)asmSize, (unsigned __int64)this->patchMemory.next);

				SIZE_T bytesWritten;
				WriteProcessMemory(GetCurrentProcess(), (LPVOID)this->patchMemory.next, encode, asmSize, &bytesWritten);
				if (bytesWritten != asmSize) {
					printf("Cannot install the patch '%s'. WriteProcessMemory wrote  %llu/%llu bytes\n", patch.name.c_str(), bytesWritten, asmSize);
					return false;
				}
				patch.codeCaveAddress = (unsigned __int64)this->patchMemory.next;
				this->patchMemory.next += asmSize;

				if (patch.hookType == HookType::JUMP) {
					if (patch.hookRegister.empty()) {
						patch.hookRegister = DEFAULT_HOOK_REGISTER;
					}
					writeBytes = this->GetJumpPatchBytes(patch.codeCaveAddress, (char*)patch.hookRegister.c_str(), &bytesWritten);
					writeSize = bytesWritten;
				}
			}
			else {
				writeSize = asmSize;
				writeBytes = encode;
			}
			printf("Writing patch (%llx) to 0x%llx\n", writeSize, patch.address);

			if (patch.hookType == HookType::PTR) {
				DWORD dwRestoreProtect;
				VirtualProtect((LPVOID)patch.address, sizeof(__int64), PAGE_EXECUTE_READWRITE, &dwRestoreProtect);

				*(unsigned __int64*)patch.address = patch.targetAddress;

				DWORD dwOldProtect;
				VirtualProtect((LPVOID)patch.address, sizeof(__int64), dwRestoreProtect, &dwOldProtect);
			}
			else {
				if (writeSize == 0) {
					return false;
				}

				HANDLE hProcess = GetCurrentProcess();
				DWORD dwRestoreProtect;
				VirtualProtect((LPVOID)patch.address, writeSize + patch.nopCount, PAGE_EXECUTE_READWRITE, &dwRestoreProtect);

				SIZE_T bytesRead = 0;
				if (ReadProcessMemory(hProcess, (LPVOID)patch.address, this->patchMemory.next, writeSize + patch.nopCount, &bytesRead)) {
					patch.originalMemorySize = bytesRead;
					patch.originalMemory = writeBytes;
				}

				patch.originalMemory = this->patchMemory.next;
				patch.originalMemorySize = bytesRead;
				this->patchMemory.next += bytesRead;

				SIZE_T bytesWritten = 0;
				WriteProcessMemory(hProcess, (LPVOID)patch.address, writeBytes, writeSize, &bytesWritten);
				if (bytesWritten != writeSize) {
					printf("Cannot install the patch '%s'\nWriteProcessMemory failed to write the patch to '0x%llx'\n", patch.name.c_str(), patch.address);
					return false;
				}
				memset((void*)(patch.address + writeSize), 0x90, patch.nopCount);

				DWORD dwOldProtect;
				VirtualProtect((LPVOID)patch.address, writeSize + patch.nopCount, dwRestoreProtect, &dwOldProtect);
			}

			if (writeBytes != NULL) {
				ks_free(writeBytes);
			}
		}
		else {
			printf("Uninstalling the patch '%s'", patch.name.c_str());
			if (patch.disableAction == REVERT) {
				if (patch.originalMemory != NULL) {
					DWORD dwRestoreProtect;
					VirtualProtect((LPVOID)patch.address, patch.originalMemorySize, PAGE_EXECUTE_READWRITE, &dwRestoreProtect);

					SIZE_T bytesWritten;
					WriteProcessMemory(GetCurrentProcess(), (LPVOID)patch.address, patch.originalMemory, patch.originalMemorySize, &bytesWritten);
					if (bytesWritten != patch.originalMemorySize) {
						printf("Cannot uninstall the patch '%s'. WriteProcessMemory failed to write the original memory to '0x%llX'", patch.name.c_str(), patch.address);
						return false;
					}

					DWORD dwOldProtect;
					VirtualProtect((LPVOID)patch.address, patch.originalMemorySize, dwRestoreProtect, &dwOldProtect);
				}
			} 
			// else if (patch.disableAction == TOGGLE) return true;
		}
		
		auto it = patchMap.find(patch.name);
		if (it == patchMap.end()) {
			printf("Adding patch '%s' to the patch map\n", patch.name.c_str());
			patchMap.insert(std::pair<std::string, Patch*>(patch.name, &patch));
		}
		return true;
	}

	unsigned char* PatchManager::GetJumpPatchBytes(unsigned __int64 targetAddress, char* jumpRegister, SIZE_T* asmSize) {
		sprintf_s(asmCode, "mov %s, 0x%llx; jmp %s;\n", jumpRegister, targetAddress, jumpRegister);
		size_t count;
		unsigned char* encode;

		if (ks_asm(ks, asmCode, 0, &encode, asmSize, &count) != KS_ERR_OK) {
			printf("ERROR: ks_asm() failed & count = %X, error = 0x%X\n", (unsigned long)count, ks_errno(ks));
		}
		return encode;
	}
}
