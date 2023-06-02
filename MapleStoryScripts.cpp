#include "pch.h"
#include <string>
#include "Patch.h"
#include "PatchManager.h"
#include "MapleStory.h"

using namespace Patch;

#define BUFF_SIZE 256
char asmBuffer[BUFF_SIZE];

namespace MapleStory {
	std::string NoDelayNPCInteractionAsm = Patch::unindent(R"(
		cmp byte ptr [0x%llX], 00
		je OriginalCode
		mov rax, 0x14431512A
		jmp rax
    
		OriginalCode:
		test rax, rax
		je OriginalExit2

		OriginalExit:
		mov rcx, [0x145D1CF50]
		mov rax, 0x144315121
		jmp rax

		OriginalExit2:
		mov rax, 0x14431513B
		jmp rax
	)");

	PatchManager::Patch patchNoDelayNPCInteraction;

	void InstallNoDelayNPCInteraction(PatchManager& patchManager) {
		printf("Installing No Delay Interaction\n");

		PatchManager::Patch patch = patchNoDelayNPCInteraction;

		patch.name = "No Delay NPC Interaction";

		sprintf(asmBuffer, NoDelayNPCInteractionAsm.c_str(), &patch.enabled);
		patch.patchType = PatchManager::PatchType::HOOK;
		patch.hookType = PatchManager::HookType::JUMP;
		patch.address = 0x144315118;
		patch.assembly = std::string(asmBuffer);
		patch.hookRegister = "r8";
		patch.nopCount = 4;

		patchManager.InstallPatch(true, patch);
	}

	void InstallPatches(PatchManager& patchManager) {
		printf("Installing patches\n");
		InstallNoDelayNPCInteraction(patchManager);
	}
}
