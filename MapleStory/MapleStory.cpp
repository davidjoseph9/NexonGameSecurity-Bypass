#include "../Patch/Patch.h"
#include "../Patch/PatchManager.h"
#include "../MapleStory/MapleStory.h"
#include "../BlackCall/BlackCall.h"

#include <windows.h>
#include <random>
#include <chrono>
#include <fstream>
#include <iostream>
#include <sstream>
#include <chrono>
#include <filesystem>
#include <iphlpapi.h>
#include <winternl.h>
#include <yaml-cpp/yaml.h>

#define BUFF_SIZE 2048

using namespace Patch;

HMODULE hKernelbase = NULL;
HMODULE hNtdll = NULL;
HMODULE hIPHLPAPI = NULL;
HMODULE hNetapi32 = NULL;

char currentModulePath[MAX_PATH];
wchar_t msgBoxBuf[255];
char patchNameBuf[255];

unsigned int blackCipherPid = -1;

unsigned __int64 maplestoryBaseAddress = 0;

const unsigned __int64 maplestoryCRCHookAddress = 0x1483DB751;
const unsigned __int64 maplestoryCRCBypassAddress = 0x1483D8128;
const unsigned __int64 maplestoryCRCBypassReturnAddress = 0x148370831;
const unsigned __int64 maplestoryCRCRegionSize = 0xE5F0000;

const unsigned __int64 processLoggingReturnAddress = 0x140E232D0;

const unsigned __int64 threadIdCheck1PatchAddress = 0x140E0048E;
const unsigned __int64 threadIdCheck1JmpAddress = 0x140E0064E;

const unsigned __int64 threadIdCheck2PatchAddress = 0x140E0067E;
const unsigned __int64 threadIdCheck2JmpAddress = 0x140E0083E;

unsigned __int64 getVolumeInformationWAddr = NULL;
unsigned __int64 ntOpenProcessAddr = NULL;

//GetVolumeInformationA()
typedef ULONG(__stdcall* _GetAdaptersInfo)(PIP_ADAPTER_INFO AdapterInfo, PULONG SizePointer);
typedef UCHAR(__stdcall* _Netbios)(PNCB pncb);
typedef BOOL(__stdcall* _GetVolumeInformationW)(LPCWSTR lpRootPathName, LPWSTR lpVolumeNameBuffer, DWORD nVolumeNameSize,
	LPDWORD lpVolumeSerialNumber, LPDWORD lpMaximumComponentLength, LPDWORD lpFileSystemFlags, LPWSTR lpFileSystemNameBuffer,
	DWORD nFileSystemNameSize);

namespace MapleStory {
	LPCWSTR MAPLESTORY_PROCESS = L"MapleStory.exe";
	LPCWSTR MAPLESTORY_MODULE = L"maplestory.exe";
	LPCWSTR BLACKCIPHER64 = L"BlackCipher64.aes";
	LPCWSTR MACHINE_ID_LIB_DLL = L"MachineIdLib.dll";
	LPCWSTR CRASH_REPORTER_DLL = L"CrashReporter_64.dll";
	LPCWSTR NEXON_ANALYTICS_DLL = L"NexonAnalytics64.dll";
	LPCWSTR KEYSTONE_DLL = L"keystone.dll";

	const char* KERNELBASE_DLL = "KERNELBASE.dll";
	const char* NTDLL_DLL = "ntdll.dll";
	const char* IPHLAPI_DLL = "IPHLPAPI.DLL";
	const char* NETAPI32_DLL = "NETAPI32.dll";
	// if process config not specified global configuration will be used
	const char* GLOBAL_CONFIG_FILENAME = "globalConfig.yaml"; 
	// process config will be used if one exists
	// this allows us to different HWID for different processes
	// launcher can be used to manage HWID and create/update this file
	const char* PROCESS_CONFIG_FILENAME = "config%X.yaml";

	unsigned int MAX_DLL_WAITTIME = 60; // secs to wait for ntdll copy module to load

	PatchManager patchManager = PatchManager();
	YAML::Node rootConfig;

	string configDir;
	bool dllsInjected = false;

	unsigned char* maplestoryCopyBase;
	char asmBuffer[BUFF_SIZE];

	unsigned __int64 machineId = 0;
	unsigned int volumeSerialNumber = 0;
	string macAddress;
	unsigned char macAddressRaw[6];

	std::string asmReturnFalse = Patch::unindent(R"(
        xor rax, rax
		ret
	)");
	std::string asmAbsoluteJumpAsm = R"(mov rax, 0x%llX; jmp rax)";
	std::string asmRelativeJump = R"(jmp 0x%llX)";

	std::string crcCodeCaveAsm = Patch::unindent(R"(
        mov rdx, 0x%llX
		sub rsi, rdx
		mov rdx, 0x%llX
        add rsi, rdx
		repe movsb
        xor rdx, rdx
		mov rsi, 0x%llX
		jmp rsi
	)");
	

	bool InstallCrcBypass(PatchManager& patchManager) {
		HMODULE hModule = GetModuleHandleW(MAPLESTORY_MODULE);
		if (hModule == NULL) {
			wprintf(L"Failed to get a handle of the module %s\n", MAPLESTORY_MODULE);
			return false;
		}
		maplestoryBaseAddress = (unsigned __int64)hModule;
		const unsigned __int64 bytesRead = 0;
		// create copy of memory region checked by CRC validation
		maplestoryCopyBase = (unsigned char*)VirtualAlloc(NULL, maplestoryCRCRegionSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (maplestoryCopyBase == NULL) {
			printf("Failed to allocate buffer for CRC memory region copy\n");
			return false;
		}
		memcpy(maplestoryCopyBase, (void*)(maplestoryBaseAddress + 0x1000), maplestoryCRCRegionSize);
		patchManager.gameCopyAddress = (unsigned __int64)maplestoryCopyBase;

		Patch::PatchManager::Patch patch1;

		patch1.name = "CRC Bypass";
		sprintf(asmBuffer, crcCodeCaveAsm.c_str(), maplestoryBaseAddress + 0x1000, maplestoryCopyBase, maplestoryCRCBypassReturnAddress);
		patch1.assembly = std::string(asmBuffer);
		patch1.patchType = Patch::PatchManager::PatchType::WRITE;
		patch1.address = maplestoryCRCBypassAddress;

		if (!patchManager.InstallPatch(true, patch1)) {
			return false;
		}

		Patch::PatchManager::Patch patch2;

		patch2.name = "CRC Hook";
		sprintf(asmBuffer, asmRelativeJump.c_str(), maplestoryCRCBypassAddress);
		patch2.assembly = std::string(asmBuffer);
		patch2.patchType = Patch::PatchManager::PatchType::WRITE;
		patch2.address = maplestoryCRCHookAddress;

		return patchManager.InstallPatch(true, patch2);
	}

	string GenerateMacAddress() {
		unsigned seed = std::chrono::system_clock::now().time_since_epoch().count();
		std::default_random_engine generator(seed);
		std::uniform_int_distribution<int> distribution(0, 255);

		constexpr int N = 6;
		std::stringstream sstream;
		sstream << std::setfill('0') << std::uppercase;
		for (int i = 0; i < N; ++i) {
			if (i > 0) sstream << ':';
			sstream << std::setw(2) << std::hex << distribution(generator);
		}

		return sstream.str();
	}

	int GenerateSerialNumber() {
		unsigned seed = std::chrono::system_clock::now().time_since_epoch().count();
		std::default_random_engine generator(seed);
		std::uniform_int_distribution<int> distribution(0, UINT_MAX);
		unsigned int serialNum = distribution(generator);
		return serialNum;
	}

	void SaveConfig(string configDir) {
		YAML::Node rootConfig;
		rootConfig["macAddress"] = macAddress;
		rootConfig["volumeSerialNumber"] = volumeSerialNumber;
		std::filesystem::path cfgPath{ configDir.c_str()};
		cfgPath.append(GLOBAL_CONFIG_FILENAME);
		printf("Saving the configuration to %s\n", cfgPath.string().c_str());
		
		std::ofstream configStream;
		configStream.open(cfgPath.string());
		std::string yamlConfig = YAML::Dump(rootConfig);
		configStream << yamlConfig;
		configStream.close();
	}

	bool LoadConfig(string cfgPath) {
		printf("Loading config %s\n", cfgPath.c_str());
		if (!std::filesystem::exists(cfgPath)) {
			return false;
		}
		rootConfig = YAML::Load(cfgPath);
		if (rootConfig.size() > 0) {
			if (YAML::Node volumeNode = rootConfig["volumeSerialNumber"]) {
				volumeSerialNumber = volumeNode.as<int>();
			}
			else {
				return false;
			}
			if (YAML::Node macNode = rootConfig["macAddress"]) {
				macAddress = macNode.as<string>();
			}
			else {
				return false;
			}
		}
		else {
			return false;
		}
		return true;
	}

	bool LoadPreferredConfig() {
		char cfgPath[MAX_PATH];
		sprintf(cfgPath, "%s/config%X.yaml", configDir.c_str(), GetCurrentProcessId());

		if (LoadConfig(cfgPath)) {
			return true;
		}
		sprintf(cfgPath, "%s/%s", configDir.c_str(), GLOBAL_CONFIG_FILENAME);
		return LoadConfig(cfgPath);
	}

	std::string getAdaptersInfoAsm = Patch::unindent(R"(
		mov r8, GetAdaptersInfo
		
		mov rax, 0x%llX
		jmp rax

	    GetAdaptersInfo:
        mov [rsp+0x08],rbx
        mov [rsp+0x20],rdi
		mov rax, 0x%llX
		jmp rax
	)");

	ULONG __stdcall GetAdaptersInfoHook(PIP_ADAPTER_INFO adapterInfo, PULONG SizePointer, unsigned __int64 pfnGetAdaptersInfo) {
		_GetAdaptersInfo getAdaptersInfo = (_GetAdaptersInfo)pfnGetAdaptersInfo;
		ULONG res = getAdaptersInfo(adapterInfo, SizePointer);
		if (res == ERROR_SUCCESS) {
			printf("GetAdaptersInfo - Spoofing MAC address: replacing %02x:%02x:%02x:%02x:%02x:%02x with %02x:%02x:%02x:%02x:%02x:%02x\n", 
				adapterInfo[0].Address[0], adapterInfo[0].Address[1], adapterInfo[0].Address[2], adapterInfo[0].Address[3], 
				adapterInfo[0].Address[4], adapterInfo[0].Address[5],
				macAddressRaw[0], macAddressRaw[1], macAddressRaw[2], macAddressRaw[3], macAddressRaw[4], macAddressRaw[5]);
			memcpy(adapterInfo[0].Address, macAddressRaw, sizeof(macAddressRaw));
		}
		return res;
	}

	bool InstallGetAdaptersInfoPatch(PatchManager& patchManager) {
		Patch::PatchManager::Patch patch;

		patch.address = (unsigned __int64)GetProcAddress(hIPHLPAPI, "GetAdaptersInfo");
		if (patch.address == NULL) {
			printf("Failed to patch %s.GetAdaptersInfo, cannot retrieve the address for the procedure address", IPHLAPI_DLL);
		}
		unsigned __int64 retAddress = patch.address + 0xA;
		sprintf_s(asmBuffer, getAdaptersInfoAsm.c_str(), &GetAdaptersInfoHook, retAddress);

		patch.patchType = PatchManager::PatchType::HOOK;
		patch.hookType = PatchManager::HookType::JUMP;

		sprintf(patchNameBuf, "%s.GetAdaptersInfo hook", IPHLAPI_DLL);
		patch.name = patchNameBuf;

		patch.assembly = std::string(asmBuffer);
		patch.hookRegister = "rax";
		patch.nopCount = 0;

		return patchManager.InstallPatch(true, patch);
	}

	std::string netbiosAsm = Patch::unindent(R"(
		mov rdx, Netbios

		mov rax, 0x%llX
		jmp rax

	    Netbios:
        mov [rsp+0x08],rbx
        push rdi
		sub rsp, 0x20
		mov rax, 0x%llX
		jmp rax
	)");

	UCHAR __stdcall NetbiosHook(PNCB pncb, unsigned __int64 pfnNetbios) {
		printf("Netbios cmd %02x\n", pncb->ncb_command);
		_Netbios netbios = (_Netbios)pfnNetbios;
		UCHAR res = netbios(pncb);
		if (pncb->ncb_command == NCBASTAT) {
			ADAPTER_STATUS* adapterStatus = (ADAPTER_STATUS*)pncb->ncb_buffer;
			printf("NETAPI32.Netbios - Spoofing MAC address: replacing %02x:%02x:%02x:%02x:%02x:%02x with %02x:%02x:%02x:%02x:%02x:%02x\n", 
				adapterStatus->adapter_address[0], adapterStatus->adapter_address[1], adapterStatus->adapter_address[2], 
				adapterStatus->adapter_address[3], adapterStatus->adapter_address[4], adapterStatus->adapter_address[5],
				macAddressRaw[0], macAddressRaw[1], macAddressRaw[2], macAddressRaw[3], macAddressRaw[4], macAddressRaw[5]);
			memcpy(adapterStatus->adapter_address, macAddressRaw, sizeof(macAddressRaw));
		}
		return res;
	}

	bool InstallNetbiosPatch(PatchManager& patchManager) {
		Patch::PatchManager::Patch patch;

		patch.address = (unsigned __int64)GetProcAddress(hNetapi32, "Netbios");
		if (patch.address == NULL) {
			printf("Failed to patch %s.Netbios, cannot retrieve the address for the procedure address", NETAPI32_DLL);
		}
		unsigned __int64 retAddress = patch.address + 0xA;
		sprintf_s(asmBuffer, netbiosAsm.c_str(), &NetbiosHook, retAddress);
		printf(asmBuffer);

		patch.patchType = PatchManager::PatchType::HOOK;
		patch.hookType = PatchManager::HookType::JUMP;

		sprintf(patchNameBuf, "%s.Netbios hook", NETAPI32_DLL);
		patch.name = patchNameBuf;

		patch.assembly = std::string(asmBuffer);
		patch.hookRegister = "rax";
		patch.nopCount = 0;

		return patchManager.InstallPatch(true, patch);
	}

	std::string getVolumeInformationWAsm = Patch::unindent(R"(
		push rcx
		mov rcx, 0x%llX
		mov rax, GetVolumeInformationW
		mov [rcx], rax
		pop rcx

		mov rax, 0x%llX
		jmp rax

	    GetVolumeInformationW:
        mov rax,rsp
        mov [rax+0x08],rbx
		mov [rax+0x10],rsi
		mov rsi, 0x%llX
		jmp rsi
	)");

	BOOL __stdcall GetVolumeInformationWHook(LPCWSTR lpRootPathName, LPWSTR lpVolumeNameBuffer, DWORD nVolumeNameSize,
		LPDWORD lpVolumeSerialNumber, LPDWORD lpMaximumComponentLength, LPDWORD lpFileSystemFlags, LPWSTR lpFileSystemNameBuffer,
		DWORD nFileSystemNameSize) {
		_GetVolumeInformationW getVolumeInformationW = (_GetVolumeInformationW)getVolumeInformationWAddr;

		bool res = getVolumeInformationW(lpRootPathName, lpVolumeNameBuffer, nVolumeNameSize, lpVolumeSerialNumber,
			lpMaximumComponentLength, lpFileSystemFlags, lpFileSystemNameBuffer, nFileSystemNameSize);

		if (lpVolumeSerialNumber != NULL) {
			wprintf(L"GetVolumeInformationW Spoof: replace 0x%X with 0x%X\n", *lpVolumeSerialNumber, volumeSerialNumber);
			*lpVolumeSerialNumber = volumeSerialNumber;
		}

		return true;
	}

	bool InstallGetVolumeInformationAPatch(PatchManager& patchManager) {
		Patch::PatchManager::Patch patch;

		patch.address = (unsigned __int64)GetProcAddress(hKernelbase, "GetVolumeInformationW");
		if (patch.address == NULL) {
			printf("Failed to patch %s.GetVolumeInformationA, cannot retrieve the address for the procedure address", KERNELBASE_DLL);
		}
		unsigned __int64 retAddress = patch.address + 0xB;
		sprintf_s(asmBuffer, getVolumeInformationWAsm.c_str(), &getVolumeInformationWAddr, &GetVolumeInformationWHook, retAddress);

		patch.patchType = PatchManager::PatchType::HOOK;
		patch.hookType = PatchManager::HookType::JUMP;

		sprintf(patchNameBuf, "%s.GetVolumeInformationW hook", NETAPI32_DLL);
		patch.name = patchNameBuf;

		patch.assembly = std::string(asmBuffer);
		patch.hookRegister = "rax";
		patch.nopCount = 0;

		return patchManager.InstallPatch(true, patch);
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

	std::string bcNtOpenProcessAsm = Patch::unindent(R"(
		mov rax, 0x%llX
	    cmp [rsp+0x70], rax
		jne NtOpenProcess

		push rcx
		mov rcx, 0x%llX
		mov rax, NtOpenProcess
		mov [rcx], rax
		pop rcx

        mov rax, 0x%llX
        jmp rax

	    NtOpenProcess:
        mov r10, rcx
        mov eax, 0x00000026
        syscall
		ret
	)");
	bool WINAPI NtOpenProcessHook(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, Patch::POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId) {
		if ((DWORD)ClientId->UniqueProcess == 0 || (DWORD)ClientId->UniqueProcess == GetCurrentProcessId() || (DWORD)ClientId->UniqueProcess == blackCipherPid) {
			printf("Allow access to NtOpenProcess for process 0x%X. MapleStory, BlackCipher64.aes, and system idle\n", (DWORD)ClientId->UniqueProcess);
			if (!dllsInjected && (DWORD)ClientId->UniqueProcess == blackCipherPid) {
				wprintf(L"Injecting bypass DLLs into the %s process\n", BLACKCIPHER64);
				dllsInjected = true;
				std::filesystem::path bypassDllPath = std::filesystem::path(currentModulePath);
				wchar_t buff[256];

				wsprintf(buff, L"%s/%s", (wchar_t*)bypassDllPath.parent_path().c_str(), KEYSTONE_DLL);
				std::filesystem::path keystoneDllPath = std::filesystem::path(buff);
				if (!Patch::InjectDll((DWORD)ClientId->UniqueProcess, (wchar_t*)keystoneDllPath.c_str())) {
					wprintf(L"Failed to inject %s\n", (wchar_t*)keystoneDllPath.c_str());
					return true;
				}

				wsprintf(buff, L"%s/%s", (wchar_t*)bypassDllPath.parent_path().c_str(), L"yaml-cpp.dll");
				wprintf(buff);
				std::filesystem::path yamlCppDllPath = std::filesystem::path(buff);
				if (!Patch::InjectDll((DWORD)ClientId->UniqueProcess, (wchar_t*)yamlCppDllPath.c_str())) {
					wprintf(L"Failed to inject %s\n", (wchar_t*)yamlCppDllPath.c_str());
					return true;
				}

				if (!Patch::InjectDll((DWORD)ClientId->UniqueProcess, (wchar_t*)bypassDllPath.c_str())) {
					wprintf(L"Failed to inject %s\n", (wchar_t*)bypassDllPath.c_str());
					return true;
				}
			}
			return true;
		}
		else {
			printf("Denying access to NtOpenProcess for the process 0x%X\n", (DWORD)ClientId->UniqueProcess);
			SetLastError(ERROR_ACCESS_DENIED);
			return false;
		}
	}

	bool InstallNtOpenProcessHook(PatchManager& patchManager) {
		Patch::PatchManager::Patch patch1;

		patch1.address = (unsigned __int64)GetProcAddress(hNtdll, "NtOpenProcess");
		if (patch1.address == NULL) {
			printf("Failed to get proc address of NtOpenProcess\n");
			return false;
		}

		patch1.address += 0x8;

		sprintf_s(asmBuffer, bcNtOpenProcessAsm.c_str(), processLoggingReturnAddress , &ntOpenProcessAddr, &NtOpenProcessHook);

		patch1.patchType = PatchManager::PatchType::HOOK;
		patch1.hookType = PatchManager::HookType::JUMP;
		patch1.name = "ntdll.NtOpenProcess hook";
		patch1.assembly = std::string(asmBuffer);
		patch1.hookRegister = "rax";
		patch1.nopCount = 0;

		patchManager.InstallPatch(true, patch1);

		return true;
	}

	bool GenerateTrainerWaitFile() {
		/*
		 * Generate a file to notify the trainer the bypass has completed installing patches
		 */
		char fileName[128];
		sprintf_s(fileName, "%s/NGSBypass%X-3", configDir.c_str(), GetCurrentProcessId());
		std::remove(fileName); // delete file if exists
		printf("Generating IPC file %s\n", fileName);
		std::filesystem::path path{ fileName };
		std::ofstream ofs(path);
		ofs.close();
		return true;
	}

	bool InstallPatches()
	{
		hNtdll = GetModuleHandleA(NTDLL_DLL);
		if (hNtdll == NULL) {
			wprintf(msgBoxBuf, L"Failed to get handle of module %s", NTDLL_DLL);
			MessageBoxW(NULL, msgBoxBuf, L"Error", MB_OK | MB_ICONERROR);
			return false;
		}

		hKernelbase = GetModuleHandleA(KERNELBASE_DLL);
		if (hKernelbase == NULL) {
			wprintf(msgBoxBuf, L"Failed to get handle of module %s", KERNELBASE_DLL);
			MessageBoxW(NULL, msgBoxBuf, L"Error", MB_OK | MB_ICONERROR);
			return false;
		}

		hIPHLPAPI = GetModuleHandleA(IPHLAPI_DLL);
		if (hIPHLPAPI == NULL) {
			wprintf(msgBoxBuf, L"Failed to get handle of module %s ", IPHLAPI_DLL);
			MessageBoxW(NULL, msgBoxBuf, L"Error", MB_OK | MB_ICONERROR);
			return false;
		}

		hNetapi32 = GetModuleHandleA(NETAPI32_DLL);
		if (hNetapi32 == NULL) {
			wprintf(msgBoxBuf, L"Failed to get handle of module %s ", NETAPI32_DLL);
			MessageBoxW(NULL, msgBoxBuf, L"Error", MB_OK | MB_ICONERROR);
			return false;
		}

		patchManager.Setup();
		configDir = getenv("appdata") + string("/NGSBypass");
		
		if (!LoadPreferredConfig()) {
			macAddress = GenerateMacAddress();
			volumeSerialNumber = GenerateSerialNumber();
			SaveConfig(configDir);
		}

		if (macAddress.length() != 16) {
			macAddress = GenerateMacAddress();
			SaveConfig(configDir);
		}

		if (volumeSerialNumber == 0) {
			volumeSerialNumber = GenerateSerialNumber();
		}

		printf("MAC address: %s\n", macAddress.c_str());
		printf("Volume Serial Number: 0x%X\n", volumeSerialNumber);

		string macRawStr = macAddress;
		macRawStr.erase(std::remove(macRawStr.begin(), macRawStr.end(), ':'), macRawStr.end());

		HexToBytes(macRawStr.c_str(), macAddressRaw);

		if (!InstallNtOpenProcessHook(patchManager)) {
			MessageBoxW(NULL, L"Failed to install NtOpenProcess patches", L"Error", MB_OK | MB_ICONERROR);
			return false;
		}

		HANDLE hProcessSnapShot = NULL;
		unsigned int counter = 0;
		bool bcfound = false;
		do {
			hProcessSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
			PROCESSENTRY32W pe;
			pe.dwSize = sizeof(PROCESSENTRY32W);
			if (Process32FirstW(hProcessSnapShot, &pe)) {
				do {
					if (endsWithW(pe.szExeFile, BLACKCIPHER64)) {
						blackCipherPid = pe.th32ProcessID;
						bcfound = true;
						break;
					}
				} while (Process32NextW(hProcessSnapShot, &pe));
			}
			else {
				wprintf(L"[Process32NextW] Failed to get information on the process %s\n", BLACKCIPHER64);
				return false;
			}
			Sleep(50);
		} while (!bcfound && counter++ < MAX_DLL_WAITTIME * 20);

		CloseHandle(hProcessSnapShot);

		if (!bcfound) {
			return false;
		}

		if (!BlackCall::InstallPatches(&blackCipherPid)) {
			MessageBoxW(NULL, L"Failed to install BlackCall64.aes patches", L"Error", MB_OK | MB_ICONERROR);
			return false;
		}

		patchManager.Setup();

		if (!InstallCrcBypass(patchManager)) {
			MessageBoxW(NULL, L"Failed to install the CRC bypass", L"Error", MB_OK | MB_ICONERROR);
			return false;
		}

		bool success = InstallGetAdaptersInfoPatch(patchManager) &&
			InstallNetbiosPatch(patchManager) &&
			InstallGetVolumeInformationAPatch(patchManager);

		if (!success) {
			MessageBoxW(NULL, L"Failed to install maplestory.exe HWID patches", L"Error", MB_OK | MB_ICONERROR);
			return false;
		}
		
		success = InstallThreadIdCheckPatch(patchManager) &&
			InstallIsDebuggerPresentPatch(patchManager) &&
			InstallNexonAnalyticsLogsPatch(patchManager) &&
			InstallCrashReporterPatch(patchManager);

		if (!success) {
			MessageBoxW(NULL, L"Failed to install maplestory.exe secondary patches", L"Error", MB_OK | MB_ICONERROR);
			return false;
		}

		// InstallUnknownRoutinePatch(patchManager); // heavily virtualized routine; not necessary
		GenerateTrainerWaitFile();
		return true;
	}

	void Main(HMODULE hModule) 
	{
		if (GetModuleFileNameA(hModule, currentModulePath, sizeof(currentModulePath))) {
			if (InstallPatches()) {
				return;
			}
		}
		
		wprintf(L"Failed to install %s patches\n", MAPLESTORY_PROCESS);
		wprintf(L"Terminating the process in 5 seconds...\n");
		Sleep(5000);
		TerminateProcess(GetCurrentProcess(), 1);
	}
}