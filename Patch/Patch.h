#pragma once

#include <string>
#include <vector>
#include <windows.h>
#include <TlHelp32.h>

#define STATUS_ACCESS_DENIED 0xC0000022

using namespace std;

namespace Patch {
	typedef long NTSTATUS;
    typedef enum _SYSTEM_INFORMATION_CLASS {
        SystemBasicInformation,
        SystemProcessorInformation,
        SystemPerformanceInformation,
        SystemTimeOfDayInformation,
        SystemPathInformation,
        SystemProcessInformation,
        SystemCallCountInformation,
        SystemDeviceInformation,
        SystemProcessorPerformanceInformation,
        SystemFlagsInformation,
        SystemCallTimeInformation,
        SystemModuleInformation,
        SystemLocksInformation,
        SystemStackTraceInformation,
        SystemPagedPoolInformation,
        SystemNonPagedPoolInformation,
        SystemHandleInformation,
        SystemObjectInformation,
        SystemPageFileInformation,
        SystemVdmInstemulInformation,
        SystemVdmBopInformation,
        SystemFileCacheInformation,
        SystemPoolTagInformation,
        SystemInterruptInformation,
        SystemDpcBehaviorInformation,
        SystemFullMemoryInformation,
        SystemLoadGdiDriverInformation,
        SystemUnloadGdiDriverInformation,
        SystemTimeAdjustmentInformation,
        SystemSummaryMemoryInformation,
        SystemNextEventIdInformation,
        SystemEventIdsInformation,
        SystemCrashDumpInformation,
        SystemExceptionInformation,
        SystemCrashDumpStateInformation,
        SystemKernelDebuggerInformation,
        SystemContextSwitchInformation,
        SystemRegistryQuotaInformation,
        SystemExtendServiceTableInformation,
        SystemPrioritySeperation,
        SystemPlugPlayBusInformation,
        SystemDockInformation,
        SystemPowerInformation,
        SystemProcessorSpeedInformation,
        SystemCurrentTimeZoneInformation,
        SystemLookasideInformation
    } SYSTEM_INFORMATION_CLASS, * PSYSTEM_INFORMATION_CLASS;

	bool endsWith(string const& fullString, string const& ending);
	bool endsWithW(wstring const& fullString, wstring const& ending);
	string unindent(const char* p);
	unsigned __int64 CopyModule(unsigned __int64 startAddress, unsigned __int64 size);
	unsigned __int64 CopyProcessModule(unsigned int processId, unsigned __int64 startAddress, unsigned __int64 size);
	void SuspendProcess(DWORD processId);
	void SuspendProcessThreads(DWORD processId);
	void ResumeProcessThreads(DWORD processId);
	PROCESSENTRY32W GetChildProcessEntry(DWORD parentPID, LPCWSTR processName);
	MODULEENTRY32W GetModuleEntry(DWORD processId, LPWSTR moduleName);
	string ReadTextFile(std::string path);
	vector<string> Split(const char* str, char c);
    bool InjectDll(DWORD pid, wchar_t* modulePath);
}