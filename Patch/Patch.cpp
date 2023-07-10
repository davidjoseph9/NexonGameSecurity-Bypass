#include "Patch.h"
#include "PatchManager.h"

#include <string>
#include <vector>
#include <fstream>
#include <TlHelp32.h>

namespace Patch {
	typedef LONG(NTAPI* NtSuspendProcess)(IN HANDLE ProcessHandle);

	bool endsWith(std::string const& fullString, std::string const& ending) {
		if (fullString.length() >= ending.length()) {
			return (0 == fullString.compare(fullString.length() - ending.length(), ending.length(), ending));
		}
		else {
			return false;
		}
	}

	bool endsWithW(std::wstring const& fullString, std::wstring const& ending) {
		if (fullString.length() >= ending.length()) {
			return (0 == fullString.compare(fullString.length() - ending.length(), ending.length(), ending));
		}
		else {
			return false;
		}
	}

	std::string unindent(const char* p)
	{
		std::string result;
		if (*p == '\n') ++p;
		const char* p_leading = p;
		while (std::isspace(*p) && *p != '\n')
			++p;
		size_t leading_len = p - p_leading;
		while (*p)
		{
			result += *p;
			if (*p++ == '\n')
			{
				for (size_t i = 0; i < leading_len; ++i)
					if (p[i] != p_leading[i])
						goto dont_skip_leading;
				p += leading_len;
			}
		dont_skip_leading:;
		}
		return result;
	}

	unsigned __int64 CopyModule(unsigned __int64 startAddress, unsigned __int64 size) {
		unsigned __int64 copyAddress = (unsigned __int64)VirtualAlloc(NULL, size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (copyAddress == NULL) {
			return NULL;
		}

		memcpy((void*)copyAddress, (void*)startAddress, size);
		return copyAddress;
	}

	unsigned __int64 CopyProcessModule(unsigned int processId, unsigned __int64 startAddress, unsigned __int64 size) {
		unsigned __int64 copyAddress = (unsigned __int64)VirtualAlloc(NULL, size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (copyAddress == NULL) {
			return NULL;
		}
		HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, 0, processId);
		if (hProcess == NULL) {
			printf("Cannot get process handle. OpenProcess failed.\n");
			return NULL;
		}

		SIZE_T bytesRead = 0;
		bool result = ReadProcessMemory(hProcess, (LPCVOID)startAddress, (LPVOID)copyAddress, size, &bytesRead);
		if (!result) return NULL;
		return copyAddress;
	}

	void SuspendProcessThreads(DWORD processId)
	{
		HANDLE hThreadSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
		DWORD currentThreadId = GetCurrentThreadId();
		THREADENTRY32 threadEntry;
		threadEntry.dwSize = sizeof(THREADENTRY32);

		Thread32First(hThreadSnapshot, &threadEntry);
		if (threadEntry.th32OwnerProcessID == processId && threadEntry.th32ThreadID != currentThreadId) {
			HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, threadEntry.th32ThreadID);
			SuspendThread(hThread);
			CloseHandle(hThread);
		}
		do
		{
			if (threadEntry.th32OwnerProcessID == processId && threadEntry.th32ThreadID != currentThreadId)
			{
				HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, threadEntry.th32ThreadID);

				SuspendThread(hThread);
				CloseHandle(hThread);
			}
		} while (Thread32Next(hThreadSnapshot, &threadEntry));

		CloseHandle(hThreadSnapshot);
	}

	void ResumeProcessThreads(DWORD processId)
	{
		HANDLE hThreadSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
		DWORD currentThreadId = GetCurrentThreadId();
		THREADENTRY32 threadEntry;
		threadEntry.dwSize = sizeof(THREADENTRY32);

		Thread32First(hThreadSnapshot, &threadEntry);
		if (threadEntry.th32ThreadID != currentThreadId) {
			HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, threadEntry.th32ThreadID);
			ResumeThread(hThread);
			CloseHandle(hThread);
		}
		do
		{
			if (threadEntry.th32OwnerProcessID == processId && threadEntry.th32ThreadID != currentThreadId)
			{
				HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, threadEntry.th32ThreadID);
				ResumeThread(hThread);
				CloseHandle(hThread);
			}
		} while (Thread32Next(hThreadSnapshot, &threadEntry));

		CloseHandle(hThreadSnapshot);
	}

	void SuspendProcess(DWORD processId)
	{
		HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);

		NtSuspendProcess ntSuspendProcess = (NtSuspendProcess)GetProcAddress(
			GetModuleHandleA("ntdll.dll"), "NtSuspendProcess");
		if (ntSuspendProcess == NULL) {
			printf("Failed to get NtSuspendProcess procedure");
		}
		ntSuspendProcess(processHandle);
		CloseHandle(processHandle);
	}

	bool InjectDll(DWORD pid, wchar_t* modulePath)
	{
		HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
		if (hProcess != INVALID_HANDLE_VALUE)
		{
			unsigned __int64 _LoadLibraryW = (unsigned __int64)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryW");
			if (_LoadLibraryW == NULL) {
				return false;
			}
			void* allocation = VirtualAllocEx(hProcess, NULL,  (2 * lstrlenW(modulePath)) + 1, MEM_COMMIT, PAGE_READWRITE);
			if (allocation == NULL) {
				return false;
			}
			WriteProcessMemory(hProcess, allocation, modulePath, (2 * lstrlenW(modulePath)) + 1, NULL);
			HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, LPTHREAD_START_ROUTINE(_LoadLibraryW), allocation, 0, NULL);
			if (hThread == NULL) {
				return false;
			}
			WaitForSingleObject(hThread, INFINITE);
			VirtualFreeEx(hProcess, allocation, NULL, MEM_RELEASE);
			CloseHandle(hThread);
			return true;
		}

		return false;
	}

	PROCESSENTRY32W GetChildProcessEntry(DWORD parentPID, LPCWSTR processName) {
		HANDLE hp = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		PROCESSENTRY32W processEntry = { 0 };
		processEntry.dwSize = sizeof(PROCESSENTRY32W);
		if (Process32FirstW(hp, &processEntry)) {
			do {
				if (processEntry.th32ParentProcessID == parentPID) {
					CloseHandle(hp);
					return processEntry;
				}
			} while (Process32NextW(hp, &processEntry));
		}
		CloseHandle(hp);
		throw exception("Child process cannot be found");
	}

	MODULEENTRY32W GetModuleEntry(DWORD processId, LPWSTR moduleName) {
		/* Build a list of allowed modules for Module32NextW filter
		 * creating the list at the start will allow additional DLLs
		 * to be injected into the process and evade detection.
		 */
		HANDLE hModuleSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, processId);
		printf("Created Toolhelp32 Snapshot %llX...\n", (unsigned __int64)hModuleSnapshot);
		MODULEENTRY32W moduleEntry;

		moduleEntry.dwSize = sizeof(MODULEENTRY32W);

		if (Module32FirstW(hModuleSnapshot, &moduleEntry)) {
			if (lstrcmpW(moduleEntry.szModule, moduleName) == 0) {
				CloseHandle(hModuleSnapshot);
				return moduleEntry;
			}

			do {
				if (lstrcmpW(moduleEntry.szModule, moduleName) == 0) {
					CloseHandle(hModuleSnapshot);
					return moduleEntry;
				}

			} while (Module32NextW(hModuleSnapshot, &moduleEntry));
		}
		else {
			printf("Module32First failed\n");
		}

		CloseHandle(hModuleSnapshot);
		throw exception("Cannot find the module specified");
	}

	vector<string> Split(const char* str, char c = ' ')
	{
		vector<string> result;

		do
		{
			const char* begin = str;

			while (*str != c && *str)
				str++;

			result.push_back(string(begin, str));
		} while (0 != *str++);

		return result;
	}

	string ReadTextFile(std::string path) {
		std::ifstream in(path);
		std::string contents((std::istreambuf_iterator<char>(in)),
			std::istreambuf_iterator<char>());
		return contents;
	}
}
