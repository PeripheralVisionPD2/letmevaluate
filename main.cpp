#include <windows.h>
#include <iostream>
#include <tlhelp32.h>
#include <tchar.h>
#include <comdef.h>
#include <stdio.h>

DWORD GetProcessIdByName(const char* procName) {
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (Process32First(snapshot, &entry) == TRUE) {
		while (Process32Next(snapshot, &entry) == TRUE) {
			const WCHAR* wc = L"Hello World";
			_bstr_t b(entry.szExeFile);
			const char* c = b;
			//printf(c);
			if (_stricmp(c, procName) == 0) {
				CloseHandle(snapshot);
				return entry.th32ProcessID;
			}
		}
	}
}

int main() {
	std::cin.get();
	DWORD processId = GetProcessIdByName("reaper.exe");
	printf("%d\n", processId);
	long long address = 0x1401caa55;
	BYTE data[] = { 0x75 }; /// replacing jz to jnz
	SIZE_T size = sizeof(data);

	// Open the target process
	HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
	if (process == NULL) {
		std::cerr << "Failed to open process!" << std::endl;
		return 1;
	}

	// Change the memory protection to read-write
	DWORD oldProtect;
	if (!VirtualProtectEx(process, (void*)address, size, PAGE_READWRITE, &oldProtect)) {
		std::cerr << "Failed to change memory protection!" << std::endl;
		return 1;
	}
	BYTE buffer2[1024];
	SIZE_T bytesRead2;
	ReadProcessMemory(process, (void*)address, &buffer2, sizeof(int), &bytesRead2);
	std::cout << std::hex << (int)buffer2[0] << std::endl;
	// Write to the memory
	SIZE_T bytesWritten;
	if (!WriteProcessMemory(process, (void*)address, data, size, &bytesWritten)) {
		std::cerr << "Failed to write to memory!" << std::endl;
		return 1;
	}
	BYTE buffer[1024];
	SIZE_T bytesRead;
	ReadProcessMemory(process, (void*)address, &buffer, sizeof(int), &bytesRead);
	std::cout << std::hex << (int)buffer[0] << std::endl;
	// Restore the old memory protection
	if (!VirtualProtectEx(process, (void*)address, size, oldProtect, &oldProtect)) {
		std::cerr << "Failed to restore memory protection!" << std::endl;
		return 1;
	}

	std::cout << "Successfully wrote to memory!" << std::endl;
	// Close the handle to the process
	CloseHandle(process);

	return 0;
}
