#pragma once
#include <Windows.h>
#include <Tlhelp32.h>
#include <iostream>
#include <vector>

namespace Memory
{
	template<typename T> auto wpm(PVOID lpProcessHandle, uintptr_t address, T value) -> BOOL
	{
		return ((WriteProcessMemory(lpProcessHandle, (LPVOID)address, &value, sizeof(value), 0)));
	}

	template<typename T> auto rpm(PVOID lpProcessHandle, uintptr_t address, T valueToRead) -> BOOL
	{
		return ((ReadProcessMemory(lpProcessHandle, (LPVOID)address, &valueToRead, sizeof(valueToRead), NULL)));
	}

	auto GetProcId(const char* processName) -> ULONG
	{
		PVOID list = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (list == nullptr || list == INVALID_HANDLE_VALUE)
		{
			CloseHandle(list);
			return 0;
		}
		ULONG ID = 0;
		PROCESSENTRY32 pe32;
		pe32.dwSize = sizeof(pe32);

		if (!Process32First(list, &pe32)) {
			CloseHandle(list);
			return 0;
		} while (Process32Next(list, &pe32)) {
			if (!strcmp(processName, pe32.szExeFile)) {
				ID = pe32.th32ProcessID;
				break;
			}
		}
		CloseHandle(list);
		return ID;
	}

	auto GetModuleBase(ULONG ProcessID, const char* moduleName) -> uintptr_t
	{
		//Create a snapshot of all the modules in our process
		PVOID list = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, ProcessID);
		if (list == nullptr || list == INVALID_HANDLE_VALUE) {
			CloseHandle(list);
			return 0;
		}
		uintptr_t baseAddress = 0;
		//Set the structure
		MODULEENTRY32 me32;
		me32.dwSize = sizeof(me32);

		if (!Module32First(list, &me32)) // If we can't find the first module then...
		{
			CloseHandle(list);
			return 0;
		}
		while (Module32Next(list, &me32)) { //Keep looping through all of our modules
			if (!strcmp(moduleName, (const char*)me32.szModule)) {
				//If the module corresponds to the moduleName return
				baseAddress = reinterpret_cast<uintptr_t>(me32.modBaseAddr);
				break;
			}
		}
		CloseHandle(list);
		return baseAddress;
		
	}

	auto GetPointerAddress(PVOID lpProcessHandle, uintptr_t moduleBase, std::vector<unsigned int> pointers) -> uintptr_t
	{
		uintptr_t address = 0;
		for (unsigned int i = 0; i < pointers.size(); i++) {
			ReadProcessMemory(lpProcessHandle, (BYTE*)address, &address, sizeof(address), 0);
			address += pointers[i];
		}
		return address;
	}

	namespace Internal
	{
		template<typename T> auto wpm(uintptr_t address, T value) -> void {
			*(T*)address = value;
		}

		template<typename T> T rpm(uintptr_t address) {
			return ((*(T*)address));
		}

		uintptr_t GetModuleBase(const char* moduleName) {
			return (((uintptr_t)GetModuleHandleA(moduleName)));
		}

		uintptr_t GetPointerAddress(uintptr_t moduleBase, std::vector<unsigned int> pointers)
		{
			uintptr_t address = 0;
			for (unsigned int i = 0; i < pointers.size(); ++i) {
				address = *(uintptr_t*)address;
				address += pointers[i];
			}
			return address;
		}
	}
}