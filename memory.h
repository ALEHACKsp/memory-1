#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <memory>
#include <string>
#include <vector>

namespace Mem
{
	const void KillProcess(const char* ProcessName) noexcept(true)
	{
		std::string buffer = "taskkill /IM ";
		buffer.append(ProcessName).append(" /F");
		system(buffer.c_str());
	}
	namespace External {
#if _WIN32
		std::uint32_t GetProcId32(const wchar_t* processName)
		{
			std::uint32_t ProcessId = NULL;
			HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
			if (!(hSnap == NULL))
			{
				PROCESSENTRY32 pe32;
				pe32.dwSize = sizeof(pe32);
				if (Process32First(hSnap, &pe32))
					while (Process32Next(hSnap, &pe32))
						if (wcscmp(processName, pe32.szExeFile))
						{
							ProcessId = pe32.th32ProcessID;
							break;
						}

			}
			CloseHandle(hSnap);
			return ProcessId;
		}

		std::uint32_t GetModuleBase32(std::uint32_t ProcessId, const wchar_t* moduleName)
		{
			std::uint32_t BaseAddress = NULL;
			HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE32 | TH32CS_SNAPMODULE, ProcessId);
			if (!(hSnap == NULL))
			{
				MODULEENTRY32 me32;
				me32.dwSize = sizeof(me32);
				if (Module32FirstW(hSnap, &me32))
					while (Module32NextW(hSnap, &me32))
						if (wcscmp(moduleName, me32.szModule))
						{
							BaseAddress = reinterpret_cast<std::uint32_t>(me32.modBaseAddr);
							break;
						}
					
			}
			CloseHandle(hSnap);
			return BaseAddress;
		}

		std::uintptr_t GetPointerAddress(HANDLE ProcessHandle,
			std::uintptr_t baseOfModule, std::vector<std::uintptr_t> pointers)
		{
			std::uintptr_t address = baseOfModule;
			for (std::uintptr_t i{ 0 }; i < pointers.size(); i++)
			{
				address = ReadProcessMemory(ProcessHandle, (BYTE*)address, &address, sizeof(address), 0);
				address += pointers[i];
			}
			return address;
		}

		template<typename T>
		inline void WPM(HANDLE ProcessHandle, ULONG Address, T value)
		{
			WriteProcessMemory(ProcessHandle, reinterpret_cast<LPVOID>(Address), &value, sizeof(value), 0);
		}

		template<typename T>
		inline T RPM(HANDLE ProcessHandle, ULONG Address)
		{
			T buffer;
			ReadProcessMemory(ProcessHandle, reinterpret_cast<LPVOID>(Address), &buffer, sizeof(buffer), 0);
			return buffer;
		}


#else 
		std::uint64_t GetProcId64(std::string process_name)
		{
			std::uint32_t ProcessId = NULL;
			HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
			if (!(hSnap == NULL))
			{
				PROCESSENTRY32 pe32;
				pe32.dwSize = sizeof(pe32);
				if (Process32First(hSnap, &pe32))
					while (Process32Next(hSnap, &pe32))
						if (!strcmp(process_name.c_str(), (const char*)pe32.szExeFile))
						{
							ProcessId = pe32.th32ProcessID;
							break;
						}

			}
			CloseHandle(hSnap);
			return ProcessId;
		}

		std::uint64_t GetModuleBase64(std::uint64_t ProcessId, const char* moduleName)
		{
			std::uint32_t BaseAddress = NULL;
			HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE32 | TH32CS_SNAPMODULE, ProcessId);
			if (!(hSnap == NULL))
			{
				MODULEENTRY32 me32;
				me32.dwSize = sizeof(me32);
				if (Module32First(hSnap, &me32))
					while (Module32Next(hSnap, &me32))
						if (strcmp(moduleName, (const char*)me32.szModule))
						{
							BaseAddress = reinterpret_cast<std::uint32_t>(me32.modBaseAddr);
							break;
						}

			}
			CloseHandle(hSnap);
			return BaseAddress;
		}
#endif
	}

	namespace Internal
	{
		/*
		
			Inlining functions:
			Remember, inlining is only a request to the compiler, 
			not a command. Compiler can ignore the request for inlining. 
			Compiler may not perform inlining in such circumstances like:

			1) If a function contains a loop. (for, while, do-while)
			2) If a function contains static variables.
			3) If a function is recursive.
			4) If a function return type is other than void, and the return statement doesn’t exist in function body.
			5) If a function contains switch or goto statement.

		*/

		template<typename T> 
		inline void WPM(ULONG Address, T value)
		{
			try { *(T*)Address = value; }
			catch (...) {}
		}

		template<typename T> 
		inline T RPM(ULONG Address)
		{
			try { return *(T*)Address; }
			catch (...) {}
		}

		inline FARPROC GetExportAddress(const char* ModuleName, const char* FunctionName)
		{
			FARPROC Address = GetProcAddress(GetModuleHandleA(ModuleName), FunctionName);
			return Address;
		}


		std::uintptr_t GetPointerAddress(std::uintptr_t baseOfModule, std::vector<std::uintptr_t> pointers)
		{
			std::uintptr_t address = baseOfModule;
			for (std::uintptr_t i{ 0 }; i < pointers.size(); i++)
			{
				address = *reinterpret_cast<std::uintptr_t*>(address);
				address += pointers[i];
			}
			return address;
		}

	}
}
