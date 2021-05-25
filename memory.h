#pragma once
#ifndef MEMORY_H
#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include <vector>

#define EASY_USE 0

namespace Mem
{

#if EASY_USE
	using namespace External;
	using namespace Internal;
#endif

	const void KillProcess(const char* ProcessName) noexcept(true)
	{
		std::string buffer = "taskkill /IM ";
		buffer += ProcessName;
		buffer += " /F";

		system(buffer.c_str());
	}

	const void CloseSafeHandle(const HANDLE handle) 
	{
		if (handle != INVALID_HANDLE_VALUE && handle != nullptr)
		{
			try 
			{
				CloseHandle(handle);
			}
			catch (std::exception& e) { MessageBoxA(0, e.what(), "CloseSafeHandle: Exception", MB_OK | MB_ICONERROR); }
		}
	}

	namespace Utils
	{
		BOOL IsDebugged()
		{
			BOOL result;
			return CheckRemoteDebuggerPresent(GetCurrentProcess(), &result);
		}

		const char* GetCurrentProcessName()
		{
			char buffer[MAX_PATH];
			if (GetModuleFileNameA(GetModuleHandleA(0), buffer, MAX_PATH))
				return buffer;
		}

		void RenameCurrentProcess(const char* newName)
		{
			try
			{
				rename(GetCurrentProcessName(), newName);
			}
			catch (...) {}
		}

		std::string ConvertToString(const char* ptr)
		{
			return static_cast<std::string>(ptr);
		}

		const char* ConvertToCharPtr(std::string str)
		{
			return str.c_str();
		}
	}

	namespace External 
	{
#if _WIN32
#if UNICODE
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
			CloseSafeHandle(hSnap);
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
			CloseSafeHandle(hSnap);
			return BaseAddress;
		}
#else
		std::uint32_t GetProcId32(const char* processName)
		{
			std::uint32_t ProcessId = NULL;
			HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
			if (!(hSnap == NULL))
			{
				PROCESSENTRY32 pe32;
				pe32.dwSize = sizeof(pe32);
				if (Process32First(hSnap, &pe32))
					while (Process32Next(hSnap, &pe32))
						if (strcmp(processName, pe32.szExeFile))
						{
							ProcessId = pe32.th32ProcessID;
							break;
						}

			}
			CloseSafeHandle(hSnap);
			return ProcessId;
		}

		std::uint32_t GetModuleBase32(std::uint32_t ProcessId, const char* moduleName)
		{
			std::uint32_t BaseAddress = NULL;
			HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE32 | TH32CS_SNAPMODULE, ProcessId);
			if (!(hSnap == NULL))
			{
				MODULEENTRY32 me32;
				me32.dwSize = sizeof(me32);
				if (Module32First(hSnap, &me32))
					while (Module32Next(hSnap, &me32))
						if (!strcmp(moduleName, me32.szModule))
						{
							BaseAddress = reinterpret_cast<std::uint32_t>(me32.modBaseAddr);
							break;
						}

			}
			CloseSafeHandle(hSnap);
			return BaseAddress;
		}
#endif
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

#if !UNICODE
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


#else
		std::uint64_t GetProcId64(const wchar_t* process_name)
		{
			std::uint32_t ProcessId = NULL;
			HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
			if (!(hSnap == NULL))
			{
				PROCESSENTRY32W pe32;
				pe32.dwSize = sizeof(pe32);
				if (Process32FirstW(hSnap, &pe32))
					while (Process32NextW(hSnap, &pe32))
						if (!wcscmp(process_name, pe32.szExeFile))
						{
							ProcessId = pe32.th32ProcessID;
							break;
						}

			}
			CloseHandle(hSnap);
			return ProcessId;
		}

		std::uint64_t GetModuleBase64(std::uint64_t ProcessId, const wchar_t* moduleName)
		{
			std::uint32_t BaseAddress = NULL;
			HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE32 | TH32CS_SNAPMODULE, ProcessId);
			if (!(hSnap == NULL))
			{
				MODULEENTRY32W me32;
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
#endif

#endif
	}

	namespace Internal
	{		
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

		PVOID GetUnhookedPointer(PVOID pointer)
		{
			if (*(unsigned char*)pointer == 0xF1)
				return (PVOID)((ULONG)pointer + 0x1);
		}


		PVOID Nop(PVOID Address, INT Bytes) 
		{
			try
			{
				ULONG OldProtection, NewProtection;
				VirtualProtect(Address, Bytes, PAGE_EXECUTE_READWRITE, &OldProtection);
				memset(Address, 0x90, Bytes);
				VirtualProtect(Address, Bytes, OldProtection, &NewProtection);
			}
			catch (std::exception*& e) { MessageBoxA(0, e->what(), "Nop: Exception", MB_OK | MB_ICONERROR); }
		}

		const void KillCurrentProcess()
		{
#if !_DLL
			HANDLE handle = GetCurrentProcess();
			TerminateProcess(handle, 0);
#else
			ExitProcess(0);
#endif
		}
	}

	namespace Prototypes
	{
		/*
		pT = Prototype, feel free to change this to what ever you'd like :)
		*/

		typedef HANDLE(*_pTCreateToolhelp32Snapshot)
		(
			DWORD dwFlags,
			DWORD th32ProcessID
		);

		_pTCreateToolhelp32Snapshot pTCreateToolhelp32Snapshot =
			(_pTCreateToolhelp32Snapshot)Internal::GetExportAddress("kernel32.dll", "CreateToolhelp32Snapshot");

		typedef BOOL(*_pTVirtualProtect)
		(
			LPVOID lpAddress,
			SIZE_T dwSize,
			DWORD  flNewProtect,
			PDWORD lpflOldProtect
		);

		_pTVirtualProtect pTVirtualProtect = 
			(_pTVirtualProtect)Internal::GetExportAddress("kernel32.dll", "VirtualProtect");

		/*
		TODO:
		   * NtWriteVirtualMemory
		   * NtProtectVirutalMemory
		   * NtOpenProcess
		   * NtReadVirtualMemory
		   * ZwWriteVirutalMemory
		   * ZwReadVirtualMemory	   
		*/

	}
}
#define MEMORY_H
#endif
