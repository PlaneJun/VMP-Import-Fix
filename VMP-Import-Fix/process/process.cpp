#include "process.h"

#include <filesystem>
#include <psapi.h>
#include <windows.h>
#include <TlHelp32.h> 

#include "../nativeapi/nativeapi.h"
#include "../utils/utils.h"

#define INRANGE(x,a,b)    (x >= a && x <= b)
#define getBits( x )    (INRANGE((x&(~0x20)),'A','F') ? ((x&(~0x20)) - 'A' + 0xa) : (INRANGE(x,'0','9') ? x - '0' : 0))
#define getByte( x )    (getBits(x[0]) << 4 | getBits(x[1]))

Process::Process()
{
	NativeWinApi::initialize();
}

Process::~Process()
{
	if (hProcess_)
	{
		CloseHandle(hProcess_);
	}
}

uint64_t Process::get_module_handle_by_name(uint32_t pid, const wchar_t* modulename)
{
	MODULEENTRY32 moduleEntry;
	HANDLE handle = NULL;
	handle = ::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid); //  获取进程快照中包含在th32ProcessID中指定的进程的所有的模块。
	if (!handle) {
		CloseHandle(handle);
		return NULL;
	}
	ZeroMemory(&moduleEntry, sizeof(MODULEENTRY32));
	moduleEntry.dwSize = sizeof(MODULEENTRY32);
	if (!Module32First(handle, &moduleEntry)) {
		CloseHandle(handle);
		return NULL;
	}
	do {
		if (_wcsicmp(moduleEntry.szModule, modulename) == 0) {
			return reinterpret_cast<uint64_t>(moduleEntry.hModule);
		}
	} while (Module32Next(handle, &moduleEntry));
	CloseHandle(handle);
	return 0;
}

uint32_t Process::get_pid_by_name(const wchar_t* name)
{
	HANDLE  hsnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hsnapshot == INVALID_HANDLE_VALUE)
	{
		return 0;
	}
	PROCESSENTRY32W pe;
	pe.dwSize = sizeof(PROCESSENTRY32W);
	BOOL find = Process32FirstW(hsnapshot, &pe);
	while (find != 0)
	{
		if (_wcsicmp(pe.szExeFile, name) == 0)
		{
			return pe.th32ProcessID;
		}
		find = Process32NextW(hsnapshot, &pe);
	}
	CloseHandle(hsnapshot);
	return 0;
}

std::string Process::get_name_by_pid(uint32_t pid)
{
	HANDLE  hsnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hsnapshot == INVALID_HANDLE_VALUE)
	{
		return 0;
	}
	PROCESSENTRY32W pe;
	pe.dwSize = sizeof(PROCESSENTRY32W);
	BOOL find = Process32FirstW(hsnapshot, &pe);
	while (find != 0)
	{
		if (pe.th32ProcessID == pid)
		{
			return utils::wstring2stirng(pe.szExeFile);
		}
		find = Process32NextW(hsnapshot, &pe);
	}
	CloseHandle(hsnapshot);
	return "";
}

std::string Process::get_modulename_by_handle(uint64_t module_base)
{
	char buffer[MAX_PATH]{};
	GetModuleFileNameExA(hProcess_, reinterpret_cast<HMODULE>(module_base), buffer,sizeof(buffer));
	std::filesystem::path tmp(buffer);
	return tmp.filename().string();
}

HANDLE Process::nt_open_process(uint32_t acess, uint32_t pid)
{
	HANDLE hProcess = 0;
	CLIENT_ID cid = { 0 };
	OBJECT_ATTRIBUTES ObjectAttributes;
	NTSTATUS ntStatus = 0;

	InitializeObjectAttributes(&ObjectAttributes, 0, 0, 0, 0);
	cid.UniqueProcess = (HANDLE)pid;
	ntStatus = NativeWinApi::NtOpenProcess(&hProcess, acess, &ObjectAttributes, &cid);

	if (NT_SUCCESS(ntStatus))
	{
		return hProcess;
	}
	else
	{
		return 0;
	}
}

bool Process::open_process(uint32_t pid)
{
	if (pid > 0)
	{
		if (hProcess_)
		{
			return false;
		}
		else
		{
			hProcess_ = nt_open_process(PROCESS_ALL_ACCESS, pid);
			pid_ = pid;
			return hProcess_ ? true : false;
		}
	}
	else
	{
		return false;
	}
}

bool Process::read_mem(uintptr_t address, size_t size, void* dataBuffer)
{
	SIZE_T lpNumberOfBytesRead = 0;
	DWORD dwProtect = 0;
	bool returnValue = false;

	if (!hProcess_)
	{
		return returnValue;
	}

	if (!ReadProcessMemory(hProcess_, (LPVOID)address, dataBuffer, size, &lpNumberOfBytesRead))
	{
		if (!VirtualProtectEx(hProcess_, (LPVOID)address, size, PAGE_READWRITE, &dwProtect))
		{
			returnValue = false;
		}
		else
		{
			if (!ReadProcessMemory(hProcess_, (LPVOID)address, dataBuffer, size, &lpNumberOfBytesRead))
			{
				returnValue = false;
			}
			else
			{
				returnValue = true;
			}
			VirtualProtectEx(hProcess_, (LPVOID)address, size, dwProtect, &dwProtect);
		}
	}
	else
	{
		returnValue = true;
	}

	if (returnValue)
	{
		if (size != lpNumberOfBytesRead)
		{
			returnValue = false;
		}
		else
		{
			returnValue = true;
		}
	}

	return returnValue;
}

bool Process::read_mem_force(uintptr_t address, size_t size, void* dataBuffer)
{
	DWORD_PTR addressPart = 0;
	DWORD_PTR readBytes = 0;
	DWORD_PTR bytesToRead = 0;
	MEMORY_BASIC_INFORMATION memBasic = { 0 };
	bool returnValue = false;

	if (!hProcess_)
	{
		return returnValue;
	}

	if (!read_mem(address, size, dataBuffer))
	{
		addressPart = address;

		do
		{
			if (!VirtualQueryEx(hProcess_, (LPCVOID)addressPart, &memBasic, sizeof(memBasic)))
			{
				break;
			}

			bytesToRead = memBasic.RegionSize;

			if ((readBytes + bytesToRead) > size)
			{
				bytesToRead = size - readBytes;
			}

			if (memBasic.State == MEM_COMMIT)
			{
				if (!read_mem(addressPart, bytesToRead, (LPVOID)((DWORD_PTR)dataBuffer + readBytes)))
				{
					break;
				}
			}
			else
			{
				ZeroMemory((LPVOID)((DWORD_PTR)dataBuffer + readBytes), bytesToRead);
			}


			readBytes += bytesToRead;

			addressPart += memBasic.RegionSize;

		} while (readBytes < size);

		if (readBytes == size)
		{
			returnValue = true;
		}

	}
	else
	{
		returnValue = true;
	}

	return returnValue;
}

bool Process::write_mem(uintptr_t address, size_t size, uintptr_t dataBuffer)
{
	SIZE_T lpNumberOfBytesWritten = 0;
	if (!hProcess_)
	{
		return false;
	}

	return (WriteProcessMemory(hProcess_, (LPVOID)address, (LPVOID)dataBuffer, size, &lpNumberOfBytesWritten) != FALSE);
}

bool Process::isWow64()
{
	BOOL wow64 = false;
	IsWow64Process(hProcess_, &wow64);
	return wow64;
}

std::vector<uint64_t> Process::find_pattern(std::string pattern, uint64_t begine, uint64_t end)
{
	std::vector<uint64_t> ret{};

	const char* pat = pattern.c_str();
	uint64_t firstMatch = NULL;
	auto rangeStart = begine;
	auto sizeOfImage = end - begine;
	auto rangeEnd = rangeStart + sizeOfImage;
	for (auto pCur = rangeStart; pCur < rangeEnd; pCur++)
	{
		if (!*pat)
		{
			ret.push_back(firstMatch);
			goto redo;
		}
		if (*(PBYTE)pat == '\?' || read<BYTE>(pCur) == getByte(pat))
		{
			if (!firstMatch)
			{
				firstMatch = pCur;
			}
			if (!pat[2])
			{
				ret.push_back(firstMatch);
				goto redo;
			}
			if (*(PWORD)pat == '\?\?' || *(PBYTE)pat != '\?')
			{
				pat += 3;
			}
			else
			{
				pat += 2;
			}
		}
		else
		{
		redo:
			pat = pattern.c_str();
			firstMatch = NULL;
		}
	}
	return ret;
}

uint64_t Process::get_base_handle()
{
	MODULEENTRY32 moduleEntry;
	HANDLE handle = NULL;
	handle = ::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid_); //  获取进程快照中包含在th32ProcessID中指定的进程的所有的模块。
	if (!handle) {
		CloseHandle(handle);
		return NULL;
	}
	ZeroMemory(&moduleEntry, sizeof(MODULEENTRY32));
	moduleEntry.dwSize = sizeof(MODULEENTRY32);
	if (!Module32First(handle, &moduleEntry)) {
		CloseHandle(handle);
		return NULL;
	}

	CloseHandle(handle);
	return reinterpret_cast<uint64_t>(moduleEntry.hModule);
}


uint64_t Process::alloc_mem_nearby(uint64_t addr, uint32_t Size)
{

	ULONG64 A = addr / 65536;
	ULONG64 AllocPtr = A * 65536;
	BOOL Direc = FALSE;
	ULONG64 Increase = 0;
	ULONG64 AllocBase = 0;
	do
	{
		AllocBase = (ULONG64)VirtualAllocEx(hProcess_,(PVOID64)AllocPtr, Size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (AllocBase == 0)
		{
			if (Direc == FALSE)
			{
				if (addr + 2147483642 >= AllocPtr)
				{
					Increase = Increase + 65536;
				}
				else
				{
					Increase = 0;
					Direc = TRUE;
				}
			}
			else
			{
				if (addr - 2147483642 <= AllocPtr)
				{
					Increase = Increase - 65536;
				}
				else
				{
					return 0;
				}
			}

			AllocPtr = AllocPtr + Increase;
		}


	} while (AllocBase == 0);

	return AllocBase;
}