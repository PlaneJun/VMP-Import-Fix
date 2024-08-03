#pragma once
#include <string>
#include <windows.h>
#include <stdint.h>

class api
{
private:
	static	ULONG_PTR EngineGetModuleBaseRemote(HANDLE hProcess, ULONG_PTR APIAddress);
	static	bool MapFileExW(wchar_t* szFileName, DWORD ReadOrWrite, LPHANDLE FileHandle, LPDWORD FileSize, LPHANDLE FileMap, LPVOID FileMapVA, DWORD SizeModifier);
	static	void UnMapFileEx(HANDLE FileHandle, DWORD FileSize, HANDLE FileMap, ULONG_PTR FileMapVA);
	static	bool EngineValidateHeader(ULONG_PTR FileMapVA, HANDLE hFileProc, LPVOID ImageBase, PIMAGE_DOS_HEADER DOSHeader, bool IsFile);
	static	ULONG_PTR ConvertVAtoFileOffset(ULONG_PTR FileMapVA, ULONG_PTR AddressToConvert, bool ReturnType);
public:
	struct ApiInfo
	{
		uint64_t		addr;				//要修复的位置
		uint64_t		api_addr;			//api地址
		uint64_t		api_module_base;	//模块base
		std::string		api_module;			//api模块名
		std::string		api_name;			//api函数名
		uint32_t		fix_offset;			//填充地址与修复地址的相对位置
	};

	static	bool GetFuncName(HANDLE hProc, ULONG_PTR APIAddress, uint64_t& module_base,std::string& apiname, std::wstring& modulepath);
};


