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
		uint64_t		addr;				//Ҫ�޸���λ��
		uint64_t		api_addr;			//api��ַ
		uint64_t		api_module_base;	//ģ��base
		std::string		api_module;			//apiģ����
		std::string		api_name;			//api������
		uint32_t		fix_offset;			//����ַ���޸���ַ�����λ��
	};

	static	bool GetFuncName(HANDLE hProc, ULONG_PTR APIAddress, uint64_t& module_base,std::string& apiname, std::wstring& modulepath);
};


