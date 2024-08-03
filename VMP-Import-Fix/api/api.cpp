#include"api.h"
#include <psapi.h>

#define UE_ACCESS_READ 0
#define UE_ACCESS_WRITE 1
#define UE_ACCESS_ALL 2
#define MAX(a,b) (((a) > (b)) ? (a) : (b))

ULONG_PTR api::EngineGetModuleBaseRemote(HANDLE hProcess, ULONG_PTR APIAddress)
{
	DWORD cbNeeded = 0;
	if (EnumProcessModules(hProcess, 0, 0, &cbNeeded))
	{
		HMODULE* hMods = (HMODULE*)malloc(cbNeeded * sizeof(HMODULE));
		if (EnumProcessModules(hProcess, hMods, cbNeeded, &cbNeeded))
		{
			for (unsigned int i = 0; i < cbNeeded / sizeof(HMODULE); i++)
			{
				MODULEINFO modinfo;
				memset(&modinfo, 0, sizeof(MODULEINFO));
				if (GetModuleInformation(hProcess, hMods[i], &modinfo, sizeof(MODULEINFO)))
				{
					ULONG_PTR start = (ULONG_PTR)hMods[i];
					ULONG_PTR end = start + modinfo.SizeOfImage;
					if (APIAddress >= start && APIAddress < end)
						return start;
				}
			}
		}
		free(hMods);
	}
	return 0;
}

bool api::MapFileExW(wchar_t* szFileName, DWORD ReadOrWrite, LPHANDLE FileHandle, LPDWORD FileSize, LPHANDLE FileMap, LPVOID FileMapVA, DWORD SizeModifier)
{
	DWORD FileAccess = 0;
	DWORD FileMapType = 0;
	DWORD FileMapViewType = 0;

	if (ReadOrWrite == UE_ACCESS_READ)
	{
		FileAccess = GENERIC_READ;
		FileMapType = PAGE_READONLY;
		FileMapViewType = FILE_MAP_READ;
	}
	else if (ReadOrWrite == UE_ACCESS_WRITE)
	{
		FileAccess = GENERIC_WRITE;
		FileMapType = PAGE_READWRITE;
		FileMapViewType = FILE_MAP_WRITE;
	}
	else if (ReadOrWrite == UE_ACCESS_ALL)
	{
		FileAccess = GENERIC_READ + GENERIC_WRITE + GENERIC_EXECUTE;
		FileMapType = PAGE_EXECUTE_READWRITE;
		FileMapViewType = FILE_MAP_WRITE;
	}
	else
	{
		FileAccess = GENERIC_READ + GENERIC_WRITE + GENERIC_EXECUTE;
		FileMapType = PAGE_EXECUTE_READWRITE;
		FileMapViewType = FILE_MAP_ALL_ACCESS;
	}

	HANDLE hFile = CreateFileW(szFileName, FileAccess, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile != INVALID_HANDLE_VALUE)
	{
		*FileHandle = hFile;
		DWORD mfFileSize = GetFileSize(hFile, NULL);
		mfFileSize = mfFileSize + SizeModifier;
		*FileSize = mfFileSize;
		HANDLE mfFileMap = CreateFileMappingA(hFile, NULL, FileMapType, NULL, mfFileSize, NULL);
		if (mfFileMap != NULL)
		{
			*FileMap = mfFileMap;
			LPVOID mfFileMapVA = MapViewOfFile(mfFileMap, FileMapViewType, NULL, NULL, NULL);
			if (mfFileMapVA != NULL)
			{
				RtlMoveMemory(FileMapVA, &mfFileMapVA, sizeof ULONG_PTR);
				return true;
			}
		}
		RtlZeroMemory(FileMapVA, sizeof ULONG_PTR);
		*FileHandle = NULL;
		*FileSize = NULL;
		CloseHandle(hFile);
	}
	else
	{
		RtlZeroMemory(FileMapVA, sizeof ULONG_PTR);
	}
	return false;
}

void api::UnMapFileEx(HANDLE FileHandle, DWORD FileSize, HANDLE FileMap, ULONG_PTR FileMapVA)
{
	if (UnmapViewOfFile((void*)FileMapVA))
	{
		CloseHandle(FileMap);
	}
}

bool api::EngineValidateHeader(ULONG_PTR FileMapVA, HANDLE hFileProc, LPVOID ImageBase, PIMAGE_DOS_HEADER DOSHeader, bool IsFile)
{
	MODULEINFO ModuleInfo;
	DWORD PESize, MaxPESize;
	PIMAGE_NT_HEADERS PEHeader;
	IMAGE_NT_HEADERS RemotePEHeader;
	ULONG_PTR NumberOfBytesRW = NULL;

	if (IsFile)
	{
		if (hFileProc == NULL)
		{
			PESize = 0;
			MaxPESize = ULONG_MAX;
		}
		else
		{
			PESize = GetFileSize(hFileProc, NULL);
			MaxPESize = PESize;
		}
		__try
		{
			if (DOSHeader->e_magic == IMAGE_DOS_SIGNATURE)
			{
				DWORD LfaNew = DOSHeader->e_lfanew;
				if ((PESize == 0 || (LfaNew < PESize && LfaNew + sizeof(IMAGE_NT_SIGNATURE) + sizeof(IMAGE_FILE_HEADER) < PESize)) &&
					MaxPESize != 0 &&
					LfaNew < (MaxPESize - sizeof(IMAGE_NT_SIGNATURE) - sizeof(IMAGE_FILE_HEADER)))
				{
					PEHeader = (PIMAGE_NT_HEADERS)((ULONG_PTR)DOSHeader + LfaNew);
					return PEHeader->Signature == IMAGE_NT_SIGNATURE;
				}
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
		}
	}
	else
	{
		RtlZeroMemory(&ModuleInfo, sizeof MODULEINFO);
		GetModuleInformation(hFileProc, (HMODULE)ImageBase, &ModuleInfo, sizeof(MODULEINFO));
		PESize = ModuleInfo.SizeOfImage;
		__try
		{
			if (DOSHeader->e_magic == IMAGE_DOS_SIGNATURE)
			{
				DWORD LfaNew = DOSHeader->e_lfanew;
				if ((LfaNew < PESize && LfaNew + sizeof(IMAGE_NT_SIGNATURE) + sizeof(IMAGE_FILE_HEADER) < PESize) &&
					LfaNew < (PESize - sizeof(IMAGE_NT_SIGNATURE) - sizeof(IMAGE_FILE_HEADER)))
				{
					if (ReadProcessMemory(hFileProc, (LPVOID)((ULONG_PTR)ImageBase + LfaNew), &RemotePEHeader, sizeof(IMAGE_NT_HEADERS), &NumberOfBytesRW))
					{
						PEHeader = (PIMAGE_NT_HEADERS)&RemotePEHeader;
						return PEHeader->Signature == IMAGE_NT_SIGNATURE;
					}
				}
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
		}
	}
	return false;
}

ULONG_PTR api::ConvertVAtoFileOffset(ULONG_PTR FileMapVA, ULONG_PTR AddressToConvert, bool ReturnType)
{
	PIMAGE_DOS_HEADER DOSHeader;
	PIMAGE_NT_HEADERS32 PEHeader32;
	PIMAGE_NT_HEADERS64 PEHeader64;
	PIMAGE_SECTION_HEADER PESections;
	DWORD SectionNumber = 0;
	ULONG_PTR ConvertedAddress = 0;
	ULONG_PTR ConvertAddress = 0;
	BOOL FileIs64;

	if (FileMapVA != NULL)
	{
		DOSHeader = (PIMAGE_DOS_HEADER)FileMapVA;
		if (EngineValidateHeader(FileMapVA, NULL, NULL, DOSHeader, true))
		{
			PEHeader32 = (PIMAGE_NT_HEADERS32)((ULONG_PTR)DOSHeader + DOSHeader->e_lfanew);
			PEHeader64 = (PIMAGE_NT_HEADERS64)((ULONG_PTR)DOSHeader + DOSHeader->e_lfanew);
			if (PEHeader32->OptionalHeader.Magic == 0x10B)
			{
				FileIs64 = false;
			}
			else if (PEHeader32->OptionalHeader.Magic == 0x20B)
			{
				FileIs64 = true;
			}
			else
			{
				return(0);
			}
			if (!FileIs64)
			{
				ConvertAddress = (DWORD)((DWORD)AddressToConvert - PEHeader32->OptionalHeader.ImageBase);
				if (ConvertAddress < PEHeader32->OptionalHeader.SectionAlignment)
				{
					ConvertedAddress = ConvertAddress;
				}
				PESections = IMAGE_FIRST_SECTION(PEHeader32);
				SectionNumber = PEHeader32->FileHeader.NumberOfSections;
				__try
				{
					while (SectionNumber > 0)
					{
						if (PESections->VirtualAddress <= ConvertAddress && ConvertAddress < PESections->VirtualAddress + MAX(PESections->Misc.VirtualSize, PESections->SizeOfRawData))
						{
							if (ConvertAddress - PESections->VirtualAddress <= PESections->SizeOfRawData)
							{
								ConvertedAddress = PESections->PointerToRawData + (ConvertAddress - PESections->VirtualAddress);
							}
						}
						PESections = (PIMAGE_SECTION_HEADER)((ULONG_PTR)PESections + IMAGE_SIZEOF_SECTION_HEADER);
						SectionNumber--;
					}
					if (ReturnType)
					{
						if (ConvertedAddress != NULL)
						{
							ConvertedAddress += FileMapVA;
						}
						else if (ConvertAddress == NULL)
						{
							ConvertedAddress = FileMapVA;
						}
					}
					return ConvertedAddress;
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					return(0);
				}
			}
			else
			{
				ConvertAddress = (DWORD)(AddressToConvert - PEHeader64->OptionalHeader.ImageBase);
				if (ConvertAddress < PEHeader64->OptionalHeader.SectionAlignment)
				{
					ConvertedAddress = ConvertAddress;
				}
				PESections = IMAGE_FIRST_SECTION(PEHeader64);
				SectionNumber = PEHeader64->FileHeader.NumberOfSections;
				__try
				{
					while (SectionNumber > 0)
					{
						if (PESections->VirtualAddress <= ConvertAddress && ConvertAddress < PESections->VirtualAddress + MAX(PESections->Misc.VirtualSize, PESections->SizeOfRawData))
						{
							if (ConvertAddress - PESections->VirtualAddress <= PESections->SizeOfRawData)
							{
								ConvertedAddress = PESections->PointerToRawData + (ConvertAddress - PESections->VirtualAddress);
							}
						}
						PESections = (PIMAGE_SECTION_HEADER)((ULONG_PTR)PESections + IMAGE_SIZEOF_SECTION_HEADER);
						SectionNumber--;
					}
					if (ReturnType)
					{
						if (ConvertedAddress != NULL)
						{
							ConvertedAddress += FileMapVA;
						}
						else if (ConvertAddress == NULL)
						{
							ConvertedAddress = FileMapVA;
						}
					}
					return(ConvertedAddress);
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					return(0);
				}
			}
		}
		else
		{
			return(0);
		}
	}
	return(0);
}

bool api::GetFuncName(HANDLE hProc, ULONG_PTR APIAddress, uint64_t& module_base, std::string& apiname, std::wstring& modulepath)
{
	if (APIAddress < 0x5fffffff)
		return false;
	HANDLE hProcess = NULL;
	HANDLE FileHandle;
	DWORD FileSize;
	HANDLE FileMap;
	ULONG_PTR FileMapVA;
	ULONG_PTR ModuleBase;
	bool result = false;
	wchar_t szModulePath[MAX_PATH] = L"";

	hProcess = hProc;

	if (hProcess == NULL)
		goto __exit;

	ModuleBase = EngineGetModuleBaseRemote(hProcess, APIAddress);
	if (!ModuleBase)
		goto __exit;

	if (!GetModuleFileNameExW(hProcess, (HMODULE)ModuleBase, szModulePath, _countof(szModulePath)))
		goto __exit;

	module_base = ModuleBase;
	if (MapFileExW(szModulePath, UE_ACCESS_READ, &FileHandle, &FileSize, &FileMap, &FileMapVA, 0))
	{
		PIMAGE_DOS_HEADER DOSHeader = (PIMAGE_DOS_HEADER)FileMapVA;
		if (EngineValidateHeader(FileMapVA, NULL, NULL, DOSHeader, true))
		{
			PIMAGE_NT_HEADERS32 PEHeader32 = (PIMAGE_NT_HEADERS32)((ULONG_PTR)DOSHeader + DOSHeader->e_lfanew);
			PIMAGE_NT_HEADERS64 PEHeader64 = (PIMAGE_NT_HEADERS64)((ULONG_PTR)DOSHeader + DOSHeader->e_lfanew);
			ULONG_PTR ExportDirectoryVA;
			DWORD ExportDirectorySize;
			ULONG_PTR ImageBase;
			if (PEHeader32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
			{
				ImageBase = PEHeader32->OptionalHeader.ImageBase;
				ExportDirectoryVA = (ULONG_PTR)PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
				ExportDirectorySize = (ULONG_PTR)PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
			}
			else //x64
			{
				ImageBase = (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase;
				ExportDirectoryVA = (ULONG_PTR)PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
				ExportDirectorySize = (ULONG_PTR)PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
			}

			if(ExportDirectoryVA >0 && ExportDirectorySize>0)
			{
				PIMAGE_EXPORT_DIRECTORY ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)ConvertVAtoFileOffset(FileMapVA, ExportDirectoryVA + ImageBase, true);
				if (ExportDirectory)
				{
					DWORD* AddrOfFunctions = (DWORD*)ConvertVAtoFileOffset(FileMapVA, ExportDirectory->AddressOfFunctions + ImageBase, true);
					DWORD* AddrOfNames = (DWORD*)ConvertVAtoFileOffset(FileMapVA, ExportDirectory->AddressOfNames + ImageBase, true);
					SHORT* AddrOfNameOrdinals = (SHORT*)ConvertVAtoFileOffset(FileMapVA, ExportDirectory->AddressOfNameOrdinals + ImageBase, true);
					if (AddrOfFunctions && AddrOfNames && AddrOfNameOrdinals)
					{
						unsigned int NumberOfNames = ExportDirectory->NumberOfNames;
						for (unsigned int i = 0; i < NumberOfNames; i++)
						{
							const char* curName = (const char*)ConvertVAtoFileOffset(FileMapVA, AddrOfNames[i] + ImageBase, true);
							if (!curName)
								continue;

							try
							{
								unsigned int curRva = AddrOfFunctions[AddrOfNameOrdinals[i]];
								if (curRva < ExportDirectoryVA || curRva >= ExportDirectoryVA + ExportDirectorySize) //non-forwarded exports
								{
									if (curRva + ModuleBase == APIAddress)
									{
										result = true;
										apiname = curName;
										modulepath = szModulePath;
										UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
										goto __exit;
									}
								}
							}
							catch (std::exception& e)
							{
								result = true;
								apiname = "Exception";
								modulepath = szModulePath;
								UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
								goto __exit;
							}

						}
					}
				}
			}
		}
		UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
	}

__exit:
	return result;
}