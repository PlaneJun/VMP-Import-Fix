#include <Windows.h>
#include "pefile.h"
#include "../process/process.h"

PEFile::PEFile()
{
	data_ = NULL;
	number_of_sections_ = 0;
	size_of_option_header_ = 0;
	size_of_code_ = 0;
	size_of_initialized_data_ = 0;
	size_of_uninitialized_data_ = 0;
	entry_point_ = 0;
	base_of_code_ = 0;
	base_of_data_ = 0;
	image_base_ = 0;
	segtion_alignment_ = 0;
	file_alignment_ = 0;
	size_of_image_ = 0;
	size_of_headers_ = 0;

}

PEFile::~PEFile()
{
	release();
}

bool PEFile::load_from_file(const char* path, bool reloc, uint64_t new_base)
{
	//读取文件
	HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		return false;
	}
	DWORD dwFileSize = GetFileSize(hFile, NULL);
	std::vector<uint8_t> data{};
	data.resize(dwFileSize);
	ReadFile(hFile, data.data(), dwFileSize, NULL, NULL);
	CloseHandle(hFile);

	return parse_pe(data.data(), NULL,true, reloc, new_base);
}

bool PEFile::load_from_process(uint32_t pid, const wchar_t* module_name)
{
	bool retValue = false;

	Process proc;
	if (!proc.open_process(pid))
	{
		return retValue;
	}

	uintptr_t addr = module_name == NULL ? proc.get_base_handle() : Process::get_module_handle_by_name(pid, module_name);
	if (!addr)
	{
		return retValue;
	}

	std::vector<uint8_t> data{};
	data.resize(0x1000);
	if (proc.read_mem_force(addr, data.size(), data.data()))
	{
		retValue = true;
		PIMAGE_DOS_HEADER pDos = reinterpret_cast<PIMAGE_DOS_HEADER>(data.data());
		if (pDos->e_magic != 'ZM')
		{
			return false;
		}

		// 获取正确的大小
		uint32_t magic_offset = pDos->e_lfanew + sizeof(IMAGE_FILE_HEADER) + 4;
		bool arch64 = *reinterpret_cast<PWORD>(data.data() + magic_offset) == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
		DWORD realSize = 0;
		if (arch64)
		{
			realSize = reinterpret_cast<PIMAGE_NT_HEADERS64>(data.data() + pDos->e_lfanew)->OptionalHeader.SizeOfImage;
		}
		else
		{
			realSize = reinterpret_cast<PIMAGE_NT_HEADERS32>(data.data() + pDos->e_lfanew)->OptionalHeader.SizeOfImage;
		}

		data.clear();
		data.resize(realSize);
		if (proc.read_mem_force(addr, data.size(), data.data()))
		{
			retValue = load_from_memory(data.data(), false, NULL);
		}
		else
		{
			retValue = false;
		}
	}

	return retValue;
}

bool PEFile::load_from_memory(uint8_t* data, size_t data_len, bool reloc, uint64_t new_base)
{
	return parse_pe(data, data_len,false, reloc, new_base);
}

bool PEFile::parse_pe(const uint8_t* data, size_t data_len, bool fromFile, bool reloc, uint64_t new_base)
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)(data);
	if (pDos->e_magic != 'ZM')
	{
		return false;
	}

	uint32_t magic_offset = pDos->e_lfanew + sizeof(IMAGE_FILE_HEADER) + 4;
	arch64_ = *(PWORD)(data + magic_offset) == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
	if (arch64_)
	{
		PIMAGE_NT_HEADERS64 pNt64 = (PIMAGE_NT_HEADERS64)(data + pDos->e_lfanew);
		number_of_sections_ = pNt64->FileHeader.NumberOfSections;
		size_of_option_header_ = pNt64->FileHeader.SizeOfOptionalHeader;
		size_of_code_ = pNt64->OptionalHeader.SizeOfCode;
		size_of_initialized_data_ = pNt64->OptionalHeader.SizeOfInitializedData;
		size_of_uninitialized_data_ = pNt64->OptionalHeader.SizeOfUninitializedData;
		entry_point_ = pNt64->OptionalHeader.AddressOfEntryPoint;
		base_of_code_ = pNt64->OptionalHeader.BaseOfCode;
		base_of_data_ = 0;
		image_base_ = pNt64->OptionalHeader.ImageBase;
		segtion_alignment_ = pNt64->OptionalHeader.SectionAlignment;
		file_alignment_ = pNt64->OptionalHeader.FileAlignment;
		size_of_image_ = pNt64->OptionalHeader.SizeOfImage;
		size_of_headers_ = pNt64->OptionalHeader.SizeOfHeaders;
		RtlCopyMemory(data_directory_, pNt64->OptionalHeader.DataDirectory, IMAGE_NUMBEROF_DIRECTORY_ENTRIES * sizeof(IMAGE_DATA_DIRECTORY));
	}
	else
	{
		PIMAGE_NT_HEADERS32 pNt32 =(PIMAGE_NT_HEADERS32)(data + pDos->e_lfanew);
		number_of_sections_ = pNt32->FileHeader.NumberOfSections;
		size_of_option_header_ = pNt32->FileHeader.SizeOfOptionalHeader;
		size_of_code_ = pNt32->OptionalHeader.SizeOfCode;
		size_of_initialized_data_ = pNt32->OptionalHeader.SizeOfInitializedData;
		size_of_uninitialized_data_ = pNt32->OptionalHeader.SizeOfUninitializedData;
		entry_point_ = pNt32->OptionalHeader.AddressOfEntryPoint;
		base_of_code_ = pNt32->OptionalHeader.BaseOfCode;
		base_of_data_ = pNt32->OptionalHeader.BaseOfData;
		image_base_ = pNt32->OptionalHeader.ImageBase;
		segtion_alignment_ = pNt32->OptionalHeader.SectionAlignment;
		file_alignment_ = pNt32->OptionalHeader.FileAlignment;
		size_of_image_ = pNt32->OptionalHeader.SizeOfImage;
		size_of_headers_ = pNt32->OptionalHeader.SizeOfHeaders;
		RtlCopyMemory(data_directory_, pNt32->OptionalHeader.DataDirectory, IMAGE_NUMBEROF_DIRECTORY_ENTRIES * sizeof(IMAGE_DATA_DIRECTORY));
	}

	release();

	data_len_ = data_len == NULL ? size_of_image_ : data_len;
	data_ = new uint8_t[data_len_];

	// 拷贝头
	RtlCopyMemory(data_, data, size_of_headers_ + number_of_sections_ * sizeof(IMAGE_SECTION_HEADER));

	//拷贝每个节区
	PIMAGE_SECTION_HEADER SectionHeader = (PIMAGE_SECTION_HEADER)(data + pDos->e_lfanew + sizeof(IMAGE_FILE_HEADER) + size_of_option_header_ + 4);
	for (int i = 0; i < number_of_sections_; ++i, SectionHeader++)
	{
		RtlCopyMemory(&data_[SectionHeader->VirtualAddress],
			data + (fromFile ? SectionHeader->PointerToRawData : SectionHeader->VirtualAddress),
			fromFile ? SectionHeader->SizeOfRawData : SectionHeader->Misc.VirtualSize);
	}

	//重定向
	if (reloc)
	{
		// 如果为NULL，则以申请的内存进行拉伸
		if (new_base == NULL)
			new_base = reinterpret_cast<uint64_t>(data_);
		else
			new_base = reinterpret_cast<uint64_t>(data);

		if (data_directory_[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress > 0 && data_directory_[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size > 0)
		{
			uint64_t Delta = new_base - image_base_;
			uint8_t* pAddress = NULL;
			PIMAGE_BASE_RELOCATION pLoc = (PIMAGE_BASE_RELOCATION)(data_ + data_directory_[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
			while ((pLoc->VirtualAddress + pLoc->SizeOfBlock) != 0) //开始扫描重定位表
			{
				uint16_t* pLocData = reinterpret_cast<uint16_t*>((uint64_t)pLoc + sizeof(IMAGE_BASE_RELOCATION));
				int NumberOfReloc = (pLoc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(uint16_t);//计算需要修正的重定位项（地址）的数目
				for (int i = 0; i < NumberOfReloc; i++)
				{
					int type = (pLocData[i] & 0xF000) >> 12;
					if (type == IMAGE_REL_BASED_HIGHLOW || type == IMAGE_REL_BASED_DIR64) //这是一个需要修正的地址
					{
						pAddress = reinterpret_cast<uint8_t*>(data_ + pLoc->VirtualAddress + (pLocData[i] & 0x0FFF));
						if (arch64_)
						{
							*(uint64_t*)pAddress += Delta;
						}
						else
						{
							*(uint32_t*)pAddress += Delta;
						}
					}
				}
				pLoc = reinterpret_cast<PIMAGE_BASE_RELOCATION>((uint64_t)pLoc + pLoc->SizeOfBlock);
			}
		}
	}

	return true;
}


uint8_t* PEFile::get_data()
{
	return data_;
}

std::vector<PIMAGE_SECTION_HEADER> PEFile::get_section_headers()
{
	std::vector<PIMAGE_SECTION_HEADER> ret;
	PIMAGE_DOS_HEADER pDos = reinterpret_cast<PIMAGE_DOS_HEADER>(data_);
	PIMAGE_SECTION_HEADER SectionHeader = reinterpret_cast<PIMAGE_SECTION_HEADER>(data_ + pDos->e_lfanew + sizeof(IMAGE_FILE_HEADER) + size_of_option_header_ + 4);
	for (int i = 0; i < number_of_sections_; i++, SectionHeader++)
	{
		ret.push_back(SectionHeader);
	}

	return ret;
}

PIMAGE_SECTION_HEADER PEFile::translate_raw_section(DWORD rva)
{
	PIMAGE_DOS_HEADER pDos = reinterpret_cast<PIMAGE_DOS_HEADER>(data_);
	PIMAGE_SECTION_HEADER SectionHeader = reinterpret_cast<PIMAGE_SECTION_HEADER>(data_ + pDos->e_lfanew + sizeof(IMAGE_FILE_HEADER) + size_of_option_header_ + 4);
	for (int i = 0; i < number_of_sections_; i++, SectionHeader++)
	{
		if (rva >= SectionHeader->VirtualAddress && rva < SectionHeader->VirtualAddress + SectionHeader->Misc.VirtualSize)
			return SectionHeader;
	}

	return NULL;

}
void* PEFile::translate_raw(DWORD rva)
{
	auto section = translate_raw_section(rva);
	if (!section) return NULL;
	return data_ + section->PointerToRawData + (rva - section->VirtualAddress);
}

bool PEFile::append_section(std::string section_name, std::uint32_t size, std::uint32_t chrs, PIMAGE_SECTION_HEADER* newSec)
{
	PIMAGE_DOS_HEADER pDos = reinterpret_cast<PIMAGE_DOS_HEADER>(data_);
	PIMAGE_SECTION_HEADER SectionHeader = reinterpret_cast<PIMAGE_SECTION_HEADER>(data_ + pDos->e_lfanew + sizeof(IMAGE_FILE_HEADER) + size_of_option_header_ + 4);
	for (int i = 0; i < number_of_sections_; i++, SectionHeader++)
	{
		SectionHeader->PointerToRawData = SectionHeader->VirtualAddress;
		SectionHeader->SizeOfRawData = SectionHeader->Misc.VirtualSize;
	}

	if (arch64_)
	{
		PIMAGE_NT_HEADERS64 pNt64 = reinterpret_cast<PIMAGE_NT_HEADERS64>(data_ + pDos->e_lfanew);
		SectionHeader->PointerToRawData = pNt64->OptionalHeader.SizeOfImage;
		SectionHeader->VirtualAddress = pNt64->OptionalHeader.SizeOfImage;
		pNt64->FileHeader.NumberOfSections++;
	}
	else
	{
		PIMAGE_NT_HEADERS32 pNt32 = reinterpret_cast<PIMAGE_NT_HEADERS32>(data_ + pDos->e_lfanew);
		SectionHeader->PointerToRawData = pNt32->OptionalHeader.SizeOfImage;
		SectionHeader->VirtualAddress = pNt32->OptionalHeader.SizeOfImage;
		pNt32->FileHeader.NumberOfSections++;
	}


	//add section header
	strncpy((char*)SectionHeader->Name, section_name.c_str(), section_name.length());
	SectionHeader->Characteristics = chrs;
	SectionHeader->SizeOfRawData = aligen(size);
	SectionHeader->Misc.VirtualSize = aligen(size);


	// Fill in some temp data
	std::vector<std::uint8_t> section_data(SectionHeader->SizeOfRawData);
	std::fill(section_data.begin(), section_data.end(), 0);


	std::vector<uint8_t> tmpBuffer(data_len_ + section_data.size());
	memcpy(tmpBuffer.data(),data_,data_len_);
	memcpy(tmpBuffer.data() + data_len_, section_data.data(), section_data.size());
	parse_pe(tmpBuffer.data(), tmpBuffer.size(),false,false,0);

	if (newSec)
		*newSec = get_section_headers().back();

	return true;
}

void PEFile::add_iat_section(uint64_t base, uint32_t rva_oep, std::map<std::string, std::map<std::string, std::vector<uint64_t>>> AddedImports)
{
	//计算导入表大小
	uint32_t thunk_count = 0;
	uint32_t dllName_count = 0;
	uint32_t funcName_count = 0; //IMAGE_IMPORT_BY_NAME总大小
	for (auto m : AddedImports)
	{
		for (auto f : m.second)
		{
			thunk_count = thunk_count + 1;
			funcName_count = funcName_count + f.first.size() + 3;
		}
		thunk_count = thunk_count + 1; //每个模块thunk的结尾处留空
		dllName_count = dllName_count + m.first.size() + 1;
	}

	uint32_t newSize = thunk_count * sizeof(IMAGE_THUNK_DATA64) + dllName_count + funcName_count;
	//添加新节区
	PIMAGE_SECTION_HEADER newSec{};
	for(auto& sec : get_section_headers())
	{
		if(!strcmp((char*)sec->Name,".pjvmp"))
		{
			newSec = sec;
			break;
		}
	}

	if(newSec == NULL)
	{
		append_section(".pjvmp", newSize, IMAGE_SCN_MEM_READ |IMAGE_SCN_MEM_WRITE |IMAGE_SCN_MEM_EXECUTE, &newSec);
	}

	// 重定向导入表RVA
	PIMAGE_IMPORT_DESCRIPTOR importDirectory = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(&data_[get_data_directory(IMAGE_DIRECTORY_ENTRY_IMPORT).VirtualAddress]);
	importDirectory = reinterpret_cast<decltype(importDirectory)>(&data_[newSec->VirtualAddress]);

	PIMAGE_DOS_HEADER pDos = reinterpret_cast<PIMAGE_DOS_HEADER>(data_);
	PIMAGE_NT_HEADERS64 pNt64 = reinterpret_cast<PIMAGE_NT_HEADERS64>(data_ + pDos->e_lfanew);
	pNt64->OptionalHeader.ImageBase = base;
	pNt64->OptionalHeader.SizeOfImage += aligen(newSize);
	pNt64->OptionalHeader.AddressOfEntryPoint = rva_oep;
	pNt64->OptionalHeader.FileAlignment = 0x1000;
	pNt64->OptionalHeader.DllCharacteristics = pNt64->OptionalHeader.DllCharacteristics & (~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE);

	// 重定向目录项中导入表的RVA
	pNt64->OptionalHeader.DataDirectory[1].VirtualAddress = newSec->VirtualAddress;
	pNt64->OptionalHeader.DataDirectory[1].Size = sizeof(IMAGE_IMPORT_DESCRIPTOR) * AddedImports.size() + sizeof(IMAGE_IMPORT_DESCRIPTOR);

	//计算descriptor的起始FOA
	PIMAGE_IMPORT_DESCRIPTOR offset_descriptor = (PIMAGE_IMPORT_DESCRIPTOR) & (data_[newSec->PointerToRawData]);
	//计算thunk的起始FOA
	PIMAGE_THUNK_DATA64 offset_thunk = (PIMAGE_THUNK_DATA64)(offset_descriptor + AddedImports.size() + 1); //+1是结尾的空描述符
	//计算存放dll名字的起始FOA
	char* offset_dllName = (char*)(offset_thunk + thunk_count);
	//计算存放BY_NAME的起始FOA
	PIMAGE_IMPORT_BY_NAME offset_imp = (PIMAGE_IMPORT_BY_NAME)(offset_dllName + dllName_count);

	for (auto m : AddedImports)
	{
		//设置描述符
		offset_descriptor->OriginalFirstThunk = 0;
		offset_descriptor->ForwarderChain = 0;
		offset_descriptor->TimeDateStamp = 0;
		offset_descriptor->Name = (uint32_t)((uint64_t)offset_dllName - (uint64_t)data_);
		offset_descriptor->FirstThunk = (uint32_t)((uint64_t)offset_thunk - (uint64_t)data_);
		offset_descriptor = offset_descriptor + 1;
		//写dll名
		strcpy(offset_dllName, m.first.c_str());
		offset_dllName = offset_dllName + m.first.size() + 1;
		//写thunk和by_name
		for (auto f : m.second)
		{
			offset_imp->Hint = 0;
			strcpy(offset_imp->Name, f.first.c_str());
			offset_thunk->u1.AddressOfData = ((uint64_t)offset_imp - (uint64_t)data_);

			//修复api的引用
			for (auto r : f.second)
			{
				//x64是相对位移
				uint32_t tmp = ((uint64_t)offset_thunk - (uint64_t)data_) - r - 4;
				*reinterpret_cast<uint32_t*>(&data_[r]) = tmp;
			}
			offset_thunk = offset_thunk + 1;
			offset_imp = (PIMAGE_IMPORT_BY_NAME)((uint8_t*)offset_imp + f.first.size() + sizeof(WORD) + 1);
		}
		//结束thunk
		offset_thunk->u1.AddressOfData = 0;
		offset_thunk = offset_thunk + 1;
	}
	memset(offset_descriptor, 0, sizeof(decltype(*offset_descriptor)));
}

bool PEFile::write_to_file(std::string filepath)
{
	FILE* f = NULL;
	fopen_s(&f,filepath.c_str(), "wb+");
	if (!f)
		return false;
	fwrite(data_, data_len_, 1, f);
	fclose(f);
	return true;
}