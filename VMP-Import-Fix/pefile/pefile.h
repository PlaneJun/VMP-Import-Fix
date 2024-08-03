#pragma once 
#include <vector>
#include <string>
#include <map>
#include <Windows.h>
#include <stdint.h>

class PEFile
{
public:
	PEFile();
	~PEFile();

	// 默认拉伸
	bool load_from_file(const char* path, bool reloc = false, uint64_t new_base = NULL);

	// 如果为空则等于pid模块
	bool load_from_process(uint32_t pid, const wchar_t* module_name = NULL);

	// new_base=0时默认为申请的内存进行重定向;data_len pe数据长度，为NULL时自动取SizeOfImage.
	bool load_from_memory(uint8_t* data, size_t data_len = NULL,bool reloc = false, uint64_t new_base = NULL);

	uint8_t* get_data();

	uint32_t get_number_of_sections() const { return number_of_sections_; }

	uint32_t get_size_of_option_header() const { return size_of_option_header_; }

	uint32_t get_size_of_code() const { return size_of_code_; }

	uint32_t get_size_of_initialized_data() const { return size_of_initialized_data_; }

	uint32_t get_size_of_uninitialized_data() const { return size_of_uninitialized_data_; }

	uint32_t get_entry_point() const { return entry_point_; }

	uint32_t get_base_of_code() const { return base_of_code_; }

	uint32_t get_base_of_data() const { return base_of_data_; }

	uint64_t get_image_base() const { return image_base_; }

	uint32_t get_segtion_alignment() const { return segtion_alignment_; }

	uint32_t get_file_alignment() const { return file_alignment_; }

	uint32_t get_size_of_image() const { return size_of_image_; }

	uint32_t get_size_of_headers() const { return size_of_headers_; }

	IMAGE_DATA_DIRECTORY get_data_directory(uint8_t index) const { return data_directory_[index]; }

	std::vector<PIMAGE_SECTION_HEADER> get_section_headers();

	//F(bool is_ordinal, char* module_name, char* function_name, IMAGE_THUNK_DATA* thunk)
	template <class F>
	void enum_imports(F func)
	{
		__try
		{
			IMAGE_DATA_DIRECTORY data_dir = get_data_directory(IMAGE_DIRECTORY_ENTRY_IMPORT);

			if (data_dir.VirtualAddress <= 0)
				return;

			PIMAGE_IMPORT_DESCRIPTOR first_import = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(data_ + data_dir.VirtualAddress);

			if (!first_import)
				return;

			for (; first_import->FirstThunk; ++first_import) {
				auto module_name = reinterpret_cast<char*>(data_ + first_import->Name);
				if (!module_name)
					break;

				size_t i = 0;
				for (auto thunk = reinterpret_cast<PIMAGE_THUNK_DATA>(data_ + first_import->OriginalFirstThunk); thunk->u1.AddressOfData; ++thunk) {
					if (thunk->u1.AddressOfData & IMAGE_ORDINAL_FLAG) {
						if (!func(true, module_name, reinterpret_cast<char*>(&thunk->u1.Ordinal), reinterpret_cast<PIMAGE_THUNK_DATA>(data_ + first_import->FirstThunk)))
							break;
					}
					else {
						auto by_name = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(data_ + thunk->u1.AddressOfData);
						auto iat_thunk = reinterpret_cast<PIMAGE_THUNK_DATA>(data_ + first_import->FirstThunk);
						iat_thunk += i;
						if (!func(false, module_name, by_name->Name, iat_thunk))
							break;
					}

					i++;
				}
			}
		}
		__except (EXCEPTION_INVALID_HANDLE)
		{
			return;
		}

	}

	template <class F>
	void enum_exports(F func)
	{
		__try
		{
			IMAGE_DATA_DIRECTORY data_dir = get_data_directory(IMAGE_DIRECTORY_ENTRY_EXPORT);

			if (data_dir.VirtualAddress <= 0)
				return;

			PIMAGE_EXPORT_DIRECTORY export_dir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(data_ + data_dir.VirtualAddress);

			DWORD* export_names = reinterpret_cast<DWORD*>(data_ + export_dir->AddressOfNames);
			DWORD* export_functions = reinterpret_cast<DWORD*>(data_ + export_dir->AddressOfFunctions);
			USHORT* export_ordinals = reinterpret_cast<USHORT*>(data_ + export_dir->AddressOfNameOrdinals);

			for (size_t i = 0; i < export_dir->NumberOfNames; i++) {
				auto name = reinterpret_cast<const char*>(data_ + export_names[i]);
				auto ordinal = export_ordinals[i];
				if (ordinal > export_dir->NumberOfFunctions)
					continue;

				auto function = reinterpret_cast<uint64_t>(data_ + export_functions[ordinal]);
				if (!func(name, function, ordinal))
					break;
			}
		}
		__except (EXCEPTION_INVALID_HANDLE)
		{
			return;
		}
	}


	PIMAGE_SECTION_HEADER translate_raw_section(DWORD rva);

	void* translate_raw(DWORD rva);

	uint32_t aligen(uint32_t size)
	{
		return (size & 0xfffff000) + 0x1000;
	}

	bool append_section(std::string section_name, std::uint32_t size, std::uint32_t chrs, PIMAGE_SECTION_HEADER* newSec =NULL);

	void add_iat_section(uint64_t base, uint32_t rva_oep, std::map<std::string, std::map<std::string, std::vector<uint64_t>>> AddedImports);

	void release() {
		if (data_)
		{
			delete[]  data_;
			data_ = NULL;
		}

	}

	bool write_to_file(std::string filepath);

private:
	/// 
	/// @param data pe数据，请确保是个正确数据
	/// @param data_len pe数据长度，为NULL时自动取SizeOfImage.
	/// @param fromFile 是否来自文件
	/// @param reloc 是否需要重定向
	/// @param new_base 仅当reloc=true时生效。以该值进行重定向，为0时默认使用申请的内存
	/// @return 
	bool parse_pe(const uint8_t* data, size_t data_len,bool fromFile, bool reloc, uint64_t new_base);

private:
	bool arch64_;
	uint8_t* data_;
	uint32_t data_len_;
	uint32_t number_of_sections_;
	uint32_t size_of_option_header_;
	uint32_t size_of_code_;
	uint32_t size_of_initialized_data_;
	uint32_t size_of_uninitialized_data_;
	uint32_t entry_point_;
	uint32_t base_of_code_;
	uint32_t base_of_data_;
	uint64_t image_base_;
	uint32_t segtion_alignment_;
	uint32_t file_alignment_;
	uint32_t size_of_image_;
	uint32_t size_of_headers_;
	IMAGE_DATA_DIRECTORY data_directory_[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
};