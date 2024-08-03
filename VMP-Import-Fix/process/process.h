#pragma once
#include <stdint.h>
#include <string>
#include <vector>
#include <windows.h>


// ¶Á¡¢Ð´ÄÚ´æ ²Î¿¼£ºhttps://github.com/NtQuery/Scylla/blob/master/Scylla/
class Process
{
public:
	Process();

	~Process();

	bool open_process(uint32_t pid);

	bool write_mem(uintptr_t address, size_t size, uintptr_t dataBuffer);

	bool read_mem(uintptr_t address, size_t size, void* dataBuffer);

	bool read_mem_force(uintptr_t address, size_t size, void* dataBuffer);

	uint64_t alloc_mem_nearby(uint64_t addr, uint32_t Size);

	uint64_t get_base_handle();

	bool isWow64();

	HANDLE get_handle() { return hProcess_; };

	std::vector<uint64_t> find_pattern(std::string pattern, uint64_t begine, uint64_t end);

	std::string get_modulename_by_handle(uint64_t module_base);

	static uint64_t get_module_handle_by_name(uint32_t pid, const wchar_t* modulename);

	static uint32_t get_pid_by_name(const wchar_t* name);

	static std::string get_name_by_pid(uint32_t pid);

	static HANDLE nt_open_process(uint32_t acess, uint32_t pid);

	template<class T>
	T read(uint64_t ptr)
	{
		T buff;
		read_mem(ptr, sizeof(T) ,&buff);
		return buff;
	}

	template <typename T>
	void write(uint64_t addr, T Val)
	{
		write_mem(addr, sizeof(T), reinterpret_cast<uintptr_t>(&Val));
	}

private:
	uint32_t pid_;
	HANDLE hProcess_ = NULL;
};