#pragma once
#include <iostream>
#include <stdint.h>
#include <unicorn/unicorn.h>
#include "../api/api.h"
#include "../pefile/pefile.h"

namespace emulator
{
	inline auto ExecuteInstructionMax = 0x40000;
	inline auto StackAddress = 0x0;
	inline auto StackSize = 1024 * 1024;
	inline auto StackInitValue = 0xFF;

	const static uc_x86_reg eReg64Table[] =
	{
		UC_X86_REG_RAX,
		UC_X86_REG_RCX,
		UC_X86_REG_RDX,
		UC_X86_REG_RBX,
		UC_X86_REG_RSP,
		UC_X86_REG_RBP,
		UC_X86_REG_RSI,
		UC_X86_REG_RDI,
		UC_X86_REG_R8,
		UC_X86_REG_R9,
		UC_X86_REG_R10,
		UC_X86_REG_R11,
		UC_X86_REG_R12,
		UC_X86_REG_R13,
		UC_X86_REG_R14,
		UC_X86_REG_R15
	};

	inline HANDLE hProc_;

	inline uc_engine* unicorn_{};

	inline uc_context* unicorn_ctx_{};

	inline uc_hook unicorn_hook_trace_{};

	inline uintptr_t image_base_{};

	inline size_t image_size_{};

	inline uintptr_t curt_addr_{};

	inline void* stack_{};

	inline int emu_num_{};

	int get_mov_regIndex(uintptr_t& RegisterIndexBuffer);

	bool is_api_vaild(uintptr_t Address, api::ApiInfo& iatinfo);

	bool check_curt_emu_state(uint64_t Address);

	int get_push_pop_regIndex();

	void trace_callback(uc_engine* Unicorn, uint64_t Address, uint32_t Size, void* UserData);

	void start(uintptr_t address);

	bool init(HANDLE hProc,void* datas, uintptr_t image_base, size_t image_size);
};